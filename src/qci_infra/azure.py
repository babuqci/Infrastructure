"""Read-only Azure collectors over ARM REST, authenticated with Azure CLI tokens."""

import json
import shutil
import subprocess
import time
from urllib.parse import quote, urlsplit

import httpx

ARM = "https://management.azure.com"
AZ = shutil.which("az") or "/opt/homebrew/bin/az"


class AzureError(Exception):
    pass


class Arm:
    """ARM client. Tokens are fetched per subscription (`az account get-access-token
    --subscription`), which picks the right signed-in user for each tenant."""

    def __init__(self):
        self._tokens: dict[str, tuple[str, float]] = {}
        self._http = httpx.Client(timeout=60)

    def _token(self, sub: str) -> str:
        tok, exp = self._tokens.get(sub, ("", 0.0))
        if time.time() < exp - 300:
            return tok
        p = subprocess.run([AZ, "account", "get-access-token", "--subscription", sub, "--resource", ARM + "/",
                            "-o", "json"], capture_output=True, text=True)
        if p.returncode:
            raise AzureError(f"Azure CLI token for {sub} failed (run `az login` on the Mac Studio): "
                             f"{p.stderr.strip()[:300]}")
        d = json.loads(p.stdout)
        self._tokens[sub] = (d["accessToken"], float(d["expires_on"]))
        return d["accessToken"]

    def request(self, method: str, sub: str, url: str, body=None) -> dict:
        url = url if url.startswith("https://") else ARM + url
        if urlsplit(url).hostname != urlsplit(ARM).hostname:  # never send the token elsewhere (e.g. a nextLink)
            raise AzureError(f"refusing non-ARM URL: {url.split('?')[0]}")
        for attempt in range(5):
            r = self._http.request(method, url, json=body, headers={"Authorization": f"Bearer {self._token(sub)}"})
            if r.status_code == 429 or r.status_code >= 500:
                wait = next((v for k, v in r.headers.items() if k.lower().endswith("retry-after")), None)
                time.sleep(min(int(wait) if wait and wait.isdigit() else 5 * 2 ** attempt, 60))
                continue
            if r.status_code >= 400:
                try:
                    err = r.json()["error"]
                    detail = f"{err.get('code')}: {err.get('message', '')[:150]}"
                except (ValueError, KeyError, TypeError):
                    detail = r.text[:200]
                api = url.split("?")[0].split("/providers/")[-1]
                raise AzureError(f"{api} -> HTTP {r.status_code} {detail}")
            return r.json()
        raise AzureError(f"{method} {url.split('?')[0]} -> still throttled/failing after retries")

    def get_all(self, sub: str, url: str) -> list[dict]:
        items, pages = [], 0
        while url:
            pages += 1
            if pages > 100:
                raise AzureError(f"too many pages from {url.split('?')[0]}")
            d = self.request("GET", sub, url)
            items += d.get("value", [])
            url = d.get("nextLink")
        return items


VM_QUERY = """resources
| where type =~ 'microsoft.compute/virtualmachines'
| project id, name, resourceGroup, subscriptionId, location, tags,
  size = tostring(properties.hardwareProfile.vmSize),
  os = tostring(properties.storageProfile.osDisk.osType),
  power = tostring(properties.extended.instanceView.powerState.code)"""


SQL_VM_QUERY = """resources
| where type =~ 'microsoft.sqlvirtualmachine/sqlvirtualmachines'
| project vm = tolower(tostring(properties.virtualMachineResourceId))"""


def _graph(arm: Arm, sub: str, query: str) -> list[dict]:
    body = {"subscriptions": [sub], "query": query, "options": {"resultFormat": "objectArray", "$top": 1000}}
    return arm.request("POST", sub, "/providers/Microsoft.ResourceGraph/resources?api-version=2022-10-01", body)["data"]


def list_vms(arm: Arm, sub: str) -> list[dict]:
    """VM rows; `sql` is True when a SQL Server VM resource is attached."""
    sql_ids = {r["vm"] for r in _graph(arm, sub, SQL_VM_QUERY)}
    vms = _graph(arm, sub, VM_QUERY)
    for v in vms:
        v["sql"] = v["id"].lower() in sql_ids
    return vms


SQL_DEV_QUERY = """resources
| where type =~ 'microsoft.sqlvirtualmachine/sqlvirtualmachines' and tostring(properties.sqlImageSku) =~ 'Developer'
| project id = tolower(tostring(properties.virtualMachineResourceId))
| join kind=inner (resources | where type =~ 'microsoft.compute/virtualmachines'
  | project id = tolower(id), name, resourceGroup,
    power = tostring(properties.extended.instanceView.powerState.code)) on id
| project id, name, resourceGroup, power"""


PUBLIC_IP_QUERY = """resources
| where type =~ 'microsoft.network/networkinterfaces'
| extend vm = tolower(tostring(properties.virtualMachine.id))
| where isnotempty(vm)
| mv-expand ipc = properties.ipConfigurations
| extend pip = tolower(tostring(ipc.properties.publicIPAddress.id))
| where isnotempty(pip)
| join kind=inner (resources | where type =~ 'microsoft.network/publicipaddresses'
  | project pip = tolower(id), ip = tostring(properties.ipAddress)) on pip
| where isnotempty(ip)
| project vm, ip"""


def vm_public_ips(arm: Arm, sub: str) -> dict[str, set[str]]:
    """{vm_id_lower: {public IP addresses}} of the VMs' NICs."""
    out: dict[str, set[str]] = {}
    for r in _graph(arm, sub, PUBLIC_IP_QUERY):
        out.setdefault(r["vm"], set()).add(r["ip"])
    return out


def list_sql_dev_vms(arm: Arm, sub: str) -> list[dict]:
    """VMs whose SQL Server VM resource reports the Developer image SKU: {id, name, resourceGroup, power}."""
    return _graph(arm, sub, SQL_DEV_QUERY)


class RunCommandBusy(AzureError):
    """Another Run Command is executing on the VM (e.g. sql-check): retry later."""


def _run_command(sub: str, rg: str, vm: str, command_id: str, script: str, timeout: float) -> tuple[str, str]:
    try:
        p = subprocess.run([AZ, "vm", "run-command", "invoke", "--subscription", sub, "-g", rg, "-n", vm,
                            "--command-id", command_id, "--scripts", f"@{script}", "-o", "json"],
                           capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        raise AzureError(f"Run Command timed out after {timeout / 60:.0f} min")
    if p.returncode:
        err = " ".join(p.stderr.split())
        cls = RunCommandBusy if "execution is in progress" in err else AzureError
        raise cls(f"Run Command failed: {err[:300]}")
    values = json.loads(p.stdout).get("value", [])
    out = {v.get("code", "").split("/")[1]: v.get("message", "") for v in values}
    if "StdOut" not in out and len(values) == 1:  # Linux: one message "...[stdout]\n...\n[stderr]\n..."
        msg = values[0].get("message", "")
        so, _, se = msg.partition("[stdout]\n")[2].partition("\n[stderr]\n")
        return so, se
    return out.get("StdOut", ""), out.get("StdErr", "")


def run_powershell(sub: str, rg: str, vm: str, script: str, timeout: float) -> tuple[str, str]:
    """Run a PowerShell script file on a VM via Run Command (`az vm run-command invoke`, which
    creates no Azure resource). Returns (stdout, stderr) of the script; raises on failure/timeout
    (RunCommandBusy when another Run Command is executing on the VM)."""
    return _run_command(sub, rg, vm, "RunPowerShellScript", script, timeout)


def run_shell(sub: str, rg: str, vm: str, script: str, timeout: float) -> tuple[str, str]:
    """Like run_powershell, for a bash script on a Linux VM (RunShellScript, runs as root)."""
    return _run_command(sub, rg, vm, "RunShellScript", script, timeout)


def vm_health(arm: Arm, sub: str) -> dict[str, str]:
    """{vm_id_lower: availabilityState} from Resource Health."""
    rows = arm.get_all(sub, f"/subscriptions/{sub}/providers/Microsoft.ResourceHealth/availabilityStatuses"
                            "?api-version=2024-02-01")
    out = {}
    for r in rows:
        rid = r["id"].lower().split("/providers/microsoft.resourcehealth")[0]
        if "/microsoft.compute/virtualmachines/" in rid:
            out[rid] = r["properties"].get("availabilityState", "Unknown")
    return out


METRICS = ("Percentage CPU", "Available Memory Percentage", "VmAvailabilityMetric")


def vm_metrics(arm: Arm, sub: str, vm_id: str) -> dict[str, list[float]]:
    """Last 30 min of 5-minute averages per metric, oldest first, gaps dropped."""
    names = quote(",".join(METRICS))
    d = arm.request("GET", sub, f"{vm_id}/providers/Microsoft.Insights/metrics?api-version=2023-10-01"
                                f"&metricnames={names}&interval=PT5M&timespan=PT30M&aggregation=Average")
    out = {}
    for m in d.get("value", []):
        points = (m.get("timeseries") or [{}])[0].get("data", [])
        out[m["name"]["value"]] = [p["average"] for p in points if p.get("average") is not None]
    return out


def _cost_query(arm: Arm, sub: str, body: dict) -> tuple[list[str], list[list]]:
    d = arm.request("POST", sub, f"/subscriptions/{sub}/providers/Microsoft.CostManagement/query"
                                 "?api-version=2023-11-01", body)
    p = d["properties"]
    return [c["name"] for c in p["columns"]], p["rows"]


def daily_cost(arm: Arm, sub: str, start: str, end: str) -> dict[str, float]:
    """{'YYYY-MM-DD': cost} of actual cost, start..end inclusive."""
    cols, rows = _cost_query(arm, sub, {
        "type": "ActualCost", "timeframe": "Custom",
        "timePeriod": {"from": f"{start}T00:00:00Z", "to": f"{end}T23:59:59Z"},
        "dataset": {"granularity": "Daily", "aggregation": {"cost": {"name": "Cost", "function": "Sum"}}},
    })
    ci, di = cols.index("Cost"), cols.index("UsageDate")
    out: dict[str, float] = {}
    for r in rows:
        s = str(r[di])
        day = f"{s[:4]}-{s[4:6]}-{s[6:8]}"
        out[day] = out.get(day, 0.0) + r[ci]
    return out


def _cost_by_resource(arm: Arm, sub: str, period: dict) -> dict[str, float]:
    cols, rows = _cost_query(arm, sub, {
        "type": "ActualCost", **period,
        "dataset": {"granularity": "None", "aggregation": {"cost": {"name": "Cost", "function": "Sum"}},
                    "grouping": [{"type": "Dimension", "name": "ResourceId"}]},
    })
    ci, ri = cols.index("Cost"), cols.index("ResourceId")
    out: dict[str, float] = {}
    for r in rows:
        out[r[ri].lower()] = out.get(r[ri].lower(), 0.0) + r[ci]
    return out


def top_resources_mtd(arm: Arm, sub: str, yesterday: str, n: int = 10) -> list[tuple[str, float, float]]:
    """[(resource name, month-to-date cost, yesterday's cost)], top n by MTD. A removed resource keeps
    its MTD cost until month end, so yesterday's cost (0) is what shows it no longer bills."""
    mtd = _cost_by_resource(arm, sub, {"timeframe": "MonthToDate"})
    day = _cost_by_resource(arm, sub, {"timeframe": "Custom", "timePeriod": {
        "from": f"{yesterday}T00:00:00Z", "to": f"{yesterday}T23:59:59Z"}})
    ranked = sorted(mtd.items(), key=lambda x: -x[1])[:n]
    return [(rid.split("/")[-1] or "(other)", cost, day.get(rid, 0.0)) for rid, cost in ranked]

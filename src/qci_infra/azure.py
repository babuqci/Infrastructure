"""Read-only Azure collectors over ARM REST, authenticated with Azure CLI tokens."""

import json
import shutil
import subprocess
import time
from urllib.parse import quote

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
        items = []
        while url:
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


def top_resources_mtd(arm: Arm, sub: str, n: int = 10) -> list[tuple[str, float]]:
    cols, rows = _cost_query(arm, sub, {
        "type": "ActualCost", "timeframe": "MonthToDate",
        "dataset": {"granularity": "None", "aggregation": {"cost": {"name": "Cost", "function": "Sum"}},
                    "grouping": [{"type": "Dimension", "name": "ResourceId"}]},
    })
    ci, ri = cols.index("Cost"), cols.index("ResourceId")
    ranked = sorted(((r[ri].split("/")[-1] or "(other)", r[ci]) for r in rows), key=lambda x: -x[1])
    return ranked[:n]

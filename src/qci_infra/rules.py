"""Pure alert rules: turn collected data into findings."""

import re
from dataclasses import dataclass
from datetime import date, datetime, timedelta

from .config import Certs, Sql, Thresholds

CPU = "Percentage CPU"
MEM = "Available Memory Percentage"
AVAIL = "VmAvailabilityMetric"
STOPPED_POWER = {"PowerState/stopped", "PowerState/stopping", "PowerState/deallocated", "PowerState/deallocating"}

VM_KINDS = ("vm-down", "vm-degraded", "cpu-high", "mem-low")
METRIC_KINDS = ("cpu-high", "mem-low")


@dataclass(frozen=True)
class Finding:
    kind: str
    sub: str
    name: str
    summary: str

    @property
    def key(self) -> str:
        return f"{self.kind}:{self.sub}:{self.name}"


def vm_findings(sub, vms, health, metrics, th: Thresholds, ignore_tag: str) -> list[Finding]:
    """vms: Resource Graph rows. health: {vm_id_lower: availabilityState}.
    metrics: {vm_id_lower: {metric name: [values, oldest first]}}."""
    out = []
    for vm in vms:
        if (vm.get("tags") or {}).get(ignore_tag, "").lower() == "off":
            continue
        vid, name = vm["id"].lower(), vm["name"]
        m = metrics.get(vid, {})
        state = health.get(vid)

        reasons = []
        if vm.get("power") in STOPPED_POWER:
            reasons.append(f"power state {vm['power'].removeprefix('PowerState/')}")
        if state == "Unavailable":
            reasons.append("Resource Health: Unavailable")
        if m.get(AVAIL) and m[AVAIL][-1] == 0:
            reasons.append("Azure availability metric is 0")
        if reasons:
            out.append(Finding("vm-down", sub, name, f"{name} ({vm['resourceGroup']}) is down: {'; '.join(reasons)}"))
            continue  # metrics are meaningless while down

        if state == "Degraded":
            out.append(Finding("vm-degraded", sub, name, f"{name} ({vm['resourceGroup']}) Resource Health: Degraded"))

        n = th.window_points
        cpu = m.get(CPU, [])[-n:]
        if len(cpu) == n and min(cpu) > th.cpu_percent:
            out.append(Finding("cpu-high", sub, name,
                               f"{name} CPU above {th.cpu_percent:g}% for {n * 5} min (now {cpu[-1]:.0f}%)"))
        mem = m.get(MEM, [])[-n:]
        mem_th = th.mem_available_percent_sql if vm.get("sql") else th.mem_available_percent
        if len(mem) == n and max(mem) < mem_th:
            out.append(Finding("mem-low", sub, name,
                               f"{name} available memory below {mem_th:g}% for {n * 5} min (now {mem[-1]:.0f}%)"))
    return out


def cost_findings(sub, sub_name, daily: dict[str, float], day: str, th: Thresholds) -> list[Finding]:
    """Flag `day` if its cost is well above the average of the 7 days before it."""
    d = date.fromisoformat(day)
    prior = [daily[k] for k in ((d - timedelta(days=i)).isoformat() for i in range(1, 8)) if k in daily]
    if len(prior) < 3 or day not in daily:
        return []
    avg, cost = sum(prior) / len(prior), daily[day]
    if cost > avg * th.cost_spike_ratio and cost - avg > th.cost_spike_min_usd:
        return [Finding("cost-spike", sub, day,
                        f"{sub_name} spent ${cost:,.0f} on {day}, vs 7-day average ${avg:,.0f}")]
    return []


# SQL Server probe (sql_health.ps1 output): each kind is judged only from the part of the
# probe it needs, and only when that part was collected (a missing key = read failed).
SQL_SOURCES = {"sql-service-down": ("svc",), "sql-disk-low": ("drives",), "sql-db-missing": ("dbs",),
               "sql-backup-stale": ("dbs", "bk")}
SQL_SERVICES = ("MSSQLSERVER", "SQLSERVERAGENT")


def sql_judged_kinds(h: dict) -> list[str]:
    """sql-* kinds this probe result can confirm or clear (backup needs no `bk` if there is no db)."""
    return [k for k, need in SQL_SOURCES.items()
            if all(n in h for n in need) or (k == "sql-backup-stale" and "dbs" in h and not h.get("db"))]


def sql_findings(sub, name: str, h: dict, now: datetime, th: Sql) -> list[Finding]:
    """h: parsed probe JSON for VM `name`. now: aware UTC datetime."""
    out = []
    if "svc" in h:
        down = [f"{s} {h['svc'].get(s, 'Missing')}" for s in SQL_SERVICES if h["svc"].get(s) != "Running"]
        if down:
            out.append(Finding("sql-service-down", sub, name, f"{name}: SQL service not running: {', '.join(down)}"))
    low = [d for d in h.get("drives", []) if d.get("size") and
           (d["free"] < th.disk_free_gb or d["free"] / d["size"] * 100 < th.disk_free_percent)]
    if low:
        out.append(Finding("sql-disk-low", sub, name, f"{name}: low disk space: " + ", ".join(
            f"{d['d']}: {d['free']:.0f} GB free of {d['size']:.0f} GB ({d['free'] / d['size'] * 100:.0f}%)"
            for d in low)))
    if "dbs" in h and not h.get("db"):
        out.append(Finding("sql-db-missing", sub, name, f"{name}: database qcidb / qcidb-develop not found"))
    elif h.get("db") and "bk" in h:
        full = (h["bk"] or {}).get("D")
        if not full:
            out.append(Finding("sql-backup-stale", sub, name, f"{name}: {h['db']} has no full backup on record"))
        else:
            age = (now - datetime.fromisoformat(full["t"].replace("Z", "+00:00"))).total_seconds() / 3600
            if age > th.backup_max_age_hours:
                out.append(Finding("sql-backup-stale", sub, name,
                                   f"{name}: last full backup of {h['db']} was {age:.0f} h ago ({full['t'][:16]}Z)"))
    return out


# TLS certificates (cert-check). Probe results are normalized by cli.parse_cert_probe to
# {host, web, bindings: [{site, host, port, thumb}], certs: [{thumb, names, issuer, not_after,
#  where, source}], in_use: [thumb], renewal: [{kind, name, state, problem}], gaps}.
CERT_KINDS = ("cert-expiring", "cert-expired", "cert-mismatch", "cert-renewal")
# A cert counts as "renewed but not in use" only when the newer one expires this much later:
# several ACME renewals can hold certs for the same name a day or two apart; a renewal adds ~60 days.
RENEWED_GAP_DAYS = 14


def is_acme(issuer: str | None) -> bool:
    """Let's Encrypt intermediates (R10, E5, ...) and ZeroSSL: certs an ACME client renews."""
    return bool(re.fullmatch(r"Y?[RE]\d{1,2}", issuer or "")) or "zerossl" in (issuer or "").lower()


def days_left(not_after: str, now: datetime) -> float:
    return (datetime.fromisoformat(not_after.replace("Z", "+00:00")) - now).total_seconds() / 86400


def covers(names, host: str) -> bool:
    """True when a certificate with DNS names `names` is valid for `host` (one-label wildcards)."""
    host = host.lower().rstrip(".")
    for n in names or ():
        n = n.lower()
        if n == host or (n.startswith("*.") and host.split(".", 1)[-1] == n[2:] and host.count(".") >= 2):
            return True
    return False


def _renewed_after(newer: str, older: str) -> bool:
    return days_left(newer, datetime.fromisoformat(older.replace("Z", "+00:00"))) > RENEWED_GAP_DAYS


def primary_name(c: dict) -> str:
    return (c.get("names") or [None])[0] or c["thumb"][:12]


def expiry_finding(sub, name: str, what: str, not_after: str | None, now: datetime, th: Certs) -> Finding | None:
    if not not_after:
        return None
    d = days_left(not_after, now)
    if d < 0:
        return Finding("cert-expired", sub, name, f"{what} EXPIRED on {not_after[:10]} ({-d:.0f} days ago)")
    if d < th.warn_days:
        return Finding("cert-expiring", sub, name, f"{what} expires on {not_after[:10]} ({d:.0f} days left)")
    return None


def server_cert_findings(sub, vm: str, p: dict, now: datetime, th: Certs) -> list[Finding]:
    """Findings for one probed VM: expiry of certs in use, IIS bindings left on an older cert
    (or none), and the renewal task/timer. Names are `vm/...` so they scope per VM."""
    out, by_thumb = [], {c["thumb"]: c for c in p["certs"]}
    in_use = [by_thumb[t] for t in dict.fromkeys(p["in_use"]) if t in by_thumb]
    for c in in_use:
        f = expiry_finding(sub, f"{vm}/{primary_name(c)}", f"{vm}: certificate {primary_name(c)} ({c['where']})",
                           c["not_after"], now, th)
        out += [f] if f else []
    stale: dict[str, list] = {}  # bound thumb -> [(binding label, newer cert)]
    for b in p["bindings"]:
        label = f"{b['host'] or '*'}:{b['port']}"
        if not b["thumb"]:
            out.append(Finding("cert-mismatch", sub, f"{vm}/{label}",
                               f"{vm}: IIS site {b['site']} https {label} has no certificate bound"))
            continue
        cur = by_thumb.get(b["thumb"])
        if not cur or not cur["not_after"]:
            continue
        host = b["host"] or primary_name(cur)
        newer = [c for c in p["certs"] if c["thumb"] != cur["thumb"] and c["not_after"] and
                 _renewed_after(c["not_after"], cur["not_after"]) and covers(c["names"], host)]
        if newer:
            stale.setdefault(cur["thumb"], []).append((label, max(newer, key=lambda c: c["not_after"])))
    for t, items in stale.items():
        cur, n = by_thumb[t], items[0][1]
        labels = ", ".join(lb for lb, _ in items[:5]) + (f" and {len(items) - 5} more" if len(items) > 5 else "")
        out.append(Finding("cert-mismatch", sub, f"{vm}/bound {t[:8]}",
                           f"{vm}: IIS https {labels} still bound to cert {t[:8]} (expires {cur['not_after'][:10]}), "
                           f"though a renewed cert {n['thumb'][:8]} (expires {n['not_after'][:10]}) is in the store"))
    problems = [f"{r['kind']} {r['name']}: {r['problem']}" for r in p["renewal"] if r.get("problem")]
    if any(is_acme(c["issuer"]) for c in in_use) and not p["renewal"]:
        problems.append("Let's Encrypt certificate in use but no renewal task, timer or cron job found")
    if problems:
        out.append(Finding("cert-renewal", sub, f"{vm}/renewal", f"{vm}: certificate renewal: {'; '.join(problems)}"))
    return out


def served_findings(sub, host: str, s: dict, disk_certs: list[dict], now: datetime, th: Certs) -> list[Finding]:
    """Findings for the certificate `host` serves on 443 (tls.served_cert result `s`), compared
    with the newest certificate for `host` found on the probed servers (`disk_certs`). Expiry
    is judged here only for certs not found on a server (e.g. a proxy or CDN in front)."""
    name, out = f"https://{host}", []
    err = s.get("error")
    if s["thumb"] in {c["thumb"] for c in disk_certs}:
        pass  # a cert found on a server: its expiry is reported once, by server_cert_findings
    elif err and "expired" in err.lower():
        out.append(Finding("cert-expired", sub, name, f"{host} serves an EXPIRED certificate "
                                                      f"(expired {s['not_after'][:10]})"))
    else:
        f = expiry_finding(sub, name, f"{host}: served certificate", s["not_after"], now, th)
        out += [f] if f else []
    problems = [f"certificate does not verify ({err})"] if err and "expired" not in err.lower() else []
    newest = max((c for c in disk_certs if c["not_after"] and covers(c["names"], host)),
                 key=lambda c: c["not_after"], default=None)
    if newest and newest["thumb"] != s["thumb"] and _renewed_after(newest["not_after"], s["not_after"]):
        problems.append(f"serves a cert expiring {s['not_after'][:10]} ({s['thumb'][:8]}), but the newer cert "
                        f"expiring {newest['not_after'][:10]} ({newest['thumb'][:8]}) is on the server: "
                        "rebind it / reload the web server")
    if problems:
        out.append(Finding("cert-mismatch", sub, name, f"{host}: {'; '.join(problems)}"))
    return out

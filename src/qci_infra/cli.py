"""Entry point: `qci-infra check` (every 5 min), `qci-infra sql-check` (hourly), `qci-infra cert-check`
(daily), `qci-infra daily` (cost + digest), `qci-infra test-email`."""

import argparse
import calendar
import json
import os
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

import httpx

from . import azure, notify, tls
from .config import Config, load_config
from .rules import (CERT_KINDS, CPU, MEM, METRIC_KINDS, SQL_SOURCES, STOPPED_POWER, VM_KINDS, Finding,
                    cost_findings, days_left, served_findings, server_cert_findings, sql_findings,
                    sql_judged_kinds, vm_findings)
from .store import (Db, connect_mssql, connect_sqlite, open_alerts, reconcile, record_run, save_certs,
                    save_cost, save_sql_health, save_vms)

SQL_SCRIPT = Path(__file__).with_name("sql_health.ps1")


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def log(msg: str):
    print(f"{now_iso()} {msg}", flush=True)


def open_db(cfg: Config, dry_run: bool) -> Db:
    """SQL Server if configured; local SQLite if it is unreachable (one email when that starts and ends)."""
    if dry_run:
        return connect_sqlite(":memory:")  # dry runs never touch real alert state
    if not cfg.database:
        return connect_sqlite(cfg.db)
    marker = Path(os.path.expanduser(cfg.db)).with_suffix(".mssql-down")
    d = cfg.database
    try:
        db = connect_mssql(d.server, d.database, d.user, d.password_file)
    except Exception as e:
        log(f"SQL Server unreachable, using local SQLite: {e}")
        if not marker.exists():
            notify.send(cfg.email, "[QCI Alert] Monitoring database unreachable",
                        f"{d.database} on {d.server} could not be reached:\n  {str(e)[:300]}\n\n"
                        "Monitoring continues using local state on the Mac Studio.")
            marker.parent.mkdir(parents=True, exist_ok=True)
            marker.touch()
        return connect_sqlite(cfg.db)
    if marker.exists():
        notify.send(cfg.email, "[QCI Alert] Monitoring database reachable again",
                    f"{d.database} on {d.server} is reachable again.")
        marker.unlink()
    return db


def vm_rows(vms, health, metrics) -> list[dict]:
    rows = []
    for v in vms:
        m = metrics.get(v["id"].lower(), {})
        cpu, mem = m.get(CPU) or [None], m.get(MEM) or [None]
        rows.append({"vm_id": v["id"].lower(), "name": v["name"], "rg": v["resourceGroup"], "location": v["location"],
                     "size": v.get("size"), "os": v.get("os"), "power": v.get("power"),
                     "health": health.get(v["id"].lower()), "cpu": cpu[-1], "mem": mem[-1],
                     "is_sql": 1 if v.get("sql") else 0})
    return rows


def check(cfg: Config, dry_run: bool):
    started = now_iso()
    arm, db = azure.Arm(), open_db(cfg, dry_run)
    findings, scope = [], set()
    for s in cfg.subscriptions:
        scope.add(("collector", s.id))
        try:
            vms = azure.list_vms(arm, s.id)
            health = azure.vm_health(arm, s.id)
        except Exception as e:  # any failure here must alert, never silently skip
            findings.append(Finding("collector", s.id, "check", f"{s.name}: monitoring check failed: {e}"))
            log(f"{s.name}: FAILED {e}")
            continue
        metrics, failed = {}, []
        for vm in vms:
            if vm.get("power") in STOPPED_POWER:
                continue
            try:
                metrics[vm["id"].lower()] = azure.vm_metrics(arm, s.id, vm["id"])
            except Exception as e:
                failed.append(vm["name"])
                log(f"{s.name}: metrics failed for {vm['name']}: {e}")
        findings += vm_findings(s.id, vms, health, metrics, cfg.thresholds, cfg.ignore_tag)
        save_vms(db, s.id, vm_rows(vms, health, metrics), now_iso())
        scope |= {(k, s.id) for k in VM_KINDS if not (failed and k in METRIC_KINDS)}
        if failed:
            findings.append(Finding("collector", s.id, "metrics",
                                    f"{s.name}: metrics unavailable for {', '.join(failed)}"))
        log(f"{s.name}: {len(vms)} VMs, {len(metrics)} with metrics, {len(failed)} metric failures")

    opened, resolved = reconcile(db, findings, scope, now_iso())
    log(f"findings={len(findings)} opened={len(opened)} resolved={len(resolved)}")
    if opened or resolved:
        notify.send(cfg.email, *notify.alert_email(opened, resolved, {s.id: s.name for s in cfg.subscriptions}),
                    dry_run=dry_run)
    record_run(db, "check", started, now_iso(), ok=not any(f.kind == "collector" for f in findings),
               message=f"findings={len(findings)} opened={len(opened)} resolved={len(resolved)}")
    db.commit()
    if cfg.heartbeat_url and not dry_run:
        httpx.get(cfg.heartbeat_url, timeout=10)


def parse_probe(stdout: str) -> dict:
    """The probe prints one JSON line; take the last one (Run Command may add other output)."""
    line = next((ln for ln in reversed(stdout.splitlines()) if ln.strip().startswith("{")), None)
    if line is None:
        raise ValueError(f"no JSON in output: {stdout.strip()[:200]!r}")
    return json.loads(line)


def probe_sql_vm(sub: str, vm: dict, timeout: float) -> tuple[dict | None, str | None]:
    """(probe result, None) or (None, error text). Never raises: one VM must not stop the others."""
    try:
        out, err = azure.run_powershell(sub, vm["resourceGroup"], vm["name"], str(SQL_SCRIPT), timeout)
        try:
            return parse_probe(out), None
        except ValueError as e:
            return None, f"unparseable probe output ({e}); stderr: {' '.join(err.split())[:200]}"
    except Exception as e:
        return None, str(e)


def sql_row(vm: dict, h: dict | None, findings: list[Finding], error: str | None) -> dict:
    h = h or {}
    full = (h.get("bk") or {}).get("D") or {}
    return {"vm_id": vm["id"].lower(), "vm_name": vm["name"], "edition": h.get("edition"),
            "version": h.get("version"), "db_name": h.get("db"), "last_full_backup": full.get("t"),
            "last_full_backup_path": full.get("f"),
            "drives": json.dumps(h["drives"]) if "drives" in h else None,
            "services": ", ".join(f"{k}={v}" for k, v in h["svc"].items()) if "svc" in h else None,
            "permission_gaps": "; ".join(h.get("gaps") or [])[:2000] or None,
            "ok": 1 if h and not error and not findings else 0, "error": error[:2000] if error else None}


def sql_summary(h: dict, now: datetime) -> str:
    full = (h.get("bk") or {}).get("D")
    age = (f"{(now - datetime.fromisoformat(full['t'].replace('Z', '+00:00'))).total_seconds() / 3600:.0f}h"
           if full else "none")
    drives = [d for d in h.get("drives", []) if d.get("size")]
    low = min(drives, key=lambda d: d["free"] / d["size"], default=None)
    lowest = f"{low['d']}: {low['free'] / low['size'] * 100:.0f}% ({low['free']:.0f} GB)" if low else "?"
    svc = ",".join(f"{k}={v}" for k, v in (h.get("svc") or {}).items())
    return (f"db={h.get('db')} full_age={age} lowest_drive={lowest} svc={svc} "
            f"gaps={h.get('gaps') or 'none'}")


def sql_check(cfg: Config, dry_run: bool):
    """Hourly: probe every SQL Server Developer VM (Run Command, read-only) for qcidb backups,
    disk space, SQL services; alert via reconcile and keep the latest status in sql_health."""
    started = now_iso()
    arm, db = azure.Arm(), open_db(cfg, dry_run)
    findings, scope, targets, rows = [], set(), [], {}
    for s in cfg.subscriptions:
        scope.add(("sql-collector", s.id, "discovery"))
        try:
            vms = azure.list_sql_dev_vms(arm, s.id)
        except Exception as e:
            findings.append(Finding("sql-collector", s.id, "discovery", f"{s.name}: SQL VM discovery failed: {e}"))
            log(f"{s.name}: SQL VM discovery FAILED {e}")
            continue
        rows[s.id] = []
        targets += [(s, v) for v in vms]
        # alerts of VMs no longer discovered (deleted, no longer Developer) may resolve
        names = {v["name"] for v in vms}
        gone = [tuple(r["alert_key"].split(":", 2)) for r in open_alerts(db)
                if r["kind"].startswith("sql-") and r["sub"] == s.id]
        scope |= {k for k in gone if k[2] not in names}

    running = [(s, v) for s, v in targets if v.get("power") == "PowerState/running"]
    for s, v in targets:
        if (s, v) not in running:  # vm-down is check's job; hold this VM's sql alerts
            rows[s.id].append(sql_row(v, None, [], f"not probed: VM {v.get('power') or 'power state unknown'}"))
            log(f"{v['name']}: skipped, {v.get('power')}")
    timeout = cfg.sql.timeout_minutes * 60
    with ThreadPoolExecutor(max_workers=max(1, len(running))) as ex:
        results = list(ex.map(lambda t: probe_sql_vm(t[0].id, t[1], timeout), running))

    now = datetime.now(timezone.utc)
    for (s, v), (h, err) in zip(running, results):
        name, found = v["name"], []
        scope.add(("sql-collector", s.id, name))
        if err:
            findings.append(Finding("sql-collector", s.id, name, f"{name}: SQL health check failed: {err[:300]}"))
            log(f"{name}: FAILED {err}")
        else:
            found = sql_findings(s.id, name, h, now, cfg.sql)
            judged = sql_judged_kinds(h)
            scope |= {(k, s.id, name) for k in judged}
            sql_up = (h.get("svc") or {}).get("MSSQLSERVER") == "Running"
            if sql_up and set(judged) != set(SQL_SOURCES):  # SQL is up but a needed read failed: don't go blind
                findings.append(Finding("sql-collector", s.id, name,
                                        f"{name}: SQL health check incomplete: {'; '.join(h.get('gaps') or [])}"))
            findings += found
            log(f"{name}: {sql_summary(h, now)} findings={[f.kind for f in found]}")
        rows[s.id].append(sql_row(v, h, found, err))
    for sub, r in rows.items():
        save_sql_health(db, sub, r, now_iso())

    opened, resolved = reconcile(db, findings, scope, now_iso())
    log(f"sql-check: {len(running)}/{len(targets)} VMs probed, findings={len(findings)} "
        f"opened={len(opened)} resolved={len(resolved)}")
    if opened or resolved:
        notify.send(cfg.email, *notify.alert_email(opened, resolved, {s.id: s.name for s in cfg.subscriptions}),
                    dry_run=dry_run)
    record_run(db, "sql-check", started, now_iso(), ok=not any(f.kind == "sql-collector" for f in findings),
               message=f"probed={len(running)}/{len(targets)} findings={len(findings)} "
                       f"opened={len(opened)} resolved={len(resolved)}")
    db.commit()


CERT_PS = Path(__file__).with_name("cert_health.ps1")
CERT_SH = Path(__file__).with_name("cert_health.sh")
# Task Scheduler LastTaskResult values that are not failures: success, ready, running, not yet run, queued
TASK_OK = {0, 0x41300, 0x41301, 0x41303, 0x41325}
RENEWAL_STALE_DAYS = 8  # win-acme and certbot run daily or twice a day
BUSY_RETRY_SECONDS = 180


def _list(x) -> list:
    return [] if x is None else x if isinstance(x, list) else [x]


def _stale(last: str | None, now: datetime) -> bool:
    return bool(last) and days_left(last, now) < -RENEWAL_STALE_DAYS


def parse_cert_probe(os_type: str, stdout: str, now: datetime) -> dict:
    """Normalize cert_health.ps1 (JSON) or cert_health.sh (tab-separated) output; see rules.py
    for the shape. Raises ValueError when the output is not a probe result."""
    p = {"host": None, "web": [], "bindings": [], "certs": [], "in_use": [], "renewal": [], "gaps": []}
    if os_type == "Windows":
        h = parse_probe(stdout)
        p["host"], p["gaps"] = h.get("host"), _list(h.get("gaps"))
        if h.get("iis") not in (None, "Missing"):
            p["web"].append(f"IIS {h['iis']}")
        for g in _list(h.get("b")):  # grouped per (site, cert); "host", "host:port", "*" = no host header
            for hp in _list(g.get("h")):
                host, _, port = hp.partition(":")
                p["bindings"].append({"site": g.get("s"), "host": "" if host == "*" else host,
                                      "port": int(port or 443), "thumb": g.get("t") or None})
        p["certs"] = [{"thumb": c["t"], "names": _list(c.get("n")), "issuer": c.get("i"), "not_after": c.get("e"),
                       "where": f"LocalMachine\\{c.get('st')}", "source": "store"} for c in _list(h.get("c"))]
        p["in_use"] = [b["thumb"] for b in p["bindings"] if b["thumb"]]
        known = {c["thumb"] for c in p["certs"]}
        p["gaps"] += [f"bound cert {t[:8]} not found in My/WebHosting" for t in dict.fromkeys(p["in_use"])
                      if t not in known]
        for t in _list(h.get("tk")):
            r, problem = t.get("r"), None
            if t.get("s") == "Disabled":
                problem = "task is disabled"
            elif isinstance(r, int) and r not in TASK_OK:
                problem = f"last run {(t.get('lr') or '?')[:10]} failed (result 0x{r & 0xFFFFFFFF:X})"
            elif _stale(t.get("lr"), now):
                problem = f"has not run since {t['lr'][:10]}"
            p["renewal"].append({"kind": "task", "name": t.get("n"), "state": t.get("s"), "last_run": t.get("lr"),
                                 "next_run": t.get("nr"), "problem": problem})
        for sv in _list(h.get("sv")):
            n, _, st = sv.partition("=")
            p["renewal"].append({"kind": "service", "name": n, "state": st,
                                 "problem": None if st == "Running" else f"service is {st}"})
        return p

    rows = [ln.split("\t") for ln in stdout.splitlines() if "\t" in ln]
    if not any(r[0] == "host" for r in rows):
        raise ValueError(f"no probe output: {stdout.strip()[:200]!r}")
    timers = {}
    for r in rows:
        r += [""] * (8 - len(r))
        if r[0] == "host":
            p["host"] = r[1]
        elif r[0] == "c":
            same = next((c for c in p["certs"] if c["thumb"] == r[2].upper()), None)
            if same:  # e.g. cert.pem and the fullchain.pem nginx uses
                same["where"] += f", {r[1]}"
                same["source"] += f",{r[6]}" if r[6] not in same["source"].split(",") else ""
                continue
            p["certs"].append({"thumb": r[2].upper(), "names": [n for n in r[4].split(",") if n],
                               "issuer": r[5] or None, "not_after": r[3] or None, "where": r[1], "source": r[6]})
        elif r[0] == "tm":
            problem = (f"timer is {r[3]}/{r[4]}" if r[3] not in ("enabled", "static") or r[4] != "active"
                       else f"has not run since {r[5][:10]}" if _stale(r[5], now) else None)
            timers[r[1].removesuffix(".timer")] = {"kind": "timer", "name": r[1], "state": f"{r[3]}/{r[4]}",
                                                    "last_run": r[5] or None, "next_run": r[6] or None,
                                                    "problem": problem}
        elif r[0] == "sr" and r[1].removesuffix(".service") in timers:
            t = timers[r[1].removesuffix(".service")]
            if not t["problem"] and (r[2] not in ("success", "") or r[3] not in ("0", "")):
                t["problem"] = f"last renewal run {r[4][:10] or '?'} failed (result={r[2]}, exit={r[3]})"
        elif r[0] == "cr":
            p["renewal"].append({"kind": "cron", "name": r[1], "state": "present", "problem": None})
        elif r[0] == "ws":
            p["web"].append(f"{r[1]} {r[2]}")
        elif r[0] == "l4":
            p["web"].append(f":443 {r[1]}")
        elif r[0] == "gap":
            p["gaps"].append(r[1])
    p["renewal"] = list(timers.values()) + p["renewal"]
    p["in_use"] = [c["thumb"] for c in p["certs"]]
    return p


def probe_cert_vm(sub: str, vm: dict, timeout: float, now: datetime) -> tuple[dict | None, str | None]:
    """(normalized probe, None) or (None, error text). Never raises. One retry when another
    Run Command (e.g. sql-check) is executing on the VM."""
    win = vm.get("os") == "Windows"
    run, script = (azure.run_powershell, CERT_PS) if win else (azure.run_shell, CERT_SH)
    for attempt in range(2):
        try:
            out, err = run(sub, vm["resourceGroup"], vm["name"], str(script), timeout)
            try:
                return parse_cert_probe("Windows" if win else "Linux", out, now), None
            except ValueError as e:
                return None, f"unparseable probe output ({e}); stderr: {' '.join(err.split())[:200]}"
        except azure.RunCommandBusy as e:
            if attempt:
                return None, f"another Run Command is executing on the VM, retry next run ({e})"
            time.sleep(BUSY_RETRY_SECONDS)
        except Exception as e:
            return None, str(e)


def renewal_text(p: dict) -> str:
    return "; ".join(f"{r['kind']} {r['name']} {r.get('state') or ''}"
                     f"{' last ' + r['last_run'][:10] if r.get('last_run') else ''}"
                     f"{' PROBLEM: ' + r['problem'] if r.get('problem') else ''}" for r in p["renewal"]) or "none found"


def cert_status(not_after: str | None, now: datetime, th) -> tuple[float | None, str]:
    if not not_after:
        return None, "unknown"
    d = days_left(not_after, now)
    return round(d, 1), "expired" if d < 0 else "expiring" if d < th.warn_days else "ok"


def cert_rows(sub: str, vm: str, p: dict, now: datetime, th) -> list[dict]:
    """certs snapshot rows for one probed VM: one per certificate in use (or one 'none' row)."""
    by_thumb = {c["thumb"]: c for c in p["certs"]}
    sites = {}
    for b in p["bindings"]:
        sites.setdefault(b["thumb"], []).append(f"{b['site']} {b['host'] or '*'}:{b['port']}")
    ren, rows = renewal_text(p)[:1000], []
    for t in dict.fromkeys(p["in_use"]):
        c = by_thumb.get(t, {"thumb": t, "names": [], "issuer": None, "not_after": None, "where": "?"})
        d, status = cert_status(c["not_after"], now, th)
        rows.append({"id": f"{vm}|{t}", "sub": sub, "server": vm, "names": ", ".join(c["names"])[:1000],
                     "source": "; ".join([c["where"], *sites.get(t, [])])[:400], "issuer": c["issuer"],
                     "not_after": c["not_after"], "days_left": d, "thumbprint": t, "renewal": ren, "status": status,
                     "detail": "; ".join(p["gaps"])[:2000] or None})
    for b in p["bindings"]:
        if not b["thumb"]:
            rows.append({"id": f"{vm}|{b['site']}|{b['host']}:{b['port']}", "sub": sub, "server": vm,
                         "names": b["host"], "source": f"{b['site']} {b['host'] or '*'}:{b['port']}",
                         "renewal": ren, "status": "mismatch", "detail": "no certificate bound"})
    if not rows:
        rows.append({"id": f"{vm}|none", "sub": sub, "server": vm, "renewal": ren, "status": "none",
                     "detail": f"no certificate in use; web: {', '.join(p['web']) or 'none'}"})
    return rows


def _vm_of(alert_name: str) -> str | None:
    """cert-* alert names are `vm/...` (server side) or `https://host` (served certificate)."""
    return None if alert_name.startswith("https://") else alert_name.split("/")[0].lower()


def cert_check(cfg: Config, dry_run: bool):
    """Daily: probe the configured app servers (Run Command, read-only) for IIS bindings,
    certificates and their renewal task/timer, then check from here what each public hostname
    really serves on 443. Alerts via reconcile; the latest status goes to the certs table."""
    started, now, th = now_iso(), datetime.now(timezone.utc), cfg.certs
    arm, db = azure.Arm(), open_db(cfg, dry_run)
    findings, scope, rows, targets, discovered, ips = [], set(), [], [], True, {}
    want = {n.lower() for n in th.servers}
    for s in cfg.subscriptions:
        scope.add(("cert-collector", s.id, "discovery"))
        try:
            vms = azure.list_vms(arm, s.id)
            ips.update(azure.vm_public_ips(arm, s.id))
        except Exception as e:
            discovered = False
            findings.append(Finding("cert-collector", s.id, "discovery", f"{s.name}: VM discovery failed: {e}"))
            log(f"{s.name}: VM discovery FAILED {e}")
            continue
        targets += [(s, v) for v in vms if v["name"].lower() in want]
    first_sub = cfg.subscriptions[0].id
    if discovered:
        scope.add(("cert-collector", first_sub, "config"))
        missing = sorted(want - {v["name"].lower() for _, v in targets})
        if missing:
            findings.append(Finding("cert-collector", first_sub, "config",
                                    f"[certs] servers not found in any subscription: {', '.join(missing)}"))
    open_cert = [{**r, "name": r["alert_key"].split(":", 2)[2]} for r in open_alerts(db) if r["kind"].startswith("cert-")]

    def held_by(pred):
        return {tuple(r["alert_key"].split(":", 2)) for r in open_cert if pred(r)}

    running = [(s, v) for s, v in targets if v.get("power") == "PowerState/running"]
    for s, v in targets:
        if (s, v) not in running:  # vm-down is check's job; hold this VM's cert alerts
            rows.append({"id": f"{v['name']}|none", "sub": s.id, "server": v["name"], "status": "error",
                         "detail": f"not probed: VM {v.get('power') or 'power state unknown'}"})
    timeout = th.timeout_minutes * 60
    with ThreadPoolExecutor(max_workers=max(1, len(running))) as ex:
        results = list(ex.map(lambda t: probe_cert_vm(t[0].id, t[1], timeout, now), running))

    probed, all_ok = [], discovered
    for (s, v), (p, err) in zip(running, results):
        name = v["name"]
        scope.add(("cert-collector", s.id, f"{name}/probe"))
        if err:
            all_ok = False
            findings.append(Finding("cert-collector", s.id, f"{name}/probe", f"{name}: certificate check failed: "
                                                                              f"{err[:300]}"))
            rows.append({"id": f"{name}|none", "sub": s.id, "server": name, "status": "error", "detail": err[:2000]})
            log(f"{name}: FAILED {err}")
            continue
        found = server_cert_findings(s.id, name, p, now, th)
        if p["gaps"]:  # a read failed: report, open new findings, but resolve nothing for this VM
            all_ok = False
            findings.append(Finding("cert-collector", s.id, f"{name}/probe",
                                    f"{name}: certificate check incomplete: {'; '.join(p['gaps'])[:300]}"))
        else:
            scope |= held_by(lambda r: r["kind"] in CERT_KINDS and _vm_of(r["name"]) == name.lower())
        findings += found
        probed.append((s, name, p, ips.get(v["id"].lower(), set())))
        rows += cert_rows(s.id, name, p, now, th)
        log(f"{name}: web={p['web']} certs_in_use={len(set(p['in_use']))} bindings={len(p['bindings'])} "
            f"renewal=[{renewal_text(p)}] gaps={p['gaps'] or 'none'} findings={[f.kind for f in found]}")
    if discovered:  # VMs dropped from [certs] servers (or deleted): their alerts may resolve
        names = {v["name"].lower() for _, v in targets}
        scope |= held_by(lambda r: _vm_of(r["name"]) not in (None, *names))

    # External check: what each public hostname of the probed servers serves on 443.
    hosts: dict[str, str] = {}
    for s, _, p, _ in probed:
        in_use = set(p["in_use"])
        names = [b["host"] for b in p["bindings"]] + [n for c in p["certs"] if c["thumb"] in in_use for n in c["names"]]
        for h in names:
            hosts.setdefault(h.lower().rstrip("."), s.id)
    skip = {h.lower() for h in th.skip_hosts}
    for host, sub in sorted(hosts.items()):
        url = f"https://{host}"
        reason = ("wildcard name" if "*" in host else "not a DNS name" if "." not in host
                  else "in [certs] skip_hosts" if host in skip else None)
        addrs = []
        if not reason:
            try:
                addrs = tls.resolve(host)
                if not tls.is_public(addrs):
                    reason = f"internal name ({addrs[0]})"
            except OSError:
                reason = "does not resolve"
        if reason:
            if reason != "does not resolve":  # deterministic skip: a stale probe-failure alert may clear
                scope.add(("cert-collector", sub, url))
            rows.append({"id": url, "sub": sub, "server": "external", "names": host, "status": "skipped",
                         "detail": f"not probed over TLS: {reason}"})
            log(f"{host}: TLS probe skipped ({reason})")
            continue
        scope.add(("cert-collector", sub, url))
        try:
            sc = tls.served_cert(host, next((a for a in addrs if ":" not in a), addrs[0]))  # prefer IPv4
        except (OSError, ValueError) as e:
            all_ok = False
            findings.append(Finding("cert-collector", sub, url, f"{host}: TLS probe on 443 failed: {e}"))
            rows.append({"id": url, "sub": sub, "server": "external", "names": host, "status": "error",
                         "source": f"served on 443 ({addrs[0]})", "detail": str(e)[:2000]})
            log(f"{host}: TLS probe FAILED {e}")
            continue
        # compare with the server's certs only when DNS points at that VM: behind a proxy or CDN
        # (e.g. Cloudflare) the edge certificate is served, not the one on the VM
        direct = [(n, p) for _, n, p, vip in probed if vip & set(addrs)]
        disk = [c for _, p in direct for c in p["certs"]]
        found = served_findings(sub, host, sc, disk, now, th)
        findings += found
        scope |= held_by(lambda r: r["kind"] in CERT_KINDS and r["name"] == url)
        d, status = cert_status(sc["not_after"], now, th)
        if any(f.kind == "cert-mismatch" for f in found):
            status = "mismatch"
        rows.append({"id": url, "sub": sub, "server": "external", "names": ", ".join(sc["names"])[:1000],
                     "source": f"served on 443 by {', '.join(n for n, _ in direct) or 'no probed VM (proxy/CDN?)'} ({addrs[0]})",
                     "issuer": sc["issuer"], "not_after": sc["not_after"],
                     "days_left": d, "thumbprint": sc["thumb"], "status": status,
                     "detail": "; ".join(f.summary for f in found if f.kind == "cert-mismatch")[:2000] or None})
        log(f"{host}: serves {sc['thumb'][:8]} issuer={sc['issuer']} expires={sc['not_after'][:10]} "
            f"verify={sc['error'] or 'ok'} via={[n for n, _ in direct] or 'not a probed VM'} findings={[f.kind for f in found]}")
    if all_ok:  # every server and host was checked: alerts of hostnames no longer in use may resolve
        scope |= held_by(lambda r: r["name"].startswith("https://") and r["name"][8:] not in hosts)

    save_certs(db, rows, now_iso())
    opened, resolved = reconcile(db, findings, scope, now_iso())
    log(f"cert-check: {len(probed)}/{len(targets)} servers probed, {len(hosts)} hostnames, "
        f"findings={len(findings)} opened={len(opened)} resolved={len(resolved)}")
    if opened or resolved:
        notify.send(cfg.email, *notify.alert_email(opened, resolved, {s.id: s.name for s in cfg.subscriptions}),
                    dry_run=dry_run)
    record_run(db, "cert-check", started, now_iso(), ok=not any(f.kind == "cert-collector" for f in findings),
               message=f"probed={len(probed)}/{len(targets)} hosts={len(hosts)} findings={len(findings)} "
                       f"opened={len(opened)} resolved={len(resolved)}")
    db.commit()


def daily(cfg: Config, dry_run: bool):
    started = now_iso()
    arm, db = azure.Arm(), open_db(cfg, dry_run)
    yesterday = date.today() - timedelta(days=1)
    month_start = yesterday.replace(day=1)
    days_in_month = calendar.monthrange(yesterday.year, yesterday.month)[1]
    start = min(month_start, yesterday - timedelta(days=8))

    fleet, cost, findings, scope = [], [], [], set()
    for s in cfg.subscriptions:
        try:
            vms = azure.list_vms(arm, s.id)
            fleet.append({"sub_name": s.name, "total": len(vms),
                          "running": sum(v.get("power") == "PowerState/running" for v in vms)})
        except Exception as e:
            fleet.append({"sub_name": f"{s.name} (inventory failed)", "total": 0, "running": 0})
            log(f"{s.name}: inventory FAILED {e}")
        if not s.cost:
            continue
        scope.add(("cost-collector", s.id))
        try:
            d = azure.daily_cost(arm, s.id, start.isoformat(), yesterday.isoformat())
            save_cost(db, s.id, d)
            mtd = sum(c for day, c in d.items() if day >= month_start.isoformat())
            cost.append({"sub_name": s.name, "yesterday": d.get(yesterday.isoformat(), 0.0), "mtd": mtd,
                         "projected": mtd / yesterday.day * days_in_month,
                         "top": azure.top_resources_mtd(arm, s.id, yesterday.isoformat())})
            findings += cost_findings(s.id, s.name, d, yesterday.isoformat(), cfg.thresholds)
            scope.add(("cost-spike", s.id))
        except Exception as e:
            cost.append({"sub_name": s.name, "error": str(e)})
            findings.append(Finding("cost-collector", s.id, "cost", f"{s.name}: cost data unavailable: {e}"))
            log(f"{s.name}: cost FAILED {e}")

    opened, resolved = reconcile(db, findings, scope, now_iso())
    if opened or resolved:
        notify.send(cfg.email, *notify.alert_email(opened, resolved, {s.id: s.name for s in cfg.subscriptions}),
                    dry_run=dry_run)
    record_run(db, "daily", started, now_iso(), ok=not any(f.kind == "cost-collector" for f in findings),
               message=f"opened={len(opened)} resolved={len(resolved)}")
    db.commit()
    notify.send(cfg.email, *notify.digest_email(date.today().isoformat(), fleet, open_alerts(db), cost),
                dry_run=dry_run)
    log(f"daily done: opened={len(opened)} resolved={len(resolved)}")


def main(argv=None):
    p = argparse.ArgumentParser(prog="qci-infra")
    p.add_argument("command", choices=["check", "sql-check", "cert-check", "daily", "test-email"])
    p.add_argument("--config", help="path to config.toml")
    p.add_argument("--dry-run", action="store_true", help="print emails instead of sending")
    a = p.parse_args(argv)
    cfg = load_config(a.config)
    if a.command == "check":
        check(cfg, a.dry_run)
    elif a.command == "sql-check":
        sql_check(cfg, a.dry_run)
    elif a.command == "cert-check":
        cert_check(cfg, a.dry_run)
    elif a.command == "daily":
        daily(cfg, a.dry_run)
    else:
        notify.send(cfg.email, "[QCI] Test email", "SendGrid delivery from the Mac Studio works.", dry_run=a.dry_run)
        log("test email sent")


if __name__ == "__main__":
    main()

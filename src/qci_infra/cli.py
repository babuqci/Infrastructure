"""Entry point: `qci-infra check` (every 5 min), `qci-infra daily` (cost + digest), `qci-infra test-email`."""

import argparse
import calendar
from datetime import date, datetime, timedelta, timezone

import httpx

from . import azure, notify
from .config import Config, load_config
from .rules import METRIC_KINDS, STOPPED_POWER, VM_KINDS, Finding, cost_findings, vm_findings
from .store import connect, open_alerts, reconcile, save_cost


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def log(msg: str):
    print(f"{now_iso()} {msg}", flush=True)


def open_db(cfg: Config, dry_run: bool):
    return connect(":memory:" if dry_run else cfg.db)  # dry runs never touch real alert state


def check(cfg: Config, dry_run: bool):
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
    db.commit()
    if cfg.heartbeat_url and not dry_run:
        httpx.get(cfg.heartbeat_url, timeout=10)


def daily(cfg: Config, dry_run: bool):
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
                         "top": azure.top_resources_mtd(arm, s.id)})
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
    db.commit()
    notify.send(cfg.email, *notify.digest_email(date.today().isoformat(), fleet, open_alerts(db), cost),
                dry_run=dry_run)
    log(f"daily done: opened={len(opened)} resolved={len(resolved)}")


def main(argv=None):
    p = argparse.ArgumentParser(prog="qci-infra")
    p.add_argument("command", choices=["check", "daily", "test-email"])
    p.add_argument("--config", help="path to config.toml")
    p.add_argument("--dry-run", action="store_true", help="print emails instead of sending")
    a = p.parse_args(argv)
    cfg = load_config(a.config)
    if a.command == "check":
        check(cfg, a.dry_run)
    elif a.command == "daily":
        daily(cfg, a.dry_run)
    else:
        notify.send(cfg.email, "[QCI] Test email", "SendGrid delivery from the Mac Studio works.", dry_run=a.dry_run)
        log("test email sent")


if __name__ == "__main__":
    main()

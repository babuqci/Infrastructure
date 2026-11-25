from qci_infra.config import Thresholds
from qci_infra.rules import cost_findings, vm_findings

TH = Thresholds()
SUB = "sub-1"
VM_ID = "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm-a"


def vm(power="PowerState/running", tags=None):
    return {"id": VM_ID, "name": "vm-a", "resourceGroup": "rg", "power": power, "tags": tags or {}}


def metrics(cpu=(5, 5, 5), mem=(50, 50, 50), avail=(1, 1, 1)):
    return {VM_ID.lower(): {"Percentage CPU": list(cpu), "Available Memory Percentage": list(mem),
                            "VmAvailabilityMetric": list(avail)}}


def kinds(findings):
    return sorted(f.kind for f in findings)


def test_healthy_vm_has_no_findings():
    assert vm_findings(SUB, [vm()], {VM_ID.lower(): "Available"}, metrics(), TH, "qci-monitor") == []


def test_stopped_vm_is_down():
    f = vm_findings(SUB, [vm(power="PowerState/deallocated")], {}, metrics(), TH, "qci-monitor")
    assert kinds(f) == ["vm-down"]
    assert "deallocated" in f[0].summary
    assert f[0].key == "vm-down:sub-1:vm-a"


def test_unknown_power_state_alone_is_not_down():
    # Resource Graph occasionally returns a VM with no power state; other signals decide.
    assert vm_findings(SUB, [vm(power="")], {VM_ID.lower(): "Available"}, metrics(), TH, "qci-monitor") == []
    assert kinds(vm_findings(SUB, [vm(power="")], {VM_ID.lower(): "Unavailable"}, metrics(), TH,
                             "qci-monitor")) == ["vm-down"]


def test_starting_vm_is_not_down():
    assert vm_findings(SUB, [vm(power="PowerState/starting")], {}, metrics(), TH, "qci-monitor") == []


def test_unavailable_health_is_down():
    assert kinds(vm_findings(SUB, [vm()], {VM_ID.lower(): "Unavailable"}, metrics(), TH, "qci-monitor")) == ["vm-down"]


def test_degraded_health_is_degraded():
    assert kinds(vm_findings(SUB, [vm()], {VM_ID.lower(): "Degraded"}, metrics(), TH, "qci-monitor")) == ["vm-degraded"]


def test_availability_metric_zero_is_down():
    assert kinds(vm_findings(SUB, [vm()], {}, metrics(avail=(1, 1, 0)), TH, "qci-monitor")) == ["vm-down"]


def test_one_finding_when_several_down_signals():
    f = vm_findings(SUB, [vm(power="PowerState/stopped")], {VM_ID.lower(): "Unavailable"},
                    metrics(avail=(0,)), TH, "qci-monitor")
    assert kinds(f) == ["vm-down"]


def test_cpu_high_needs_whole_window():
    assert kinds(vm_findings(SUB, [vm()], {}, metrics(cpu=(95, 96, 97)), TH, "qci-monitor")) == ["cpu-high"]
    assert vm_findings(SUB, [vm()], {}, metrics(cpu=(50, 96, 97)), TH, "qci-monitor") == []
    assert vm_findings(SUB, [vm()], {}, metrics(cpu=(96, 97)), TH, "qci-monitor") == []  # too few points


def test_memory_low():
    assert kinds(vm_findings(SUB, [vm()], {}, metrics(mem=(8, 6, 5)), TH, "qci-monitor")) == ["mem-low"]


def test_sql_vm_uses_lower_memory_threshold():
    sql_vm = {**vm(), "sql": True}
    assert vm_findings(SUB, [sql_vm], {}, metrics(mem=(5, 4, 3)), TH, "qci-monitor") == []
    assert kinds(vm_findings(SUB, [sql_vm], {}, metrics(mem=(1, 1, 1)), TH, "qci-monitor")) == ["mem-low"]


def test_metrics_skipped_when_vm_down():
    f = vm_findings(SUB, [vm(power="PowerState/deallocated")], {}, metrics(cpu=(99, 99, 99)), TH, "qci-monitor")
    assert kinds(f) == ["vm-down"]


def test_ignore_tag_skips_vm():
    v = vm(power="PowerState/deallocated", tags={"qci-monitor": "off"})
    assert vm_findings(SUB, [v], {}, metrics(), TH, "qci-monitor") == []


def test_cost_spike():
    daily = {f"2026-11-{d:02d}": 300.0 for d in range(1, 21)}
    daily["2026-11-21"] = 600.0
    f = cost_findings(SUB, "QCI Internal", daily, "2026-11-21", TH)
    assert kinds(f) == ["cost-spike"]
    assert "$600" in f[0].summary


def test_cost_no_spike_when_small_delta_or_no_history():
    daily = {f"2026-11-{d:02d}": 50.0 for d in range(1, 21)}
    daily["2026-11-21"] = 120.0  # 2.4x but only +$70
    assert cost_findings(SUB, "x", daily, "2026-11-21", TH) == []
    assert cost_findings(SUB, "x", {"2026-11-21": 999.0}, "2026-11-21", TH) == []


# --- SQL Server probe rules -------------------------------------------------
from datetime import datetime, timezone  # noqa: E402

from qci_infra.config import Sql  # noqa: E402
from qci_infra.rules import sql_findings, sql_judged_kinds  # noqa: E402

NOW = datetime(2026, 11, 22, 12, 0, tzinfo=timezone.utc)
SQL = Sql()


def probe(**over):
    h = {"svc": {"MSSQLSERVER": "Running", "SQLSERVERAGENT": "Running"},
         "drives": [{"d": "C", "size": 127.0, "free": 60.0}, {"d": "K", "size": 1024.0, "free": 400.0}],
         "dbs": ["QCIDB=ONLINE"], "db": "QCIDB",
         "bk": {"D": {"t": "2026-11-22T02:00:00Z", "f": r"K:\MSSQL\Backup\QCIDB_full.bak"}}, "gaps": []}
    h.update(over)
    return {k: v for k, v in h.items() if v is not ...}  # `...` drops a key (that read failed)


def test_healthy_sql_vm_has_no_findings():
    assert sql_findings(SUB, "sql1", probe(), NOW, SQL) == []
    assert sorted(sql_judged_kinds(probe())) == ["sql-backup-stale", "sql-db-missing", "sql-disk-low",
                                                 "sql-service-down"]


def test_stale_full_backup():
    f = sql_findings(SUB, "sql1", probe(bk={"D": {"t": "2026-11-21T09:00:00Z", "f": "x.bak"}}), NOW, SQL)
    assert kinds(f) == ["sql-backup-stale"] and "27 h ago" in f[0].summary
    assert f[0].key == "sql-backup-stale:sub-1:sql1"


def test_only_log_backups_is_stale():
    f = sql_findings(SUB, "sql1", probe(bk={"L": {"t": "2026-11-22T11:00:00Z", "f": "x.trn"}}), NOW, SQL)
    assert kinds(f) == ["sql-backup-stale"] and "no full backup" in f[0].summary
    assert kinds(sql_findings(SUB, "sql1", probe(bk={}), NOW, SQL)) == ["sql-backup-stale"]


def test_disk_low_by_percent_or_gb():
    pct = probe(drives=[{"d": "K", "size": 1024.0, "free": 90.0}])  # 9% but 90 GB
    gb = probe(drives=[{"d": "K", "size": 100.0, "free": 12.0}])  # 12% but 12 GB
    for h in (pct, gb):
        assert kinds(sql_findings(SUB, "sql1", h, NOW, SQL)) == ["sql-disk-low"]
    both = probe(drives=[{"d": "C", "size": 127.0, "free": 5.0}, {"d": "K", "size": 1024.0, "free": 12.0}])
    f = sql_findings(SUB, "sql1", both, NOW, SQL)
    assert len(f) == 1 and "C: 5 GB free" in f[0].summary and "K: 12 GB free" in f[0].summary


def test_service_down_or_missing():
    f = sql_findings(SUB, "sql1", probe(svc={"MSSQLSERVER": "Running", "SQLSERVERAGENT": "Stopped"}), NOW, SQL)
    assert kinds(f) == ["sql-service-down"] and "SQLSERVERAGENT Stopped" in f[0].summary
    f = sql_findings(SUB, "sql1", probe(svc={"SQLSERVERAGENT": "Running"}), NOW, SQL)
    assert "MSSQLSERVER Missing" in f[0].summary


def test_db_missing_replaces_backup_check():
    h = probe(dbs=[], db=None, bk=...)
    assert kinds(sql_findings(SUB, "sql1", h, NOW, SQL)) == ["sql-db-missing"]
    assert "sql-backup-stale" in sql_judged_kinds(h)  # no db: an old backup alert may resolve


def test_failed_reads_judge_nothing():
    # SQL unreachable / permission denied: no db or backup verdict either way
    h = probe(dbs=..., db=..., bk=..., gaps=["sys.databases: Login failed"])
    assert sql_findings(SUB, "sql1", h, NOW, SQL) == []
    assert sorted(sql_judged_kinds(h)) == ["sql-disk-low", "sql-service-down"]
    h = probe(bk=..., gaps=["msdb.backupset: permission denied"])
    assert sql_findings(SUB, "sql1", h, NOW, SQL) == []
    assert "sql-backup-stale" not in sql_judged_kinds(h)
    assert sql_findings(SUB, "sql1", probe(svc=..., drives=...), NOW, SQL) == []

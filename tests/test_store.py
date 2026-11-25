from qci_infra.rules import Finding
from qci_infra.store import connect_sqlite as connect, open_alerts, reconcile, save_vms

T1, T2, T3 = "2026-11-22T10:00:00+00:00", "2026-11-22T10:05:00+00:00", "2026-11-22T10:10:00+00:00"
DOWN = Finding("vm-down", "sub-1", "vm-a", "vm-a is deallocated")
SCOPE = {("vm-down", "sub-1")}


def test_new_finding_opens_once():
    db = connect(":memory:")
    opened, resolved = reconcile(db, [DOWN], SCOPE, T1)
    assert opened == [DOWN] and resolved == []
    opened, resolved = reconcile(db, [DOWN], SCOPE, T2)  # still down: no new alert
    assert opened == [] and resolved == []
    assert [r["alert_key"] for r in open_alerts(db)] == ["vm-down:sub-1:vm-a"]


def test_cleared_finding_resolves():
    db = connect(":memory:")
    reconcile(db, [DOWN], SCOPE, T1)
    opened, resolved = reconcile(db, [], SCOPE, T2)
    assert opened == [] and [r["alert_key"] for r in resolved] == ["vm-down:sub-1:vm-a"]
    assert open_alerts(db) == []


def test_out_of_scope_alert_is_not_resolved():
    db = connect(":memory:")
    reconcile(db, [DOWN], SCOPE, T1)
    opened, resolved = reconcile(db, [], set(), T2)  # sub-1 collector failed
    assert resolved == [] and len(open_alerts(db)) == 1


def test_uncommitted_alert_is_reopened_next_run():
    db = connect(":memory:")
    reconcile(db, [DOWN], SCOPE, T1)
    db.rollback()  # email send failed
    opened, _ = reconcile(db, [DOWN], SCOPE, T2)
    assert opened == [DOWN]


def test_resolved_alert_can_reopen():
    db = connect(":memory:")
    reconcile(db, [DOWN], SCOPE, T1)
    reconcile(db, [], SCOPE, T2)
    opened, _ = reconcile(db, [DOWN], SCOPE, T3)
    assert opened == [DOWN]
    assert open_alerts(db)[0]["opened_at"] == T3


def test_save_vms_replaces_snapshot_per_subscription():
    db = connect(":memory:")
    row = {"vm_id": "id-a", "name": "vm-a", "rg": "rg", "location": "westus2", "size": "B2s", "os": "Windows",
           "power": "PowerState/running", "health": "Available", "cpu": 5.0, "mem": 50.0, "is_sql": 0}
    save_vms(db, "sub-1", [row, {**row, "vm_id": "id-b", "name": "vm-b"}], T1)
    save_vms(db, "sub-1", [row], T2)  # vm-b deleted since
    names = [r["name"] for r in db.query("select name, updated_at from vms")]
    assert names == ["vm-a"]


def test_per_vm_scope_resolves_only_that_vm():
    db = connect(":memory:")
    a = Finding("sql-disk-low", "sub-1", "sql-a", "sql-a: low disk")
    b = Finding("sql-disk-low", "sub-1", "sql-b", "sql-b: low disk")
    reconcile(db, [a, b], set(), T1)
    # sql-b's probe failed this run: only sql-a is in scope
    opened, resolved = reconcile(db, [], {("sql-disk-low", "sub-1", "sql-a")}, T2)
    assert [r["alert_key"] for r in resolved] == ["sql-disk-low:sub-1:sql-a"]
    assert [r["alert_key"] for r in open_alerts(db)] == ["sql-disk-low:sub-1:sql-b"]


def test_save_sql_health_replaces_snapshot_per_subscription():
    from qci_infra.store import save_sql_health
    db = connect(":memory:")
    row = {"vm_id": "id-a", "vm_name": "sql-a", "edition": "Developer Edition (64-bit)", "version": "16.0.4135.4",
           "db_name": "QCIDB", "last_full_backup": "2026-11-22T02:00:00Z", "last_full_backup_path": r"K:\b.bak",
           "drives": '[{"d": "K", "size": 1024.0, "free": 400.0}]', "services": "MSSQLSERVER=Running",
           "permission_gaps": None, "ok": 1, "error": None}
    save_sql_health(db, "sub-1", [row, {**row, "vm_id": "id-b", "vm_name": "sql-b"}], T1)
    save_sql_health(db, "sub-2", [{**row, "vm_id": "id-c", "vm_name": "sql-c"}], T1)
    save_sql_health(db, "sub-1", [{**row, "ok": 0, "error": "timed out"}], T2)
    got = db.query("select vm_name, sub, ok, error, updated_at from sql_health order by vm_name")
    assert [(r["vm_name"], r["ok"], r["updated_at"]) for r in got] == [("sql-a", 0, T2), ("sql-c", 1, T1)]


def test_save_certs_replaces_snapshot():
    from qci_infra.store import save_certs
    db = connect(":memory:")
    save_certs(db, [{"id": "vm-a|AB", "sub": "sub-1", "server": "vm-a", "names": "a.example.com", "days_left": 40.5,
                     "status": "ok"}, {"id": "https://a.example.com", "sub": "sub-1", "server": "external",
                                       "status": "skipped"}], T1)
    save_certs(db, [{"id": "vm-a|CD", "sub": "sub-1", "server": "vm-a", "status": "expiring", "days_left": 3.0}], T2)
    rows = db.query("select * from certs")
    assert [(r["id"], r["status"], r["days_left"], r["updated_at"]) for r in rows] == [("vm-a|CD", "expiring", 3.0, T2)]

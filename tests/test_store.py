from qci_infra.rules import Finding
from qci_infra.store import connect, open_alerts, reconcile

T1, T2, T3 = "2026-11-22T10:00:00+00:00", "2026-11-22T10:05:00+00:00", "2026-11-22T10:10:00+00:00"
DOWN = Finding("vm-down", "sub-1", "vm-a", "vm-a is deallocated")
SCOPE = {("vm-down", "sub-1")}


def test_new_finding_opens_once():
    db = connect(":memory:")
    opened, resolved = reconcile(db, [DOWN], SCOPE, T1)
    assert opened == [DOWN] and resolved == []
    opened, resolved = reconcile(db, [DOWN], SCOPE, T2)  # still down: no new alert
    assert opened == [] and resolved == []
    assert [r["key"] for r in open_alerts(db)] == ["vm-down:sub-1:vm-a"]


def test_cleared_finding_resolves():
    db = connect(":memory:")
    reconcile(db, [DOWN], SCOPE, T1)
    opened, resolved = reconcile(db, [], SCOPE, T2)
    assert opened == [] and [r["key"] for r in resolved] == ["vm-down:sub-1:vm-a"]
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

from qci_infra.notify import alert_email, digest_email
from qci_infra.rules import Finding


def test_alert_email_lists_new_and_resolved():
    f = Finding("vm-down", "sub-1", "vm-a", "vm-a (rg) is down: power state deallocated")
    resolved = [{"kind": "cpu-high", "summary": "vm-b CPU above 90%", "opened_at": "2026-11-22T10:00:00+00:00"}]
    subject, body = alert_email([f], resolved, {"sub-1": "QCI Internal"})
    assert subject.startswith("[QCI Alert] 1 new, 1 resolved: vm-a")
    assert "QCI Internal" in body and "RESOLVED" in body and "vm-b" in body


def test_digest_totals_and_cost_error():
    fleet = [{"sub_name": "A", "total": 3, "running": 2}, {"sub_name": "B", "total": 1, "running": 1}]
    cost = [{"sub_name": "A", "yesterday": 600.0, "mtd": 12000.0, "projected": 18000.0, "top": [("vm-a", 900.0, 30.0), ("oldplan", 2145.0, 0.0)]},
            {"sub_name": "B", "error": "RBACAccessDenied"}]
    subject, body = digest_email("2026-11-22", fleet, [], cost)
    assert subject == "[QCI Daily] 2026-11-22: 3/4 VMs running, 0 open alerts, $12,000 MTD"
    assert "B: unavailable (RBACAccessDenied)" in body and "vm-a" in body
    assert "oldplan  (no cost yesterday)" in body and "vm-a  (no cost" not in body

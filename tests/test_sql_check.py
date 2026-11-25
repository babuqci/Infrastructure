import json

import pytest

from qci_infra.cli import parse_probe, sql_row
from qci_infra.rules import Finding

VM = {"id": "/subscriptions/S/resourceGroups/RG/providers/Microsoft.Compute/virtualMachines/SQL1", "name": "sql1",
      "resourceGroup": "RG", "power": "PowerState/running"}


def test_parse_probe_takes_last_json_line():
    assert parse_probe('WARNING: something\n{"host": "SQL1", "gaps": []}\n') == {"host": "SQL1", "gaps": []}
    with pytest.raises(ValueError):
        parse_probe("Access is denied.")
    with pytest.raises(ValueError):
        parse_probe('{"host": "SQL1", "drives": [{"d"')  # truncated at the Run Command output limit


def test_sql_row_from_probe():
    h = {"edition": "Developer Edition (64-bit)", "version": "16.0.1", "db": "QCIDB",
         "svc": {"MSSQLSERVER": "Running", "SQLSERVERAGENT": "Running"}, "drives": [{"d": "K", "size": 10, "free": 1}],
         "bk": {"D": {"t": "2026-11-22T02:00:00Z", "f": "K:\\a.bak"}, "L": {"t": "2026-11-22T11:00:00Z", "f": "x"}},
         "gaps": ["msdb.sysjobhistory: denied"]}
    r = sql_row(VM, h, [Finding("sql-disk-low", "S", "sql1", "low")], None)
    assert r["vm_id"] == VM["id"].lower() and r["db_name"] == "QCIDB"
    assert (r["last_full_backup"], r["last_full_backup_path"]) == ("2026-11-22T02:00:00Z", "K:\\a.bak")
    assert json.loads(r["drives"]) == h["drives"] and r["services"] == "MSSQLSERVER=Running, SQLSERVERAGENT=Running"
    assert r["permission_gaps"] == "msdb.sysjobhistory: denied" and r["ok"] == 0 and r["error"] is None
    assert sql_row(VM, h, [], None)["ok"] == 1


def test_sql_row_for_failed_probe():
    r = sql_row(VM, None, [], "Run Command timed out after 20 min")
    assert r["ok"] == 0 and r["error"].startswith("Run Command timed out") and r["db_name"] is None


def test_sql_check_holds_alerts_of_failed_vm(monkeypatch, capsys):
    from qci_infra import azure, cli
    from qci_infra.config import Config, Email, Subscription
    from qci_infra.store import connect_sqlite, open_alerts

    db = connect_sqlite(":memory:")
    cfg = Config(subscriptions=[Subscription("S", "QCI Internal")], email=Email("to@x", "from@x", "k"))
    vms = [{**VM, "id": f"/vm/{n}", "name": n} for n in ("good", "bad")] + \
          [{**VM, "id": "/vm/off", "name": "off", "power": "PowerState/deallocated"}]
    probes = {"good": {"svc": {"MSSQLSERVER": "Running", "SQLSERVERAGENT": "Running"},
                       "drives": [{"d": "K", "size": 100.0, "free": 50.0}], "dbs": ["QCIDB=ONLINE"], "db": "QCIDB",
                       "bk": {}, "gaps": []}}

    def run(sub, rg, vm, script, timeout):
        if vm not in probes:
            raise azure.AzureError("Run Command timed out after 20 min")
        return json.dumps(probes[vm]), ""

    monkeypatch.setattr(cli, "open_db", lambda cfg, dry_run: db)
    monkeypatch.setattr(azure, "Arm", lambda: None)
    monkeypatch.setattr(azure, "list_sql_dev_vms", lambda arm, sub: vms)
    monkeypatch.setattr(azure, "run_powershell", run)
    # earlier run: all three had low disk
    from qci_infra.store import reconcile
    reconcile(db, [Finding("sql-disk-low", "S", n, f"{n}: low") for n in ("good", "bad", "off")], set(), "T0")

    cli.sql_check(cfg, dry_run=True)

    keys = sorted(r["alert_key"] for r in open_alerts(db))
    assert keys == ["sql-backup-stale:S:good", "sql-collector:S:bad", "sql-disk-low:S:bad", "sql-disk-low:S:off"]
    rows = {r["vm_name"]: r for r in db.query("select * from sql_health")}
    assert rows["good"]["db_name"] == "QCIDB" and rows["bad"]["error"].startswith("Run Command timed out")
    assert rows["off"]["error"] == "not probed: VM PowerState/deallocated"
    assert "RESOLVED" in capsys.readouterr().out  # good's disk alert resolved in the dry-run email

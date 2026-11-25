import json
from datetime import datetime, timezone

import pytest

from qci_infra.cli import parse_cert_probe
from qci_infra.config import Certs
from qci_infra.rules import covers, served_findings, server_cert_findings

NOW = datetime(2026, 11, 23, 12, 0, tzinfo=timezone.utc)
TH = Certs(warn_days=21)
OLD, NEW = "A" * 40, "B" * 40


def win_probe(**kw) -> str:
    h = {"host": "APP1", "iis": "Running",
         "b": [{"s": "Default Web Site", "t": NEW, "h": ["app.example.com", "www.example.com:8443"]}],
         "c": [{"t": NEW, "st": "WebHosting", "n": ["app.example.com", "www.example.com"], "i": "R11",
                "e": "2027-02-01T00:00:00Z"}],
         "tk": [{"n": "win-acme renew (acme-v02.api.letsencrypt.org)", "s": "Ready", "lr": "2026-11-23T09:00:00Z",
                 "r": 0, "nr": "2026-11-24T09:00:00Z", "x": "wacs.exe"}], "sv": [], "gaps": []}
    h.update(kw)
    return "noise\n" + json.dumps(h)


LINUX = "\n".join([
    "host\tweb1",
    "c\t/etc/letsencrypt/live/web.example.com/cert.pem\taa11\t2026-12-01T00:00:00Z\tweb.example.com,*.example.org\tE7\tle",
    "c\t/etc/letsencrypt/live/web.example.com/fullchain.pem\taa11\t2026-12-01T00:00:00Z\tweb.example.com\tE7\tnginx",
    "tm\tcertbot.timer\tloaded\tenabled\tactive\t2026-11-23T06:00:00Z\t2026-11-23T18:00:00Z",
    "sr\tcertbot.service\tsuccess\t0\t2026-11-23T06:00:05Z",
    "ws\tnginx\tactive",
    "l4\tnginx",
])


def test_parse_windows_probe_expands_grouped_bindings():
    p = parse_cert_probe("Windows", win_probe(), NOW)
    assert p["web"] == ["IIS Running"] and p["in_use"] == [NEW, NEW]
    assert p["bindings"][1] == {"site": "Default Web Site", "host": "www.example.com", "port": 8443, "thumb": NEW}
    assert p["renewal"][0]["problem"] is None and p["gaps"] == []


@pytest.mark.parametrize("task, problem", [
    ({"s": "Disabled", "r": 0, "lr": "2026-11-23T09:00:00Z"}, "task is disabled"),
    ({"s": "Ready", "r": 4294967295, "lr": "2026-11-23T09:00:00Z"}, "last run 2026-11-23 failed (result 0xFFFFFFFF)"),
    ({"s": "Ready", "r": 0, "lr": "2026-11-01T09:00:00Z"}, "has not run since 2026-11-01"),
    ({"s": "Ready", "r": 267011, "lr": None}, None),  # never ran yet
])
def test_parse_windows_task_problems(task, problem):
    p = parse_cert_probe("Windows", win_probe(tk=[{"n": "win-acme renew", **task}]), NOW)
    assert p["renewal"][0]["problem"] == problem


def test_parse_windows_reports_bound_cert_missing_from_store():
    p = parse_cert_probe("Windows", win_probe(c=[]), NOW)
    assert p["gaps"] == [f"bound cert {NEW[:8]} not found in My/WebHosting"]


def test_parse_windows_truncated_output_raises():
    with pytest.raises(ValueError):
        parse_cert_probe("Windows", win_probe()[:300], NOW)


def test_parse_linux_probe():
    p = parse_cert_probe("Linux", LINUX, NOW)
    assert p["host"] == "web1" and p["in_use"] == ["AA11"] and p["web"] == ["nginx active", ":443 nginx"]
    assert p["certs"][0]["names"] == ["web.example.com", "*.example.org"] and p["certs"][0]["source"] == "le,nginx"
    assert p["certs"][0]["where"].endswith("cert.pem, /etc/letsencrypt/live/web.example.com/fullchain.pem")
    assert p["renewal"] == [{"kind": "timer", "name": "certbot.timer", "state": "enabled/active",
                             "last_run": "2026-11-23T06:00:00Z", "next_run": "2026-11-23T18:00:00Z", "problem": None}]
    with pytest.raises(ValueError):
        parse_cert_probe("Linux", "bash: openssl: command not found", NOW)


def test_parse_linux_failed_renewal_and_disabled_timer():
    failed = LINUX.replace("sr\tcertbot.service\tsuccess\t0", "sr\tcertbot.service\texit-code\t1")
    assert "failed (result=exit-code, exit=1)" in parse_cert_probe("Linux", failed, NOW)["renewal"][0]["problem"]
    off = LINUX.replace("enabled\tactive", "disabled\tinactive")
    assert parse_cert_probe("Linux", off, NOW)["renewal"][0]["problem"] == "timer is disabled/inactive"


def test_covers():
    assert covers(["*.example.com"], "a.example.com") and covers(["A.Example.com"], "a.example.com")
    assert not covers(["*.example.com"], "example.com") and not covers(["*.example.com"], "a.b.example.com")


def kinds(fs):
    return sorted((f.kind, f.name) for f in fs)


def test_server_findings_healthy():
    assert server_cert_findings("S", "APP1", parse_cert_probe("Windows", win_probe(), NOW), NOW, TH) == []


def test_server_findings_expiring_and_expired():
    soon = [{"t": NEW, "st": "WebHosting", "n": ["app.example.com"], "i": "R11", "e": "2026-12-01T00:00:00Z"}]
    p = parse_cert_probe("Windows", win_probe(c=soon), NOW)
    fs = server_cert_findings("S", "APP1", p, NOW, TH)
    assert kinds(fs) == [("cert-expiring", "APP1/app.example.com")] and "8 days left" in fs[0].summary
    gone = [{**soon[0], "e": "2026-11-20T00:00:00Z"}]
    fs = server_cert_findings("S", "APP1", parse_cert_probe("Windows", win_probe(c=gone), NOW), NOW, TH)
    assert kinds(fs) == [("cert-expired", "APP1/app.example.com")]


def test_server_findings_binding_left_on_old_cert():
    certs = [{"t": OLD, "st": "WebHosting", "n": ["app.example.com"], "i": "R11", "e": "2026-12-20T00:00:00Z"},
             {"t": NEW, "st": "WebHosting", "n": ["app.example.com"], "i": "R11", "e": "2027-02-20T00:00:00Z"}]
    b = [{"s": "Default Web Site", "t": OLD, "h": ["app.example.com"]}]
    fs = server_cert_findings("S", "APP1", parse_cert_probe("Windows", win_probe(b=b, c=certs), NOW), NOW, TH)
    assert kinds(fs) == [("cert-mismatch", f"APP1/bound {OLD[:8]}")] and NEW[:8] in fs[0].summary
    # two renewals a day apart for the same name are normal: no mismatch
    certs[1]["e"] = "2026-12-21T00:00:00Z"
    assert server_cert_findings("S", "APP1", parse_cert_probe("Windows", win_probe(b=b, c=certs), NOW), NOW, TH) == []


def test_server_findings_binding_without_cert():
    p = parse_cert_probe("Windows", win_probe(b=[{"s": "Site", "t": "", "h": ["x.example.com"]}]), NOW)
    assert kinds(server_cert_findings("S", "APP1", p, NOW, TH)) == [("cert-mismatch", "APP1/x.example.com:443")]


def test_server_findings_renewal():
    bad = [{"n": "win-acme renew", "s": "Ready", "r": 4294967295, "lr": "2026-11-23T09:00:00Z"}]
    fs = server_cert_findings("S", "APP1", parse_cert_probe("Windows", win_probe(tk=bad), NOW), NOW, TH)
    assert kinds(fs) == [("cert-renewal", "APP1/renewal")] and "0xFFFFFFFF" in fs[0].summary
    fs = server_cert_findings("S", "APP1", parse_cert_probe("Windows", win_probe(tk=[]), NOW), NOW, TH)
    assert kinds(fs) == [("cert-renewal", "APP1/renewal")] and "no renewal task" in fs[0].summary
    # a manually installed (non-ACME) cert needs no renewal task
    manual = [{"t": NEW, "st": "My", "n": ["app.example.com"], "i": "Sectigo RSA DV", "e": "2027-06-01T00:00:00Z"}]
    assert server_cert_findings("S", "APP1", parse_cert_probe("Windows", win_probe(tk=[], c=manual), NOW),
                                NOW, TH) == []


def served(thumb=NEW, end="2027-02-01T00:00:00Z", error=None):
    return {"thumb": thumb, "not_after": end, "names": ["app.example.com"], "issuer": "R11", "error": error}


DISK = [{"thumb": NEW, "names": ["app.example.com"], "not_after": "2027-02-01T00:00:00Z"}]


def test_served_findings():
    assert served_findings("S", "app.example.com", served(), DISK, NOW, TH) == []
    # renewed on disk, but the old cert is still served
    fs = served_findings("S", "app.example.com", served(OLD, "2026-12-10T00:00:00Z"), DISK, NOW, TH)
    assert kinds(fs) == [("cert-expiring", "https://app.example.com"), ("cert-mismatch", "https://app.example.com")]
    fs = served_findings("S", "app.example.com", served(error="Hostname mismatch"), DISK, NOW, TH)
    assert kinds(fs) == [("cert-mismatch", "https://app.example.com")] and "Hostname mismatch" in fs[0].summary
    fs = served_findings("S", "app.example.com", served(OLD, "2026-11-01T00:00:00Z", "certificate has expired"),
                         [], NOW, TH)
    assert kinds(fs) == [("cert-expired", "https://app.example.com")]
    # a server's own cert: expiry is reported by the server check only
    soon = [{**DISK[0], "not_after": "2026-12-01T00:00:00Z"}]
    assert served_findings("S", "app.example.com", served(end="2026-12-01T00:00:00Z"), soon, NOW, TH) == []


def test_cert_check_scope(monkeypatch, capsys):
    from qci_infra import azure, cli, tls
    from qci_infra.config import Config, Email, Subscription
    from qci_infra.rules import Finding
    from qci_infra.store import connect_sqlite, open_alerts, reconcile

    db = connect_sqlite(":memory:")
    cfg = Config(subscriptions=[Subscription("S", "QCI")], email=Email("to@x", "from@x", "k"),
                 certs=Certs(servers=("good", "bad", "busy", "off", "web")))
    vm = {"resourceGroup": "RG", "power": "PowerState/running", "os": "Windows"}
    vms = [{**vm, "id": f"/vm/{n}", "name": n} for n in ("good", "bad", "busy", "other")] + \
          [{**vm, "id": "/vm/off", "name": "off", "power": "PowerState/deallocated"},
           {**vm, "id": "/vm/web", "name": "web", "os": "Linux"}]

    def run_ps(sub, rg, name, script, timeout):
        if name == "bad":
            raise azure.AzureError("Run Command timed out after 15 min")
        if name == "busy":
            raise azure.RunCommandBusy("Conflict: Run command extension execution is in progress")
        return win_probe(), ""

    monkeypatch.setattr(cli, "open_db", lambda cfg, dry_run: db)
    monkeypatch.setattr(cli, "BUSY_RETRY_SECONDS", 0)
    monkeypatch.setattr(azure, "Arm", lambda: None)
    monkeypatch.setattr(azure, "list_vms", lambda arm, sub: vms)
    monkeypatch.setattr(azure, "vm_public_ips", lambda arm, sub: {"/vm/good": {"20.1.2.3"}})
    monkeypatch.setattr(azure, "run_powershell", run_ps)
    monkeypatch.setattr(azure, "run_shell", lambda *a: (LINUX, ""))
    monkeypatch.setattr(tls, "resolve", lambda h: ["10.0.0.4"] if h == "web.example.com" else ["20.1.2.3"])
    monkeypatch.setattr(tls, "served_cert", lambda h: served())
    earlier = [Finding("cert-expiring", "S", f"{n}/app.example.com", "x") for n in ("good", "bad", "busy", "off")]
    earlier += [Finding("cert-mismatch", "S", "https://app.example.com", "x"),
                Finding("cert-mismatch", "S", "https://gone.example.com", "x")]
    reconcile(db, earlier, set(), "T0")

    cli.cert_check(cfg, dry_run=True)

    keys = sorted(r["alert_key"] for r in open_alerts(db))
    assert keys == ["cert-collector:S:bad/probe", "cert-collector:S:busy/probe",
                    "cert-expiring:S:bad/app.example.com", "cert-expiring:S:busy/app.example.com",
                    "cert-expiring:S:off/app.example.com", "cert-expiring:S:web/web.example.com",
                    "cert-mismatch:S:https://gone.example.com"]  # held: a probe failed, so it might still exist
    rows = {r["id"]: r for r in db.query("select * from certs")}
    assert rows[f"good|{NEW}"]["status"] == "ok" and rows[f"good|{NEW}"]["renewal"].startswith("task win-acme")
    assert rows["https://app.example.com"]["status"] == "ok" and "served on 443 by good" in rows["https://app.example.com"]["source"]
    assert rows["https://web.example.com"]["status"] == "skipped" and "internal" in rows["https://web.example.com"]["detail"]
    assert rows["https://*.example.org"]["detail"] == "not probed over TLS: wildcard name"
    assert rows["busy|none"]["detail"].startswith("another Run Command is executing")
    assert rows["off|none"]["detail"] == "not probed: VM PowerState/deallocated"
    assert "RESOLVED" in capsys.readouterr().out

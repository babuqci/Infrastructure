import base64
import json

import pytest
from fastapi.testclient import TestClient
from itsdangerous import TimestampSigner

from qci_infra.config import Config, Email, Subscription
from qci_infra.rules import Finding
from qci_infra.store import connect_sqlite, reconcile, save_cost, save_vms
from qci_infra.web import WebConfig, create_app, is_allowed

DOMAIN = "quickcustomintelligence.com"
SECRET = "test-session-secret"
CFG = Config(subscriptions=[Subscription("sub-1", "QCI")], email=Email("to@x", "from@x", "/dev/null"))
WCFG = WebConfig(base_url="http://testserver", allowed_domain=DOMAIN, google_client_id="cid",
                 google_client_secret_file="/dev/null", session_secret_file="/dev/null")


@pytest.mark.parametrize("info, ok", [
    ({"email": "a@" + DOMAIN, "email_verified": True, "hd": DOMAIN}, True),
    ({"email": "a@" + DOMAIN, "email_verified": False, "hd": DOMAIN}, False),  # unverified
    ({"email": "a@gmail.com", "email_verified": True}, False),  # consumer account
    ({"email": "a@evil.com", "email_verified": True, "hd": DOMAIN}, False),  # hd/email mismatch
    ({"email": "a@" + DOMAIN, "email_verified": True}, False),  # no hd: not a Workspace account
    ({"email": "a@x." + DOMAIN, "email_verified": True, "hd": "x." + DOMAIN}, False),  # subdomain
])
def test_is_allowed(info, ok):
    assert is_allowed(info, DOMAIN) is ok


@pytest.fixture
def client(tmp_path):
    path = str(tmp_path / "state.db")
    db = connect_sqlite(path)
    save_vms(db, "sub-1", [{"vm_id": "id-a", "name": "vm-a", "rg": "rg", "location": "westus2", "size": "B2s",
                            "os": "Windows", "power": "PowerState/running", "health": "Available", "cpu": 5.0,
                            "mem": 50.0, "is_sql": 1}], "2026-11-22T10:00:00+00:00")
    reconcile(db, [Finding("vm-down", "sub-1", "vm-b", "vm-b is <deallocated>")], {("vm-down", "sub-1")},
              "2026-11-22T10:00:00+00:00")
    save_cost(db, "sub-1", {"2026-11-21": 123.45})
    db.commit()
    app = create_app(CFG, WCFG, db_factory=lambda: connect_sqlite(path), client_secret="x", session_secret=SECRET)
    return TestClient(app, follow_redirects=False)


def sign_in(client, email="a@" + DOMAIN):
    data = base64.b64encode(json.dumps({"user": {"email": email, "name": "A"}}).encode())
    client.cookies.set("qci_infra", TimestampSigner(SECRET).sign(data).decode())


@pytest.mark.parametrize("path", ["/", "/vms", "/alerts", "/cost", "/sql", "/certs"])
def test_pages_require_login(client, path):
    r = client.get(path)
    assert r.status_code == 303 and r.headers["location"] == "/login"


@pytest.mark.parametrize("path, text", [("/", "1 / 1"), ("/vms", "vm-a"), ("/alerts", "vm-b"),
                                        ("/cost", "123.45"), ("/sql", "No SQL Server health data"),
                                        ("/certs", "No certificate data")])
def test_pages_render_when_signed_in(client, path, text):
    sign_in(client)
    r = client.get(path)
    assert r.status_code == 200 and text in r.text
    assert r.headers["x-frame-options"] == "DENY"


def test_summary_is_html_escaped(client):
    sign_in(client)
    assert "&lt;deallocated&gt;" in client.get("/alerts").text


def test_forged_cookie_rejected(client):
    data = base64.b64encode(json.dumps({"user": {"email": "x@" + DOMAIN}}).encode())
    client.cookies.set("qci_infra", TimestampSigner("wrong").sign(data).decode())
    assert client.get("/").status_code == 303


def test_healthz_is_public(client):
    assert client.get("/healthz").text == "ok"


def test_base_for_picks_only_configured_urls():
    from qci_infra.web import base_for
    w = WebConfig(**{**WCFG.__dict__, "base_url": "https://mac.example.ts.net",
                     "extra_base_urls": ("http://localhost:8090",)})
    assert base_for(w, "localhost:8090") == "http://localhost:8090"
    assert base_for(w, "mac.example.ts.net") == "https://mac.example.ts.net"
    assert base_for(w, "evil.com") == "https://mac.example.ts.net"  # spoofed Host never becomes a redirect
    assert base_for(w, None) == "https://mac.example.ts.net"

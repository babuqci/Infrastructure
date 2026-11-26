"""Read-only web UI for QCI Infra, behind Google sign-in limited to one Workspace domain.

Runs on 127.0.0.1 on the Mac Studio; Cloudflare Tunnel publishes it over HTTPS.
"""

import os
import tomllib
from collections import defaultdict
from dataclasses import dataclass
from datetime import date, timedelta
from pathlib import Path
from urllib.parse import urlsplit

from authlib.integrations.starlette_client import OAuth, OAuthError
from fastapi import FastAPI, Request
from fastapi.responses import PlainTextResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from .config import DEFAULT_PATH, Config, load_config
from .store import Db, connect_mssql, connect_sqlite

GOOGLE_METADATA = "https://accounts.google.com/.well-known/openid-configuration"
TEMPLATES = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))


@dataclass(frozen=True)
class WebConfig:
    base_url: str  # e.g. https://infra.quickcustomintelligence.com
    allowed_domain: str  # Google Workspace domain allowed to sign in
    google_client_id: str
    google_client_secret_file: str
    session_secret_file: str
    host: str = "127.0.0.1"
    port: int = 8090
    extra_base_urls: tuple[str, ...] = ()  # e.g. http://localhost:8090 for an SSH tunnel

    @property
    def base_urls(self) -> tuple[str, ...]:
        return (self.base_url, *self.extra_base_urls)


def load_web_config(path: str | None = None) -> WebConfig:
    p = Path(os.path.expanduser(path or os.environ.get("QCI_INFRA_CONFIG", DEFAULT_PATH)))
    raw = tomllib.loads(p.read_text())["web"]
    return WebConfig(**{**raw, "extra_base_urls": tuple(raw.get("extra_base_urls", ()))})


def base_for(wcfg: WebConfig, host: str | None) -> str:
    """The configured URL the browser used (by Host header); only configured URLs are ever returned."""
    return next((u for u in wcfg.base_urls if urlsplit(u).netloc == host), wcfg.base_url).rstrip("/")


def read_secret(path: str) -> str:
    return Path(os.path.expanduser(path)).read_text().strip()


def is_allowed(userinfo: dict, domain: str) -> bool:
    """Only verified accounts of the Workspace domain; the `hd` claim proves Workspace membership."""
    email = (userinfo.get("email") or "").lower()
    return userinfo.get("email_verified") is True and userinfo.get("hd") == domain and email.endswith("@" + domain)


class NeedLogin(Exception):
    pass


def current_user(request: Request) -> dict:
    user = request.session.get("user")
    if not user:
        raise NeedLogin
    return user


def default_db(cfg: Config) -> Db:
    d = cfg.database
    return connect_mssql(d.server, d.database, d.user, d.password_file, d.freetds_conf) if d else connect_sqlite(cfg.db)


def create_app(cfg: Config, wcfg: WebConfig, db_factory=None, client_secret: str | None = None,
               session_secret: str | None = None) -> FastAPI:
    db_factory = db_factory or (lambda: default_db(cfg))
    sub_names = {s.id: s.name for s in cfg.subscriptions}
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    app.add_middleware(SessionMiddleware, secret_key=session_secret or read_secret(wcfg.session_secret_file),
                       session_cookie="qci_infra", max_age=12 * 3600, same_site="lax",
                       https_only=all(u.startswith("https://") for u in wcfg.base_urls))

    oauth = OAuth()
    oauth.register("google", client_id=wcfg.google_client_id,
                   client_secret=client_secret or read_secret(wcfg.google_client_secret_file),
                   server_metadata_url=GOOGLE_METADATA, client_kwargs={"scope": "openid email profile"})

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        resp = await call_next(request)
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Referrer-Policy"] = "same-origin"
        resp.headers["Content-Security-Policy"] = ("default-src 'self'; style-src 'self' 'unsafe-inline'; "
                                                   "img-src 'self' data:; form-action 'self' https://accounts.google.com")
        return resp

    @app.exception_handler(NeedLogin)
    async def need_login(request: Request, exc: NeedLogin):
        return RedirectResponse("/login", status_code=303)

    def page(request: Request, name: str, **ctx):
        return TEMPLATES.TemplateResponse(request, name, {"user": request.session.get("user"),
                                                          "sub_names": sub_names, **ctx})

    def with_db(fn):
        db = db_factory()
        try:
            return fn(db)
        finally:
            db.conn.close()

    # --- auth ---------------------------------------------------------------
    @app.get("/healthz")
    async def healthz():
        return PlainTextResponse("ok")

    @app.get("/login")
    async def login(request: Request):
        return await oauth.google.authorize_redirect(request, base_for(wcfg, request.headers.get("host")) + "/auth",
                                                     hd=wcfg.allowed_domain, prompt="select_account")

    @app.get("/auth")
    async def auth(request: Request):
        try:
            token = await oauth.google.authorize_access_token(request)
        except OAuthError as e:
            return page(request, "denied.html", reason=f"Google sign-in failed ({e.error}).")
        info = token.get("userinfo") or {}
        if not is_allowed(info, wcfg.allowed_domain):
            return page(request, "denied.html",
                        reason=f"{info.get('email', 'This account')} is not a {wcfg.allowed_domain} account.")
        request.session.clear()
        request.session["user"] = {"email": info["email"], "name": info.get("name", "")}
        return RedirectResponse("/", status_code=303)

    @app.get("/logout")
    async def logout(request: Request):
        request.session.clear()
        return page(request, "denied.html", reason="You are signed out.", signed_out=True)

    # --- pages (all read-only) ------------------------------------------------
    @app.get("/")
    def overview(request: Request):
        current_user(request)

        def load(db):
            vms = db.query("select power from vms")
            month = date.today().replace(day=1).isoformat()
            mtd = defaultdict(float)
            for r in db.query("select sub, cost from cost_daily where day >= ?", (month,)):
                mtd[r["sub"]] += r["cost"] or 0
            return {"total": len(vms), "running": sum(v["power"] == "PowerState/running" for v in vms),
                    "alerts": db.query("select * from alerts where status = 'open' order by opened_at desc"),
                    "mtd": dict(mtd), "runs": db.query("select * from runs order by job")}
        return page(request, "overview.html", **with_db(load))

    @app.get("/vms")
    def vms(request: Request):
        current_user(request)
        rows = with_db(lambda db: db.query("select * from vms order by sub, name"))
        return page(request, "vms.html", vms=rows)

    @app.get("/alerts")
    def alerts(request: Request):
        current_user(request)

        def load(db):
            resolved = db.query("select * from alerts where status = 'resolved' order by resolved_at desc")
            return {"open": db.query("select * from alerts where status = 'open' order by opened_at desc"),
                    "resolved": resolved[:100]}
        return page(request, "alerts.html", **with_db(load))

    @app.get("/cost")
    def cost(request: Request):
        current_user(request)
        since = (date.today() - timedelta(days=30)).isoformat()
        rows = with_db(lambda db: db.query("select sub, day, cost from cost_daily where day >= ? order by day",
                                           (since,)))
        by_day, by_sub = defaultdict(float), defaultdict(float)
        for r in rows:
            by_day[r["day"]] += r["cost"] or 0
            by_sub[r["sub"]] += r["cost"] or 0
        days = sorted(by_day.items())
        return page(request, "cost.html", days=days, peak=max((c for _, c in days), default=0) or 1,
                    by_sub=sorted(by_sub.items(), key=lambda x: -x[1]), total=sum(by_sub.values()))

    @app.get("/sql")
    def sql(request: Request):
        current_user(request)

        def load(db):
            try:
                rows = db.query("select * from sql_health")
            except Exception:  # table appears once SQL monitoring has run
                return []
            return sorted(rows, key=lambda r: [str(v) for v in r.values()])
        return page(request, "sql.html", servers=with_db(load))

    @app.get("/certs")
    def certs(request: Request):
        current_user(request)

        def load(db):
            try:
                rows = db.query("select * from certs")
            except Exception:  # table appears once certificate monitoring has run
                return []
            return sorted(rows, key=lambda r: (r["days_left"] is None, r["days_left"] or 0, r["server"] or ""))
        return page(request, "certs.html", certs=with_db(load))

    return app


def main():
    import uvicorn

    cfg, wcfg = load_config(), load_web_config()
    uvicorn.run(create_app(cfg, wcfg), host=wcfg.host, port=wcfg.port, log_level="info")

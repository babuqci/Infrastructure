"""Load the service config (TOML)."""

import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_PATH = "~/.config/qci-infra/config.toml"


@dataclass(frozen=True)
class Subscription:
    id: str
    name: str
    cost: bool = True  # pull cost data for this subscription


@dataclass(frozen=True)
class Thresholds:
    cpu_percent: float = 90
    mem_available_percent: float = 10
    mem_available_percent_sql: float = 2  # SQL Server holds most RAM by design
    window_points: int = 3  # 5-minute points: 3 = 15 minutes sustained
    cost_spike_ratio: float = 1.5
    cost_spike_min_usd: float = 100


@dataclass(frozen=True)
class Sql:
    """`sql-check` thresholds (SQL Server Developer VMs, polled hourly)."""
    backup_max_age_hours: float = 26  # newest full backup of qcidb older than this alerts
    disk_free_percent: float = 10  # a fixed drive alerts below this % free...
    disk_free_gb: float = 20  # ...or below this many GB free
    timeout_minutes: float = 20  # per-VM Run Command limit


@dataclass(frozen=True)
class Certs:
    """`cert-check` settings (TLS certificates on the app servers, checked daily)."""
    warn_days: float = 21  # alert when fewer days are left (Let's Encrypt renews at 30)
    servers: tuple[str, ...] = ()  # VM names to probe (IIS HTTPS bindings or Let's Encrypt certs)
    skip_hosts: tuple[str, ...] = ()  # hostnames never probed over TLS from the Mac Studio
    timeout_minutes: float = 15  # per-VM Run Command limit


@dataclass(frozen=True)
class Email:
    to: str
    sender: str
    api_key_file: str


@dataclass(frozen=True)
class Database:
    server: str
    database: str
    user: str
    password_file: str


@dataclass(frozen=True)
class Config:
    subscriptions: list[Subscription]
    email: Email
    thresholds: Thresholds = field(default_factory=Thresholds)
    sql: Sql = field(default_factory=Sql)
    certs: Certs = field(default_factory=Certs)
    database: Database | None = None  # SQL Server; `db` (SQLite) is the fallback
    db: str = "~/.local/share/qci-infra/state.db"
    heartbeat_url: str = ""
    ignore_tag: str = "qci-monitor"  # VMs tagged qci-monitor=off are skipped


def load_config(path: str | None = None) -> Config:
    p = Path(os.path.expanduser(path or os.environ.get("QCI_INFRA_CONFIG", DEFAULT_PATH)))
    raw = tomllib.loads(p.read_text())
    svc = raw.get("service", {})
    return Config(
        subscriptions=[Subscription(**s) for s in raw["subscriptions"]],
        email=Email(**raw["email"]),
        thresholds=Thresholds(**raw.get("thresholds", {})),
        sql=Sql(**raw.get("sql", {})),
        certs=Certs(**{k: tuple(v) if isinstance(v, list) else v for k, v in raw.get("certs", {}).items()}),
        database=Database(**raw["database"]) if "database" in raw else None,
        **{k: svc[k] for k in ("db", "heartbeat_url", "ignore_tag") if k in svc},
    )

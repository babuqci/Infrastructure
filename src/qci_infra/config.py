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
class Email:
    to: str
    sender: str
    api_key_file: str


@dataclass(frozen=True)
class Config:
    subscriptions: list[Subscription]
    email: Email
    thresholds: Thresholds = field(default_factory=Thresholds)
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
        **{k: svc[k] for k in ("db", "heartbeat_url", "ignore_tag") if k in svc},
    )

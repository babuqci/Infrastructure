"""SQLite state: open/resolved alerts and daily cost history."""

import os
import sqlite3
from pathlib import Path

from .rules import Finding

SCHEMA = """
create table if not exists alerts (
  key text primary key, kind text, sub text, summary text,
  status text, opened_at text, resolved_at text, last_seen text
);
create table if not exists cost_daily (
  sub text, day text, cost real, primary key (sub, day)
);
"""


def connect(path: str) -> sqlite3.Connection:
    if path != ":memory:":
        path = os.path.expanduser(path)
        Path(path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    return conn


def reconcile(conn, findings: list[Finding], scope: set[tuple[str, str]], now: str):
    """Open alerts for new findings; resolve open alerts no longer found.

    Only alerts whose (kind, sub) is in `scope` can be resolved, so a collector
    that failed for a subscription never auto-resolves that subscription's alerts.
    Returns (opened findings, resolved alert rows). Does not commit: the caller
    commits only after the email went out, so a failed send is retried next run.
    """
    by_key = {f.key: f for f in findings}
    open_rows = {r["key"]: r for r in conn.execute("select * from alerts where status = 'open'")}
    opened, resolved = [], []
    for key, f in by_key.items():
        if key in open_rows:
            conn.execute("update alerts set summary = ?, last_seen = ? where key = ?", (f.summary, now, key))
        else:
            conn.execute(
                "insert or replace into alerts values (?, ?, ?, ?, 'open', ?, null, ?)",
                (key, f.kind, f.sub, f.summary, now, now),
            )
            opened.append(f)
    for key, row in open_rows.items():
        if key not in by_key and (row["kind"], row["sub"]) in scope:
            conn.execute("update alerts set status = 'resolved', resolved_at = ? where key = ?", (now, key))
            resolved.append(row)
    return opened, resolved


def open_alerts(conn) -> list[sqlite3.Row]:
    return list(conn.execute("select * from alerts where status = 'open' order by opened_at"))


def save_cost(conn, sub: str, daily: dict[str, float]):
    conn.executemany("insert or replace into cost_daily values (?, ?, ?)", [(sub, d, c) for d, c in daily.items()])
    conn.commit()

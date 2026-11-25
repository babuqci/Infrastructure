"""State store: alerts, cost history, VM snapshot, job runs.

Backed by SQL Server (QCIInfrastructure on apisql) in production, SQLite for tests
and as a fallback when SQL Server is unreachable. SQL is written once with `?`
placeholders and portable statements (update-then-insert instead of MERGE).
"""

import os
import sqlite3
from pathlib import Path

from .rules import Finding

SQLITE_SCHEMA = """
create table if not exists alerts (
  alert_key text primary key, kind text, sub text, summary text,
  status text, opened_at text, resolved_at text, last_seen text);
create table if not exists cost_daily (sub text, day text, cost real, primary key (sub, day));
create table if not exists vms (
  vm_id text primary key, sub text, name text, rg text, location text, size text, os text,
  power text, health text, cpu real, mem real, is_sql integer, updated_at text);
create table if not exists runs (job text primary key, started_at text, finished_at text, ok integer, message text);
create table if not exists sql_health (
  vm_id text primary key, sub text, vm_name text, edition text, version text, db_name text,
  last_full_backup text, last_full_backup_path text, drives text, services text, permission_gaps text,
  ok integer, error text, updated_at text);
create table if not exists certs (
  id text primary key, sub text, server text, names text, source text, issuer text, not_after text,
  days_left real, thumbprint text, renewal text, status text, detail text, updated_at text);
"""

MSSQL_SCHEMA = [
    """if object_id('dbo.alerts') is null create table dbo.alerts (
      alert_key nvarchar(400) not null primary key, kind nvarchar(50), sub nvarchar(64), summary nvarchar(2000),
      status nvarchar(20), opened_at nvarchar(32), resolved_at nvarchar(32), last_seen nvarchar(32))""",
    """if object_id('dbo.cost_daily') is null create table dbo.cost_daily (
      sub nvarchar(64) not null, day char(10) not null, cost float, primary key (sub, day))""",
    """if object_id('dbo.vms') is null create table dbo.vms (
      vm_id nvarchar(400) not null primary key, sub nvarchar(64), name nvarchar(100), rg nvarchar(100),
      location nvarchar(50), size nvarchar(50), os nvarchar(20), power nvarchar(50), health nvarchar(50),
      cpu float, mem float, is_sql bit, updated_at nvarchar(32))""",
    """if object_id('dbo.runs') is null create table dbo.runs (
      job nvarchar(50) not null primary key, started_at nvarchar(32), finished_at nvarchar(32), ok bit,
      message nvarchar(2000))""",
    """if object_id('dbo.sql_health') is null create table dbo.sql_health (
      vm_id nvarchar(400) not null primary key, sub nvarchar(64), vm_name nvarchar(100), edition nvarchar(128),
      version nvarchar(64), db_name nvarchar(128), last_full_backup nvarchar(32), last_full_backup_path nvarchar(400),
      drives nvarchar(2000), services nvarchar(400), permission_gaps nvarchar(2000), ok bit, error nvarchar(2000),
      updated_at nvarchar(32))""",
    """if object_id('dbo.certs') is null create table dbo.certs (
      id nvarchar(400) not null primary key, sub nvarchar(64), server nvarchar(100), names nvarchar(1000),
      source nvarchar(400), issuer nvarchar(200), not_after nvarchar(32), days_left float, thumbprint nvarchar(64),
      renewal nvarchar(1000), status nvarchar(20), detail nvarchar(2000), updated_at nvarchar(32))""",
]


class Db:
    """Thin wrapper so the same `?`-style SQL runs on SQLite and SQL Server (pymssql)."""

    def __init__(self, conn, mssql: bool):
        self.conn, self.mssql = conn, mssql

    def execute(self, sql: str, params=()):
        cur = self.conn.cursor()
        cur.execute(sql.replace("?", "%s") if self.mssql else sql, tuple(params))
        return cur

    def query(self, sql: str, params=()) -> list[dict]:
        if self.mssql:
            cur = self.conn.cursor(as_dict=True)
            cur.execute(sql.replace("?", "%s"), tuple(params))
            return list(cur.fetchall())
        return [dict(r) for r in self.conn.execute(sql, tuple(params))]

    def commit(self):
        self.conn.commit()

    def rollback(self):
        self.conn.rollback()


def connect_sqlite(path: str) -> Db:
    if path != ":memory:":
        path = os.path.expanduser(path)
        Path(path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.executescript(SQLITE_SCHEMA)
    return Db(conn, mssql=False)


def connect_mssql(server: str, database: str, user: str, password_file: str) -> Db:
    import pymssql  # imported lazily so tests don't need it

    password = Path(os.path.expanduser(password_file)).read_text().strip()
    conn = pymssql.connect(server=server, user=user, password=password, database=database,
                           login_timeout=15, timeout=60, tds_version="7.4", encryption="require")
    db = Db(conn, mssql=True)
    for ddl in MSSQL_SCHEMA:
        db.execute(ddl)
    db.commit()
    return db


def _upsert(db: Db, table: str, keys: dict, values: dict):
    sets = ", ".join(f"{k} = ?" for k in values)
    where = " and ".join(f"{k} = ?" for k in keys)
    if db.execute(f"update {table} set {sets} where {where}", [*values.values(), *keys.values()]).rowcount == 0:
        cols = [*keys, *values]
        db.execute(f"insert into {table} ({', '.join(cols)}) values ({', '.join('?' * len(cols))})",
                   [*keys.values(), *values.values()])


def reconcile(db: Db, findings: list[Finding], scope: set[tuple[str, str]], now: str):
    """Open alerts for new findings; resolve open alerts no longer found.

    Only alerts whose (kind, sub) or (kind, sub, name) is in `scope` can be resolved,
    so a collector that failed for a subscription (or one VM) never auto-resolves its alerts.
    Returns (opened findings, resolved alert rows). Does not commit: the caller
    commits only after the email went out, so a failed send is retried next run.
    """
    by_key = {f.key: f for f in findings}
    open_rows = {r["alert_key"]: r for r in db.query("select * from alerts where status = 'open'")}
    opened, resolved = [], []
    for key, f in by_key.items():
        if key in open_rows:
            db.execute("update alerts set summary = ?, last_seen = ? where alert_key = ?", (f.summary, now, key))
        else:
            _upsert(db, "alerts", {"alert_key": key}, {"kind": f.kind, "sub": f.sub, "summary": f.summary,
                                                        "status": "open", "opened_at": now, "resolved_at": None,
                                                        "last_seen": now})
            opened.append(f)
    for key, row in open_rows.items():
        if key not in by_key and ((row["kind"], row["sub"]) in scope or tuple(key.split(":", 2)) in scope):
            db.execute("update alerts set status = 'resolved', resolved_at = ? where alert_key = ?", (now, key))
            resolved.append(row)
    return opened, resolved


def open_alerts(db: Db) -> list[dict]:
    return db.query("select * from alerts where status = 'open' order by opened_at")


def save_cost(db: Db, sub: str, daily: dict[str, float]):
    for day, cost in daily.items():
        _upsert(db, "cost_daily", {"sub": sub, "day": day}, {"cost": cost})
    db.commit()


def save_vms(db: Db, sub: str, rows: list[dict], now: str):
    """Replace the VM snapshot for one subscription. rows: dicts with the vms columns."""
    db.execute("delete from vms where sub = ?", (sub,))
    for r in rows:
        _upsert(db, "vms", {"vm_id": r["vm_id"]}, {**{k: v for k, v in r.items() if k != "vm_id"},
                                                    "sub": sub, "updated_at": now})


def save_sql_health(db: Db, sub: str, rows: list[dict], now: str):
    """Replace the SQL health snapshot for one subscription. rows: dicts with the sql_health columns."""
    db.execute("delete from sql_health where sub = ?", (sub,))
    for r in rows:
        _upsert(db, "sql_health", {"vm_id": r["vm_id"]}, {**{k: v for k, v in r.items() if k != "vm_id"},
                                                          "sub": sub, "updated_at": now})


def save_certs(db: Db, rows: list[dict], now: str):
    """Replace the certificate snapshot. rows: dicts with the certs columns (id unique)."""
    db.execute("delete from certs")
    for r in rows:
        _upsert(db, "certs", {"id": r["id"]}, {**{k: v for k, v in r.items() if k != "id"}, "updated_at": now})


def record_run(db: Db, job: str, started_at: str, finished_at: str, ok: bool, message: str = ""):
    _upsert(db, "runs", {"job": job}, {"started_at": started_at, "finished_at": finished_at,
                                       "ok": 1 if ok else 0, "message": message[:2000]})

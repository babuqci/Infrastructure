"""Email via SendGrid, plus the alert and daily-digest message bodies."""

import os
from pathlib import Path

import httpx

from .config import Email
from .rules import Finding

SENDGRID_URL = "https://api.sendgrid.com/v3/mail/send"


def send(cfg: Email, subject: str, body: str, dry_run: bool = False):
    if dry_run:
        print(f"--- EMAIL (dry run) to {cfg.to}\nSubject: {subject}\n\n{body}\n---")
        return
    key = Path(os.path.expanduser(cfg.api_key_file)).read_text().strip()
    r = httpx.post(SENDGRID_URL, timeout=30, headers={"Authorization": f"Bearer {key}"}, json={
        "personalizations": [{"to": [{"email": cfg.to}]}],
        "from": {"email": cfg.sender, "name": "QCI Infra Monitor"},
        "subject": subject,
        "content": [{"type": "text/plain", "value": body}],
    })
    if r.status_code >= 300:
        raise RuntimeError(f"SendGrid {r.status_code}: {r.text[:300]}")


def alert_email(opened: list[Finding], resolved: list, sub_names: dict[str, str]) -> tuple[str, str]:
    parts = []
    if opened:
        parts.append(f"{len(opened)} new")
    if resolved:
        parts.append(f"{len(resolved)} resolved")
    subject = f"[QCI Alert] {', '.join(parts)}"
    if opened:
        subject += f": {opened[0].summary[:80]}"
    lines = []
    if opened:
        lines.append("NEW")
        lines += [f"  - [{f.kind}] {f.summary}  ({sub_names.get(f.sub, f.sub)})" for f in opened]
    if resolved:
        lines.append("\nRESOLVED")
        lines += [f"  - [{r['kind']}] {r['summary']}  (open since {r['opened_at'][:16]}Z)" for r in resolved]
    return subject, "\n".join(lines)


def digest_email(day: str, fleet: list[dict], open_rows: list, cost: list[dict]) -> tuple[str, str]:
    """fleet: [{sub_name, total, running}]; cost: [{sub_name, yesterday, mtd, projected, top}] or {sub_name, error}."""
    total = sum(f["total"] for f in fleet)
    running = sum(f["running"] for f in fleet)
    mtd = sum(c.get("mtd", 0) for c in cost)
    proj = sum(c.get("projected", 0) for c in cost)
    subject = f"[QCI Daily] {day}: {running}/{total} VMs running, {len(open_rows)} open alerts, ${mtd:,.0f} MTD"
    lines = ["FLEET"]
    lines += [f"  {f['sub_name']}: {f['running']}/{f['total']} running" for f in fleet]
    lines.append(f"\nOPEN ALERTS ({len(open_rows)})")
    lines += [f"  - [{r['kind']}] {r['summary']} (since {r['opened_at'][:16]}Z)" for r in open_rows] or ["  none"]
    lines.append(f"\nCOST (USD)  month to date ${mtd:,.0f}, projected month ${proj:,.0f}")
    for c in cost:
        if "error" in c:
            lines.append(f"  {c['sub_name']}: unavailable ({c['error'][:120]})")
            continue
        lines.append(f"  {c['sub_name']}: yesterday ${c['yesterday']:,.0f}, MTD ${c['mtd']:,.0f}, "
                     f"projected ${c['projected']:,.0f}")
        lines += [f"      {cost_:>9,.0f}  {name}" for name, cost_ in c["top"]]
    lines.append("\nCost data lags Azure by up to a day.")
    return subject, "\n".join(lines)

# QCI Infrastructure — Plan (Phase 1: Azure)

Status: draft, 2026-11-22. Nothing built yet.

## Goal

One service, running on the Mac Studio (`mac.attlocal.net`), that for every QCI cloud account:

1. **Monitors** servers (up/down, CPU, memory, disk, network, health events).
2. **Optimizes cost** (spend by tenant/subscription/resource, waste, rightsizing).
3. **Alerts** when something goes wrong (server down, resource pressure, cost spike).

Azure first; AWS and others later behind the same interfaces.

## Accounts

| Login | Tenant with subscriptions | Known subscriptions |
|---|---|---|
| barunachalam@qci3.com | `22f93914-2800-4e30-96df-a85b20c8cc9c` "QCI01" | not yet listed (MFA required) |
| barunachalam@quickcustomintelligence.com | `bbc0108d-0adf-47c1-b08e-45f9f1ee0660` "Default Directory" | "Pay-As-You-Go", "QCI Pay-As-You-Go" (from a 2022 CLI profile) |

The quickcustomintelligence.com home tenant (`f3525387…`) has no subscriptions. That login is also a guest in customer tenants (Live! Casino and Hotel, SkyCity, Galaxy Entertainment Group — guest disabled). **Those are out of scope** unless you say otherwise.

The service gets its **own read-only identity in each in-scope tenant** (service principal); it does not use your personal logins.

## Decisions (2026-11-22)

- **Scale:** about 30 servers, mostly Windows, some Ubuntu.
- **Alerts:** email to barunachalam@quickcustomintelligence.com, sent through SendGrid (API key in macOS Keychain on the Mac Studio).
- **Scope:** QCI01 and Default Directory tenants only. Customer tenants (Live! Casino, SkyCity, Galaxy) are out of scope.
- **Read-only.** The service never changes Azure. Resizing and all other changes are recommended, then done interactively with you.
- **Mac Studio:** always on, on a UPS. Service runs as `qciadmin@mac.attlocal.net`, with key-based SSH.

## Answer: should we open SSH on each server?

**No.** Don't open port 22 (or 3389/RDP) to the internet. Nothing in this plan needs inbound access to the servers:

- **Metrics without any agent** — Azure collects host-level metrics for every VM for free: CPU %, Available Memory Bytes, disk IOPS/throughput, network in/out, VM availability. We read them with the Azure Monitor API.
- **Inside-the-OS data** (disk free space, services, Windows event errors, pending updates) — **Azure Monitor Agent** pushes it out over HTTPS (outbound only). Works the same on Windows and Ubuntu.
- **Running a command on a server** — **Azure Run Command** goes through the VM agent already on every Azure VM. No open port, works on Windows (PowerShell) and Linux (bash), every call logged in the Azure Activity Log.
- **Your own interactive access** — Azure Bastion, or Just-In-Time access (port opens for your IP for N hours, then closes). If you want a mesh, Tailscale on the servers + Mac Studio, which also needs no open inbound port.

Windows servers mostly don't run sshd anyway. One early job of the service: **flag any NSG that already allows 22/3389 from `*`** — that's a common security finding.

## Architecture

```
          ┌───────────── Mac Studio (launchd service) ─────────────┐
          │                                                         │
Azure ◄───┤ collectors ─► SQLite (later Postgres) ─► rules ─► alerts├──► email / Teams / Slack / push
tenant A  │   inventory    metrics, cost, events     engine         │
tenant B  │   metrics                                               │
(AWS later)   cost         ─► web dashboard (local)                 │
          │   health/advisor                                        │
          └──────────────────────────┬──────────────────────────────┘
                                     └──► heartbeat to external dead-man's switch
```

Two layers so that one dead Mac doesn't mean silent outages:

1. **Azure-native alerts (critical, managed as code with Terraform).** VM availability, CPU/memory/disk sustained high, Resource Health "unavailable", budget thresholds, cost anomalies. These fire from Azure, even when the Mac Studio is offline. They cost about $0.10 per metric series per month.
2. **Mac Studio service (everything else).** Cross-tenant and later cross-cloud inventory, cost reports, waste detection, trends, a dashboard, a daily digest, and smarter rules. It sends a heartbeat to an external check (e.g. healthchecks.io) so you know if *it* dies.

### Components

| Module | Source APIs | Cadence |
|---|---|---|
| Inventory | Azure Resource Graph (VMs, disks, IPs, NSGs, tags, power state) | 15 min |
| Metrics | Azure Monitor Metrics API (platform metrics, agentless) | 5 min |
| Health | Resource Health, Activity Log, Service Health | 5 min |
| Guest data (phase 2) | Log Analytics query (Azure Monitor Agent data) | 5 min |
| Cost | Cost Management Query API (daily actual + amortized), Budgets | daily |
| Recommendations | Azure Advisor (rightsizing, idle, reservations) | daily |
| Alerting | Local rules engine + Azure action groups | continuous |

### Stack (proposed)

- Python 3.12+ and `uv`. Plain ARM REST calls via `httpx` (no Azure SDKs). Code in `src/qci_infra/`.
- SQLite at `~/.local/share/qci-infra/state.db`; move to Postgres only if needed.
- Two launchd agents for `qciadmin` on the Mac Studio: `check` every 5 min, `daily` at 08:00. Logs in `~/Library/Logs/qci-infra/`. Deploy with `deploy/deploy.sh`.
- Credentials (now): the Azure CLI logins on the Mac Studio, with tokens requested per subscription. If a login expires, the service alerts on itself.
- Credentials (later, done interactively with you): one read-only service principal per tenant.
- SendGrid key in `~/.config/qci-infra/sendgrid.key` (chmod 600). It isn't in the Keychain because a background launchd job can't reliably unlock it. No secrets in the repo.
- Terraform for Azure-native alerts, action groups, budgets, data collection rules.
- Provider interface (`Inventory`, `Metrics`, `Cost`) so AWS (CloudWatch, Cost Explorer) plugs in later.

### Permissions per tenant (least privilege)

Read-only to start, assigned on each subscription:

- `Reader`
- `Monitoring Reader`
- `Cost Management Reader`
- `Log Analytics Reader` (phase 2)

No write roles. Changes to Azure are made interactively with you, not by the service.

## Cost optimization — what we'll look for

- **Idle / oversized VMs** — low CPU for 14+ days → downsize or B-series.
- **Stopped but not deallocated** — still billed for compute.
- **Orphans** — unattached disks, unused public IPs, NICs, old snapshots.
- **Disk tiers** — Premium SSD on low-IO servers → Standard SSD.
- **Azure Hybrid Benefit** — Windows Server / SQL licenses you already own.
- **Reservations / Savings Plan** — for servers that run 24×7.
- **Auto-shutdown schedules** — for dev/test servers (via tag).
- **Log Analytics spend** — keep guest data collection minimal so monitoring doesn't become a cost line.

## Phased plan

### Phase 0 — Access and discovery (needs you)
1. Wake the Mac Studio and turn on Remote Login (System Settings → General → Sharing). It was unreachable today (no ARP reply at 192.168.1.173).
2. Install the Azure CLI (`brew install azure-cli`) on this Mac and the Mac Studio.
3. You run `az login --tenant <tenant>` once per account. I then pull a read-only inventory: tenants, subscriptions, VMs (OS, size, region, power state), disks, IPs, NSG rules, last 3 months of cost.
4. Write `docs/inventory.md` from that: what exists, what it costs, obvious waste, open ports.

✅ Done when: we know every subscription, VM, and the monthly spend per tenant.

### Phase 1 — Service skeleton + Azure read-only (agentless)
1. Create a service principal per tenant with the read-only roles above.
2. Build collectors: inventory, platform metrics, Resource Health, cost, Advisor.
3. Rules: VM down, CPU > 90% for 15 min, low available memory, cost day-over-day spike, budget 80/100%.
4. Notifications: one channel first (your pick), plus daily digest.
5. Deploy to the Mac Studio under launchd, plus external heartbeat.

✅ Done when: stopping a test VM triggers an alert within 10 minutes, and a daily cost digest arrives.

### Phase 2 — Azure-native safety net + guest data
1. Terraform: action group, VM availability + resource-pressure alerts, budgets for each subscription.
2. Azure Monitor Agent + one minimal data collection rule (heartbeat, disk free, memory, critical events) on all servers.
3. Rules: disk < 10% free, heartbeat missing, critical Windows events / failed systemd units.

✅ Done when: alerts fire even with the Mac Studio off, and disk-full is caught early.

### Phase 3 — Cost optimization
1. Waste report (orphans, idle VMs, stopped-not-deallocated, disk tiers), weekly.
2. Rightsizing with estimated savings; Hybrid Benefit and reservation checks.
3. Review the list together; apply chosen changes interactively.

✅ Done when: a ranked savings list with $/month exists and the first changes are applied.

### Phase 4 — AWS and others
Same provider interface: Resource Explorer/EC2, CloudWatch, Cost Explorer, IAM read-only role.

## Open questions

1. **SendGrid sender** — which verified sender address/domain to send from.

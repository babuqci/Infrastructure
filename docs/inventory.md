# Azure Inventory — 2026-11-22

Read-only snapshot pulled from the Mac Studio with your two logins. Raw JSON lives on the Mac Studio at `~/qci-inventory/` (not committed — it contains IP addresses and resource IDs).

## Subscriptions

| Subscription | Tenant | VMs | Disks | Public IPs | Monthly cost |
|---|---|---|---|---|---|
| QCI Internal (`b7e90e29…`) | QCI01 (qci3.com) | 32 | 75 (46 TB) | 43 | ~$19–24K |
| QCI Pay-As-You-Go (`fe5d8f2a…`) | Default Directory | 9 | 28 (19 TB) | 16 | **unknown — access denied** |
| Pay-As-You-Go (`3ee1b1e9…`) | Default Directory | 0 | 0 | 0 | **unknown — access denied** (8 SQL DBs, 4 web apps) |

**41 VMs in total**: 34 Windows, 7 Linux. All are running. **Every VM has a public IP.**

Cost for the two Default Directory subscriptions failed with `RBACAccessDenied`. Your login there probably lacks a cost role (needs Cost Management Reader or Billing Reader), or the tenant wants a fresh MFA token for the Cost API.

## QCI Internal — cost

| Month | Total (USD) |
|---|---|
| 2026-08 | 18,913 |
| 2026-09 | 18,819 |
| 2026-10 | 23,678 |
| 2026-11 (to ~21st) | 17,816 → on pace for ~$24K |

October jumped by $4.9K. The causes: QCIReplitSQL ($987 → $2,518), plus the new LAMMES servers (four VMs, about $2K/month together).

October by category: VMs $14.4K · Storage $3.5K · **DDoS Protection $3.0K** · Azure Firewall $930 · VPN Gateways $804 · Entra Domain Services $595 · Bastion $216.

## Top findings

### Cost (QCI Internal unless noted)

1. **DDoS Protection plan `neoddos` costs $3,000/month ($36K/year)**, for the NEO resource group. It's the single biggest line item. For a small fleet, that's usually not worth it; Azure's basic DDoS protection is free and always on. → **Review first.**
2. **Azure Firewall `neovnet-firewall` costs $930/month**, also NEO. Check whether NSGs alone would be enough.
3. **Two VPN gateways at $402/month each** (`qci_internal_virtual_network_gateway`, `qci_virtual_gateway`). Check whether both are in use.
4. **QCIReplitSQL** (E32-8as_v7) costs $2.5K/month and is the most expensive VM. Its two data-disk snapshots from 2026-09-28 may be old backups.
5. **Dev/demo VMs run 24×7.** QCIDevelopment has 18 VMs costing about $9K/month: QCIReplitSQL, NewDevelopSQL, qcidemosql, qcihotfixsql, missionm, and others. Shutting them down at night and on weekends could save 50–65% of that.
6. **Unattached disks in QCI Pay-As-You-Go: 5 disks (2.9 TB), 4 of them Premium**, some dating from 2020–2022, roughly $390/month. Candidates for deletion once confirmed.
7. **7 unused public IPs** (4 in QCI Internal, 3 in QCI Pay-As-You-Go), about $3.65/month each.
8. **Azure Hybrid Benefit is barely used.** Only 1 of the 34 Windows VMs has it (QCI-PORTAL-PROD). There are also 27 SQL Server VMs. If QCI owns Windows or SQL licenses with Software Assurance, this is the biggest saving lever. → Question for you.
9. **53 Premium SSD disks.** Some low-IO servers could move to Standard SSD. Phase 3 will check this with metrics.

### Security

None of these blocks the monitoring work, but they matter more than any of the monitoring itself.

**Open to the whole internet, on NSGs attached to a VM or subnet:**

| Port | Servers |
|---|---|
| RDP 3389 | QCI-PORTAL-PROD, GRQCIAPP01, LammesPlayerApp, LammesPlayerSQL, QCIPlayer, AADDS subnet |
| SQL 1433 | QCIReplitSQL, LammesPlayerApp, LammesPlayerSQL, QCILegalSQL |
| SMB 139/445 | GRQCIAPP01 |
| SSH 22 | committeenexus, LitigationAI, PrototypeApp, SkyRiverFTP |

You already have **Azure Bastion** in both tenants, so RDP and SSH can be closed and access routed through Bastion. SQL and SMB open to the internet are the most urgent. (Effective exposure also depends on subnet NSGs; I'll confirm with `az network nic list-effective-nsg` before you change anything.)

**29 orphan NSGs** (attached to nothing) can be cleaned up.

### Monitoring already in place

- **42 metric alerts and 5 action groups** already exist. I'll review them in Phase 2 and fold them into Terraform rather than duplicate them.
- **Azure Monitor Agent is on only 2 VMs**, so guest-level data (disk free, services) is mostly missing today.
- **SQL IaaS extension on 27 VMs.** It provides SQL licensing and health info we can use.

## Still to pull

- Cost for both Default Directory subscriptions (needs a role or re-auth).
- SQL VM license type (pay-as-you-go vs Hybrid Benefit) for each of the 27 SQL VMs.
- 14 days of CPU and memory per VM, for rightsizing (Phase 1 collector).
- Azure Advisor recommendations.

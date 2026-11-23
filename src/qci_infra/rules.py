"""Pure alert rules: turn collected data into findings."""

from dataclasses import dataclass
from datetime import date, timedelta

from .config import Thresholds

CPU = "Percentage CPU"
MEM = "Available Memory Percentage"
AVAIL = "VmAvailabilityMetric"
STOPPED_POWER = {"PowerState/stopped", "PowerState/stopping", "PowerState/deallocated", "PowerState/deallocating"}

VM_KINDS = ("vm-down", "vm-degraded", "cpu-high", "mem-low")
METRIC_KINDS = ("cpu-high", "mem-low")


@dataclass(frozen=True)
class Finding:
    kind: str
    sub: str
    name: str
    summary: str

    @property
    def key(self) -> str:
        return f"{self.kind}:{self.sub}:{self.name}"


def vm_findings(sub, vms, health, metrics, th: Thresholds, ignore_tag: str) -> list[Finding]:
    """vms: Resource Graph rows. health: {vm_id_lower: availabilityState}.
    metrics: {vm_id_lower: {metric name: [values, oldest first]}}."""
    out = []
    for vm in vms:
        if (vm.get("tags") or {}).get(ignore_tag, "").lower() == "off":
            continue
        vid, name = vm["id"].lower(), vm["name"]
        m = metrics.get(vid, {})
        state = health.get(vid)

        reasons = []
        if vm.get("power") in STOPPED_POWER:
            reasons.append(f"power state {vm['power'].removeprefix('PowerState/')}")
        if state == "Unavailable":
            reasons.append("Resource Health: Unavailable")
        if m.get(AVAIL) and m[AVAIL][-1] == 0:
            reasons.append("Azure availability metric is 0")
        if reasons:
            out.append(Finding("vm-down", sub, name, f"{name} ({vm['resourceGroup']}) is down: {'; '.join(reasons)}"))
            continue  # metrics are meaningless while down

        if state == "Degraded":
            out.append(Finding("vm-degraded", sub, name, f"{name} ({vm['resourceGroup']}) Resource Health: Degraded"))

        n = th.window_points
        cpu = m.get(CPU, [])[-n:]
        if len(cpu) == n and min(cpu) > th.cpu_percent:
            out.append(Finding("cpu-high", sub, name,
                               f"{name} CPU above {th.cpu_percent:g}% for {n * 5} min (now {cpu[-1]:.0f}%)"))
        mem = m.get(MEM, [])[-n:]
        mem_th = th.mem_available_percent_sql if vm.get("sql") else th.mem_available_percent
        if len(mem) == n and max(mem) < mem_th:
            out.append(Finding("mem-low", sub, name,
                               f"{name} available memory below {mem_th:g}% for {n * 5} min (now {mem[-1]:.0f}%)"))
    return out


def cost_findings(sub, sub_name, daily: dict[str, float], day: str, th: Thresholds) -> list[Finding]:
    """Flag `day` if its cost is well above the average of the 7 days before it."""
    d = date.fromisoformat(day)
    prior = [daily[k] for k in ((d - timedelta(days=i)).isoformat() for i in range(1, 8)) if k in daily]
    if len(prior) < 3 or day not in daily:
        return []
    avg, cost = sum(prior) / len(prior), daily[day]
    if cost > avg * th.cost_spike_ratio and cost - avg > th.cost_spike_min_usd:
        return [Finding("cost-spike", sub, day,
                        f"{sub_name} spent ${cost:,.0f} on {day}, vs 7-day average ${avg:,.0f}")]
    return []

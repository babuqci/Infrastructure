from qci_infra.config import Thresholds
from qci_infra.rules import cost_findings, vm_findings

TH = Thresholds()
SUB = "sub-1"
VM_ID = "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm-a"


def vm(power="PowerState/running", tags=None):
    return {"id": VM_ID, "name": "vm-a", "resourceGroup": "rg", "power": power, "tags": tags or {}}


def metrics(cpu=(5, 5, 5), mem=(50, 50, 50), avail=(1, 1, 1)):
    return {VM_ID.lower(): {"Percentage CPU": list(cpu), "Available Memory Percentage": list(mem),
                            "VmAvailabilityMetric": list(avail)}}


def kinds(findings):
    return sorted(f.kind for f in findings)


def test_healthy_vm_has_no_findings():
    assert vm_findings(SUB, [vm()], {VM_ID.lower(): "Available"}, metrics(), TH, "qci-monitor") == []


def test_stopped_vm_is_down():
    f = vm_findings(SUB, [vm(power="PowerState/deallocated")], {}, metrics(), TH, "qci-monitor")
    assert kinds(f) == ["vm-down"]
    assert "deallocated" in f[0].summary
    assert f[0].key == "vm-down:sub-1:vm-a"


def test_unknown_power_state_alone_is_not_down():
    # Resource Graph occasionally returns a VM with no power state; other signals decide.
    assert vm_findings(SUB, [vm(power="")], {VM_ID.lower(): "Available"}, metrics(), TH, "qci-monitor") == []
    assert kinds(vm_findings(SUB, [vm(power="")], {VM_ID.lower(): "Unavailable"}, metrics(), TH,
                             "qci-monitor")) == ["vm-down"]


def test_starting_vm_is_not_down():
    assert vm_findings(SUB, [vm(power="PowerState/starting")], {}, metrics(), TH, "qci-monitor") == []


def test_unavailable_health_is_down():
    assert kinds(vm_findings(SUB, [vm()], {VM_ID.lower(): "Unavailable"}, metrics(), TH, "qci-monitor")) == ["vm-down"]


def test_degraded_health_is_degraded():
    assert kinds(vm_findings(SUB, [vm()], {VM_ID.lower(): "Degraded"}, metrics(), TH, "qci-monitor")) == ["vm-degraded"]


def test_availability_metric_zero_is_down():
    assert kinds(vm_findings(SUB, [vm()], {}, metrics(avail=(1, 1, 0)), TH, "qci-monitor")) == ["vm-down"]


def test_one_finding_when_several_down_signals():
    f = vm_findings(SUB, [vm(power="PowerState/stopped")], {VM_ID.lower(): "Unavailable"},
                    metrics(avail=(0,)), TH, "qci-monitor")
    assert kinds(f) == ["vm-down"]


def test_cpu_high_needs_whole_window():
    assert kinds(vm_findings(SUB, [vm()], {}, metrics(cpu=(95, 96, 97)), TH, "qci-monitor")) == ["cpu-high"]
    assert vm_findings(SUB, [vm()], {}, metrics(cpu=(50, 96, 97)), TH, "qci-monitor") == []
    assert vm_findings(SUB, [vm()], {}, metrics(cpu=(96, 97)), TH, "qci-monitor") == []  # too few points


def test_memory_low():
    assert kinds(vm_findings(SUB, [vm()], {}, metrics(mem=(8, 6, 5)), TH, "qci-monitor")) == ["mem-low"]


def test_sql_vm_uses_lower_memory_threshold():
    sql_vm = {**vm(), "sql": True}
    assert vm_findings(SUB, [sql_vm], {}, metrics(mem=(5, 4, 3)), TH, "qci-monitor") == []
    assert kinds(vm_findings(SUB, [sql_vm], {}, metrics(mem=(1, 1, 1)), TH, "qci-monitor")) == ["mem-low"]


def test_metrics_skipped_when_vm_down():
    f = vm_findings(SUB, [vm(power="PowerState/deallocated")], {}, metrics(cpu=(99, 99, 99)), TH, "qci-monitor")
    assert kinds(f) == ["vm-down"]


def test_ignore_tag_skips_vm():
    v = vm(power="PowerState/deallocated", tags={"qci-monitor": "off"})
    assert vm_findings(SUB, [v], {}, metrics(), TH, "qci-monitor") == []


def test_cost_spike():
    daily = {f"2026-11-{d:02d}": 300.0 for d in range(1, 21)}
    daily["2026-11-21"] = 600.0
    f = cost_findings(SUB, "QCI Internal", daily, "2026-11-21", TH)
    assert kinds(f) == ["cost-spike"]
    assert "$600" in f[0].summary


def test_cost_no_spike_when_small_delta_or_no_history():
    daily = {f"2026-11-{d:02d}": 50.0 for d in range(1, 21)}
    daily["2026-11-21"] = 120.0  # 2.4x but only +$70
    assert cost_findings(SUB, "x", daily, "2026-11-21", TH) == []
    assert cost_findings(SUB, "x", {"2026-11-21": 999.0}, "2026-11-21", TH) == []

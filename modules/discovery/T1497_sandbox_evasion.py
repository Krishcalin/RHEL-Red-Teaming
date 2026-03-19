"""T1497 — Virtualization/Sandbox Evasion.

Checks for VM/sandbox detection indicators and evasion techniques.
Sub-techniques: T1497.001 (System Checks), T1497.002 (User Activity), T1497.003 (Time Checks).
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class SandboxEvasionCheck(BaseModule):
    TECHNIQUE_ID = "T1497"
    TECHNIQUE_NAME = "Virtualization/Sandbox Evasion"
    TACTIC = Tactic.DISCOVERY
    SEVERITY = Severity.LOW
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        vm_indicators = []

        # T1497.001 — System Checks
        # Check DMI strings
        dmi = session.execute("cat /sys/class/dmi/id/sys_vendor 2>/dev/null")
        if dmi.success and dmi.output.strip():
            vendor = dmi.output.strip().lower()
            vm_vendors = ["vmware", "qemu", "kvm", "xen", "virtualbox", "microsoft", "parallels", "bochs"]
            if any(v in vendor for v in vm_vendors):
                vm_indicators.append(f"DMI vendor: {dmi.output.strip()}")

        # Check for VM-specific kernel modules
        vm_modules = ["vmw_vmci", "vmw_balloon", "virtio", "xen_blkfront", "hv_vmbus", "vboxguest"]
        loaded = session.execute("lsmod 2>/dev/null")
        if loaded.success:
            for mod in vm_modules:
                if mod in loaded.output:
                    vm_indicators.append(f"VM kernel module: {mod}")

        # Check for VM-specific hardware
        cpuinfo = session.execute("grep -i 'hypervisor' /proc/cpuinfo 2>/dev/null")
        if cpuinfo.success and cpuinfo.output.strip():
            vm_indicators.append("CPU hypervisor flag present")

        if vm_indicators:
            self.add_finding(
                title=f"VM/sandbox indicators found: {len(vm_indicators)}",
                description="System exhibits virtualization indicators that malware could use to detect sandboxes",
                severity=Severity.INFO,
                evidence="\n".join(vm_indicators),
                remediation="If running a sandbox, harden VM artifacts to prevent evasion",
            )

        # T1497.002 — User Activity Checks
        uptime = session.execute("uptime -s 2>/dev/null")
        if uptime.success and uptime.output.strip():
            self.add_finding(
                title=f"System uptime since: {uptime.output.strip()}",
                description="Uptime can indicate sandbox (short uptime) vs production (long uptime)",
                severity=Severity.INFO,
                evidence=uptime.output.strip(),
            )

        # Check login count
        users = session.execute("last -20 2>/dev/null | grep -c 'pts\\|tty'")
        if users.success and users.output.strip().isdigit():
            count = int(users.output.strip())
            if count < 3:
                self.add_finding(
                    title=f"Low login activity: {count} recent sessions",
                    description="Very few login sessions may indicate a sandbox/analysis environment",
                    severity=Severity.INFO,
                    evidence=f"Recent login sessions: {count}",
                )

        # T1497.003 — Time Checks
        # Check for NTP skew
        time_check = session.execute("date +%s")
        if time_check.success:
            self.add_finding(
                title="System time accessible",
                description="System epoch time is readable (used in time-based sandbox evasion)",
                severity=Severity.INFO,
                evidence=f"Epoch: {time_check.output.strip()}",
            )

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Harden VM artifacts to prevent sandbox detection",
            "Simulate realistic user activity in analysis environments",
            "Remove VM guest tools if detection resistance is needed",
        ]

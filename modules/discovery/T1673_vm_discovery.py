"""T1673 — Virtual Machine Discovery.

Checks whether the system is a VM/container and identifies the hypervisor.
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class VMDiscoveryCheck(BaseModule):
    TECHNIQUE_ID = "T1673"
    TECHNIQUE_NAME = "Virtual Machine Discovery"
    TACTIC = Tactic.DISCOVERY
    SEVERITY = Severity.INFO
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        # systemd-detect-virt
        virt = session.execute("systemd-detect-virt 2>/dev/null")
        if virt.success and virt.output.strip() and virt.output.strip() != "none":
            virt_type = virt.output.strip()
            self.add_finding(
                title=f"Virtualization detected: {virt_type}",
                description=f"System is running under {virt_type} virtualization",
                severity=Severity.INFO,
                evidence=f"systemd-detect-virt: {virt_type}",
            )

        # Container detection
        container = session.execute("systemd-detect-virt --container 2>/dev/null")
        if container.success and container.output.strip() and container.output.strip() != "none":
            self.add_finding(
                title=f"Container environment detected: {container.output.strip()}",
                description="System is running inside a container",
                severity=Severity.LOW,
                evidence=f"Container type: {container.output.strip()}",
            )

        # DMI/BIOS strings
        dmi = session.execute("cat /sys/class/dmi/id/product_name 2>/dev/null")
        if dmi.success and dmi.output.strip():
            product = dmi.output.strip()
            vm_indicators = ["virtual", "vmware", "kvm", "qemu", "xen", "hyper-v", "bochs", "virtualbox"]
            if any(ind in product.lower() for ind in vm_indicators):
                self.add_finding(
                    title=f"VM product name: {product}",
                    description="DMI/BIOS data reveals virtual machine platform",
                    severity=Severity.INFO,
                    evidence=product,
                )

        # Check /.dockerenv or /run/.containerenv
        for marker, ctype in [("/.dockerenv", "Docker"), ("/run/.containerenv", "Podman/OCI")]:
            check = session.execute(f"test -f {marker} && echo found")
            if check.success and check.output.strip() == "found":
                self.add_finding(
                    title=f"Container marker found: {marker}",
                    description=f"System is running inside a {ctype} container",
                    severity=Severity.LOW,
                    evidence=f"{marker} exists",
                )

        # Check cgroup for container indicators
        cgroup = session.execute("cat /proc/1/cgroup 2>/dev/null | head -5")
        if cgroup.success and cgroup.output.strip():
            if "docker" in cgroup.output or "kubepods" in cgroup.output or "lxc" in cgroup.output:
                self.add_finding(
                    title="Container detected via cgroup",
                    description="PID 1 cgroup indicates containerized environment",
                    severity=Severity.LOW,
                    evidence=cgroup.output.strip()[:300],
                )

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Restrict access to /sys/class/dmi/ on VMs if needed",
            "Use SELinux and seccomp to confine container workloads",
            "Enable virt-what restrictions if VM detection is a concern",
        ]

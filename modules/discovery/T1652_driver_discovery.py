"""T1652 — Device Driver Discovery.

Checks for loaded kernel modules and driver enumeration.
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule

SUSPICIOUS_MODULES = [
    "usb-storage", "firewire-core", "thunderbolt", "bluetooth",
    "pcspkr", "cramfs", "freevxfs", "jffs2", "hfs", "hfsplus",
    "squashfs", "udf", "vfat",
]


class DriverDiscoveryCheck(BaseModule):
    TECHNIQUE_ID = "T1652"
    TECHNIQUE_NAME = "Device Driver Discovery"
    TACTIC = Tactic.DISCOVERY
    SEVERITY = Severity.INFO
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        lsmod = session.execute("lsmod 2>/dev/null")
        if lsmod.success and lsmod.output.strip():
            modules = [l.split()[0] for l in lsmod.output.splitlines()[1:] if l.strip()]
            self.add_finding(
                title=f"Loaded kernel modules: {len(modules)}",
                description="Kernel module list is accessible",
                severity=Severity.INFO,
                evidence="\n".join(modules[:30]),
            )

            # Check for potentially unnecessary modules
            found_suspicious = [m for m in modules if m in SUSPICIOUS_MODULES]
            if found_suspicious:
                self.add_finding(
                    title=f"Potentially unnecessary modules loaded: {len(found_suspicious)}",
                    description="Modules that may not be needed on a server are loaded",
                    severity=Severity.LOW,
                    evidence=", ".join(found_suspicious),
                    remediation="Blacklist unnecessary modules in /etc/modprobe.d/",
                )

        # Check module signing enforcement
        sig_enforce = session.execute("cat /proc/sys/kernel/modules_disabled 2>/dev/null")
        if sig_enforce.success and sig_enforce.output.strip() == "0":
            self.add_finding(
                title="Kernel module loading is not disabled",
                description="New kernel modules can be loaded at runtime",
                severity=Severity.LOW,
                evidence="kernel.modules_disabled = 0",
                remediation="Set kernel.modules_disabled = 1 after boot (irreversible until reboot)",
            )

        # Check module signature enforcement
        sig_check = session.execute("cat /proc/sys/kernel/module_sig_enforce 2>/dev/null")
        if sig_check.success and sig_check.output.strip() == "0":
            self.add_finding(
                title="Kernel module signature enforcement disabled",
                description="Unsigned kernel modules can be loaded",
                severity=Severity.MEDIUM,
                evidence="module_sig_enforce = 0",
                remediation="Enable module signature enforcement in kernel config",
            )

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Blacklist unnecessary kernel modules in /etc/modprobe.d/",
            "Enable kernel module signature enforcement",
            "Set kernel.modules_disabled = 1 after boot",
            "Use Secure Boot to verify module signatures",
        ]

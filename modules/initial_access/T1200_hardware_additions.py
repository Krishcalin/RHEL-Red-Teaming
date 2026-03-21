"""T1200 — Hardware Additions.

Checks USB device policies and udev rules on RHEL systems.
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class HardwareAdditionsCheck(BaseModule):
    TECHNIQUE_ID = "T1200"
    TECHNIQUE_NAME = "Hardware Additions"
    TACTIC = Tactic.INITIAL_ACCESS
    SEVERITY = Severity.MEDIUM
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        self._check_usbguard(session)
        self._check_usb_authorized(session)
        self._check_thunderbolt(session)

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def _check_usbguard(self, session: Session) -> None:
        result = session.execute("systemctl is-active usbguard 2>/dev/null")
        if not result.success or result.output.strip() != "active":
            self.add_finding(
                title="USBGuard not active",
                description="No USB device allow-listing — rogue hardware devices are accepted",
                severity=Severity.MEDIUM,
                evidence=f"usbguard: {result.output.strip() if result.success else 'not installed'}",
                remediation="Install and enable USBGuard with deny-by-default policy",
            )

    def _check_usb_authorized(self, session: Session) -> None:
        result = session.execute("cat /sys/bus/usb/devices/usb*/authorized_default 2>/dev/null | sort -u")
        if result.success and result.output.strip():
            if "1" in result.output:
                self.add_finding(
                    title="USB devices authorized by default",
                    description="New USB devices are automatically authorized — rogue devices accepted",
                    severity=Severity.MEDIUM,
                    evidence="authorized_default = 1",
                    remediation="Set authorized_default=0 via udev rules for deny-by-default USB policy",
                )

    def _check_thunderbolt(self, session: Session) -> None:
        result = session.execute("cat /sys/bus/thunderbolt/devices/*/security 2>/dev/null | head -3")
        if result.success and result.output.strip():
            if "none" in result.output.lower():
                self.add_finding(
                    title="Thunderbolt security is none",
                    description="Thunderbolt DMA attacks possible — devices have unrestricted access",
                    severity=Severity.HIGH,
                    evidence=result.output.strip()[:200],
                    remediation="Set Thunderbolt security level to 'user' or 'secure' in BIOS",
                )

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Deploy USBGuard with deny-by-default policy",
            "Set USB authorized_default=0 via udev rules",
            "Enable Thunderbolt security in BIOS",
            "Monitor USB device connections with auditd",
        ]

"""T1092 — Communication Through Removable Media.

Checks USB automount policies and removable media C2 feasibility on RHEL systems.
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class RemovableMediaC2Check(BaseModule):
    TECHNIQUE_ID = "T1092"
    TECHNIQUE_NAME = "Communication Through Removable Media"
    TACTIC = Tactic.COMMAND_AND_CONTROL
    SEVERITY = Severity.MEDIUM
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        self._check_usb_automount(session)
        self._check_usbguard(session)
        self._check_removable_devices(session)

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def _check_usb_automount(self, session: Session) -> None:
        udisks = session.execute("systemctl is-active udisks2 2>/dev/null")
        if udisks.success and udisks.output.strip() == "active":
            self.add_finding(
                title="udisks2 automount service is active",
                description="USB devices may be automatically mounted — enables removable media C2",
                severity=Severity.MEDIUM,
                evidence="udisks2 is active",
                remediation="Disable udisks2 on servers: systemctl disable --now udisks2",
            )

    def _check_usbguard(self, session: Session) -> None:
        result = session.execute("systemctl is-active usbguard 2>/dev/null")
        if not result.success or result.output.strip() != "active":
            self.add_finding(
                title="USBGuard is not active",
                description="No USB device policy enforcement — any USB device can be connected",
                severity=Severity.MEDIUM,
                evidence=f"usbguard status: {result.output.strip() if result.success else 'not installed'}",
                remediation="Install and configure USBGuard: dnf install usbguard && systemctl enable --now usbguard",
            )

    def _check_removable_devices(self, session: Session) -> None:
        result = session.execute("lsblk -o NAME,RM,TYPE 2>/dev/null | grep '1.*disk'")
        if result.success and result.output.strip():
            self.add_finding(
                title="Removable block devices detected",
                description="Removable storage devices are connected — potential C2 channel",
                severity=Severity.LOW,
                evidence=result.output.strip()[:300],
                remediation="Implement USBGuard policy to block unauthorized removable devices",
            )

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Deploy USBGuard with a deny-by-default policy",
            "Disable udisks2 automount on servers",
            "Use udev rules to restrict removable media mounting",
            "Monitor USB device connect events with auditd",
        ]

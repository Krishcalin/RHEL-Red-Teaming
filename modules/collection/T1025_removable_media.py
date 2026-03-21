"""T1025 — Data from Removable Media.

Checks USB auto-mount and media access policies on RHEL systems.
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class RemovableMediaCheck(BaseModule):
    TECHNIQUE_ID = "T1025"
    TECHNIQUE_NAME = "Data from Removable Media"
    TACTIC = Tactic.COLLECTION
    SEVERITY = Severity.MEDIUM
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        self._check_automount(session)
        self._check_removable_devices(session)
        self._check_usb_storage_module(session)

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def _check_automount(self, session: Session) -> None:
        udisks = session.execute("systemctl is-active udisks2 2>/dev/null")
        if udisks.success and udisks.output.strip() == "active":
            self.add_finding(
                title="udisks2 automount is active",
                description="Removable media is automatically mounted — data accessible without manual action",
                severity=Severity.MEDIUM,
                evidence="udisks2 is active",
                remediation="Disable udisks2 on servers: systemctl disable --now udisks2",
            )

    def _check_removable_devices(self, session: Session) -> None:
        result = session.execute("lsblk -o NAME,RM,SIZE,MOUNTPOINT 2>/dev/null | grep ' 1 '")
        if result.success and result.output.strip():
            self.add_finding(
                title="Removable media devices detected",
                description="Removable storage is connected and accessible for data collection",
                severity=Severity.MEDIUM,
                evidence=result.output.strip()[:300],
                remediation="Implement USBGuard policy to control removable device access",
            )

    def _check_usb_storage_module(self, session: Session) -> None:
        result = session.execute("lsmod 2>/dev/null | grep usb_storage")
        if result.success and result.output.strip():
            self.add_finding(
                title="usb_storage kernel module loaded",
                description="USB mass storage support is active",
                severity=Severity.LOW,
                evidence=result.output.strip(),
                remediation="Blacklist usb_storage if removable media is not needed",
            )

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Disable udisks2 automount on servers",
            "Deploy USBGuard with deny-by-default policy",
            "Blacklist usb_storage kernel module",
        ]

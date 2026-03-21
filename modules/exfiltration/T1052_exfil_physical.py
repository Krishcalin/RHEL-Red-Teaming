"""T1052 — Exfiltration Over Physical Medium.

Checks USB write policies and device control for physical media
exfiltration on RHEL systems.
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class ExfilPhysicalCheck(BaseModule):
    TECHNIQUE_ID = "T1052"
    TECHNIQUE_NAME = "Exfiltration Over Physical Medium"
    TACTIC = Tactic.EXFILTRATION
    SEVERITY = Severity.MEDIUM
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        self._check_usb_storage(session)
        self._check_usbguard(session)
        self._check_udev_rules(session)

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def _check_usb_storage(self, session: Session) -> None:
        result = session.execute("lsmod 2>/dev/null | grep usb_storage")
        if result.success and result.output.strip():
            self.add_finding(
                title="usb_storage kernel module is loaded",
                description="USB mass storage is active — data can be copied to USB devices",
                severity=Severity.MEDIUM,
                evidence=result.output.strip(),
                remediation="Blacklist usb_storage: echo 'blacklist usb_storage' > /etc/modprobe.d/no-usb.conf",
            )

        blacklist = session.execute("grep -r 'blacklist usb_storage' /etc/modprobe.d/ 2>/dev/null")
        if not blacklist.success or not blacklist.output.strip():
            self.add_finding(
                title="usb_storage module not blacklisted",
                description="USB storage can be loaded on demand for data exfiltration",
                severity=Severity.MEDIUM,
                evidence="No blacklist entry for usb_storage in /etc/modprobe.d/",
                remediation="Blacklist: echo 'blacklist usb_storage' > /etc/modprobe.d/no-usb.conf",
            )

    def _check_usbguard(self, session: Session) -> None:
        result = session.execute("systemctl is-active usbguard 2>/dev/null")
        if not result.success or result.output.strip() != "active":
            self.add_finding(
                title="USBGuard is not active",
                description="No USB device policy — any USB storage device can be connected",
                severity=Severity.MEDIUM,
                evidence=f"usbguard: {result.output.strip() if result.success else 'not installed'}",
                remediation="Install and enable USBGuard with a deny-by-default policy",
            )

    def _check_udev_rules(self, session: Session) -> None:
        result = session.execute("grep -r 'usb' /etc/udev/rules.d/ 2>/dev/null | grep -i 'block\\|deny\\|reject'")
        if not result.success or not result.output.strip():
            self.add_finding(
                title="No udev rules blocking USB devices",
                description="No udev rules restrict USB device access",
                severity=Severity.LOW,
                evidence="No USB-blocking udev rules found",
                remediation="Add udev rules to restrict USB storage devices",
            )

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Blacklist usb_storage kernel module",
            "Deploy USBGuard with deny-by-default policy",
            "Add udev rules to restrict USB storage devices",
            "Monitor USB device connections with auditd",
        ]

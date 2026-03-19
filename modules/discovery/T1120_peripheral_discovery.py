"""T1120 — Peripheral Device Discovery.

Checks for USB, PCI, and other peripheral device enumeration.
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class PeripheralDiscoveryCheck(BaseModule):
    TECHNIQUE_ID = "T1120"
    TECHNIQUE_NAME = "Peripheral Device Discovery"
    TACTIC = Tactic.DISCOVERY
    SEVERITY = Severity.INFO
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        # USB devices
        lsusb = session.execute("lsusb 2>/dev/null")
        if lsusb.success and lsusb.output.strip():
            devices = lsusb.output.strip().splitlines()
            self.add_finding(
                title=f"USB devices enumerable: {len(devices)}",
                description="USB device inventory is accessible",
                severity=Severity.INFO,
                evidence="\n".join(devices[:15]),
            )

        # PCI devices
        lspci = session.execute("lspci 2>/dev/null | head -20")
        if lspci.success and lspci.output.strip():
            self.add_finding(
                title="PCI devices enumerable",
                description="PCI hardware inventory is accessible",
                severity=Severity.INFO,
                evidence=lspci.output.strip()[:500],
            )

        # Block devices / storage
        lsblk = session.execute("lsblk -o NAME,SIZE,TYPE,MOUNTPOINT 2>/dev/null")
        if lsblk.success and lsblk.output.strip():
            self.add_finding(
                title="Block devices enumerable",
                description="Storage device layout is accessible",
                severity=Severity.INFO,
                evidence=lsblk.output.strip()[:500],
            )

        # USB storage policy
        usb_storage = session.execute("modprobe -n -v usb-storage 2>/dev/null")
        if usb_storage.success and "install /bin/true" not in usb_storage.output and "install /bin/false" not in usb_storage.output:
            self.add_finding(
                title="USB storage module not disabled",
                description="USB mass storage devices can be connected — data exfiltration risk",
                severity=Severity.MEDIUM,
                evidence=usb_storage.output.strip() or "usb-storage module is loadable",
                remediation="Disable USB storage: echo 'install usb-storage /bin/true' > /etc/modprobe.d/usb-storage.conf",
            )

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Disable USB storage: install usb-storage /bin/true in modprobe.d",
            "Use udev rules to restrict USB device classes",
            "Restrict lsusb/lspci access via RBAC or SELinux",
        ]

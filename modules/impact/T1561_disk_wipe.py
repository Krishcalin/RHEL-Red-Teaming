"""T1561 — Disk Wipe.

Checks disk write access, availability of low-level disk tools, and
partition table protection on RHEL systems.
Sub-techniques: Disk Content Wipe (T1561.001), Disk Structure Wipe (T1561.002).
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class DiskWipeCheck(BaseModule):
    TECHNIQUE_ID = "T1561"
    TECHNIQUE_NAME = "Disk Wipe"
    TACTIC = Tactic.IMPACT
    SEVERITY = Severity.CRITICAL
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        self._check_disk_tools(session)
        self._check_raw_disk_access(session)
        self._check_partition_protection(session)

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def _check_disk_tools(self, session: Session) -> None:
        tools = {"dd": "raw disk copy/wipe", "shred": "secure overwrite",
                 "wipefs": "wipe filesystem signatures", "fdisk": "partition table editor",
                 "parted": "partition manager", "mkfs": "filesystem formatter"}
        for tool, desc in tools.items():
            result = session.execute(f"which {tool} 2>/dev/null")
            if result.success and result.output.strip():
                suid = session.execute(f"test -u {result.output.strip()} && echo SUID")
                severity = Severity.HIGH if suid.success and "SUID" in suid.output else Severity.MEDIUM
                self.add_finding(
                    title=f"Disk tool available: {tool}",
                    description=f"{tool} ({desc}) is available — could be used for disk wiping",
                    severity=severity,
                    evidence=f"{result.output.strip()}" + (" [SUID]" if "SUID" in (suid.output or "") else ""),
                    remediation=f"Restrict access to {tool} if not needed; monitor with auditd",
                )

    def _check_raw_disk_access(self, session: Session) -> None:
        devices = session.execute("ls -la /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null | head -10")
        if devices.success and devices.output.strip():
            for line in devices.output.strip().splitlines():
                parts = line.split()
                if len(parts) >= 9:
                    perms = parts[0]
                    device = parts[-1]
                    if perms[7] == "w" or perms[4] == "w":
                        self.add_finding(
                            title=f"Block device has broad write permissions: {device}",
                            description=f"Device {device} may be writable by group or others",
                            severity=Severity.CRITICAL,
                            evidence=line.strip(),
                            remediation=f"Restrict device permissions: chmod 660 {device}; chown root:disk",
                        )

    def _check_partition_protection(self, session: Session) -> None:
        result = session.execute("cat /proc/sys/kernel/modules_disabled 2>/dev/null")
        if result.success and result.output.strip() == "0":
            self.add_finding(
                title="Kernel module loading is unrestricted",
                description="Arbitrary kernel modules can be loaded — could bypass disk protections",
                severity=Severity.MEDIUM,
                evidence="kernel.modules_disabled = 0",
                remediation="Set kernel.modules_disabled=1 after boot in production (irreversible until reboot)",
            )

        result = session.execute("cat /sys/block/sda/ro 2>/dev/null")
        if result.success and result.output.strip() == "0":
            self.add_finding(
                title="Primary disk is read-write",
                description="The primary block device is in read-write mode (expected but noted)",
                severity=Severity.INFO,
                evidence="sda read-only flag: 0",
                remediation="Consider read-only root filesystem for immutable infrastructure",
            )

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Restrict access to disk tools (dd, fdisk, wipefs) via permissions and auditd",
            "Ensure block devices have restrictive permissions (root:disk 660)",
            "Use UEFI Secure Boot to prevent unauthorized boot modifications",
            "Deploy regular disk/volume snapshots for rapid recovery",
            "Consider read-only root filesystems for immutable server deployments",
        ]

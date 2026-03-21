"""T1080 — Taint Shared Content.

Checks for writable NFS/Samba shares and other shared content that
could be poisoned for lateral movement on RHEL systems.
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class TaintSharedContentCheck(BaseModule):
    TECHNIQUE_ID = "T1080"
    TECHNIQUE_NAME = "Taint Shared Content"
    TACTIC = Tactic.LATERAL_MOVEMENT
    SEVERITY = Severity.HIGH
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        self._check_nfs_exports(session)
        self._check_samba_shares(session)
        self._check_writable_mounts(session)

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def _check_nfs_exports(self, session: Session) -> None:
        result = session.execute("cat /etc/exports 2>/dev/null")
        if result.success and result.output.strip():
            for line in result.output.strip().splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    if "no_root_squash" in line:
                        self.add_finding(
                            title="NFS export with no_root_squash",
                            description="Root on NFS clients has root access on the share — content can be poisoned",
                            severity=Severity.CRITICAL,
                            evidence=line[:300],
                            remediation="Remove no_root_squash from NFS exports; use root_squash (default)",
                        )
                    if "rw" in line and "*" in line:
                        self.add_finding(
                            title="NFS export writable by any host",
                            description="NFS share is exported read-write to all hosts (*)",
                            severity=Severity.HIGH,
                            evidence=line[:300],
                            remediation="Restrict NFS exports to specific hosts/subnets",
                        )

    def _check_samba_shares(self, session: Session) -> None:
        result = session.execute("testparm -s 2>/dev/null | grep -A5 '\\[' | grep -E 'writable|guest ok|path'")
        if result.success and result.output.strip():
            if "writable = yes" in result.output.lower() or "write ok = yes" in result.output.lower():
                if "guest ok = yes" in result.output.lower():
                    self.add_finding(
                        title="Samba share writable by guests",
                        description="A Samba share allows guest write access — shared content can be poisoned",
                        severity=Severity.HIGH,
                        evidence=result.output.strip()[:500],
                        remediation="Disable guest access and require authentication for writable shares",
                    )

    def _check_writable_mounts(self, session: Session) -> None:
        result = session.execute("mount -t nfs,nfs4,cifs 2>/dev/null")
        if result.success and result.output.strip():
            for line in result.output.strip().splitlines():
                if "rw" in line:
                    mount_point = line.split(" on ")[-1].split(" type ")[0] if " on " in line else line.split()[2]
                    writable = session.execute(f"test -w {mount_point} && echo writable")
                    if writable.success and "writable" in writable.output:
                        self.add_finding(
                            title=f"Writable network mount: {mount_point}",
                            description=f"Current user can write to network share at {mount_point}",
                            severity=Severity.MEDIUM,
                            evidence=line[:300],
                            remediation=f"Restrict write access on {mount_point} or mount read-only",
                        )

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Use root_squash on all NFS exports (never no_root_squash)",
            "Restrict NFS exports to specific hosts, not wildcards",
            "Require authentication for all Samba shares (no guest access)",
            "Mount shared content read-only where possible",
            "Monitor shared content for unauthorized modifications with AIDE",
        ]

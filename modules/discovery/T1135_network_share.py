"""T1135 — Network Share Discovery.

Checks for NFS exports, Samba shares, and mounted network filesystems.
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class NetworkShareCheck(BaseModule):
    TECHNIQUE_ID = "T1135"
    TECHNIQUE_NAME = "Network Share Discovery"
    TACTIC = Tactic.DISCOVERY
    SEVERITY = Severity.MEDIUM
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        # NFS exports
        exports = session.execute("cat /etc/exports 2>/dev/null | grep -v '^#' | grep -v '^$'")
        if exports.success and exports.output.strip():
            lines = exports.output.strip().splitlines()
            self.add_finding(
                title=f"NFS exports configured: {len(lines)}",
                description="NFS shares are exported from this system",
                severity=Severity.MEDIUM,
                evidence=exports.output.strip(),
                remediation="Restrict NFS exports to specific hosts; use root_squash",
            )
            # Check for no_root_squash
            if "no_root_squash" in exports.output:
                self.add_finding(
                    title="NFS export with no_root_squash",
                    description="Remote root users retain root privileges on mounted shares — privilege escalation risk",
                    severity=Severity.HIGH,
                    evidence=exports.output.strip(),
                    remediation="Remove no_root_squash option from NFS exports",
                )

        # Samba shares
        smb_conf = session.execute("testparm -s 2>/dev/null | grep -A3 '\\[' | head -40")
        if not smb_conf.success or not smb_conf.output.strip():
            smb_conf = session.execute("cat /etc/samba/smb.conf 2>/dev/null | grep -A2 '\\[' | grep -v '^#' | head -40")
        if smb_conf.success and smb_conf.output.strip() and "[" in smb_conf.output:
            self.add_finding(
                title="Samba shares configured",
                description="SMB/CIFS shares are available on this system",
                severity=Severity.MEDIUM,
                evidence=smb_conf.output.strip()[:500],
                remediation="Restrict Samba shares; require authentication; disable guest access",
            )

        # Currently mounted network filesystems
        mounts = session.execute("mount | grep -E 'nfs|cifs|smb|sshfs|gluster' 2>/dev/null")
        if mounts.success and mounts.output.strip():
            self.add_finding(
                title="Network filesystems mounted",
                description="Remote filesystems are currently mounted",
                severity=Severity.INFO,
                evidence=mounts.output.strip(),
            )

        # fstab network entries
        fstab = session.execute("grep -E 'nfs|cifs|smbfs' /etc/fstab 2>/dev/null | grep -v '^#'")
        if fstab.success and fstab.output.strip():
            self.add_finding(
                title="Network mounts in /etc/fstab",
                description="Persistent network mounts reveal infrastructure relationships",
                severity=Severity.LOW,
                evidence=fstab.output.strip(),
            )

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Use root_squash on all NFS exports",
            "Restrict NFS exports to specific IP addresses/subnets",
            "Require authentication for Samba shares; disable guest access",
            "Use NFSv4 with Kerberos authentication where possible",
        ]

"""T1039 — Data from Network Shared Drive.

Checks NFS/Samba mount enumeration on RHEL systems.
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class NetworkSharedDriveCheck(BaseModule):
    TECHNIQUE_ID = "T1039"
    TECHNIQUE_NAME = "Data from Network Shared Drive"
    TACTIC = Tactic.COLLECTION
    SEVERITY = Severity.MEDIUM
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        self._check_mounted_shares(session)
        self._check_fstab_shares(session)
        self._check_share_tools(session)

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def _check_mounted_shares(self, session: Session) -> None:
        result = session.execute("mount -t nfs,nfs4,cifs,smbfs 2>/dev/null")
        if result.success and result.output.strip():
            for line in result.output.strip().splitlines():
                self.add_finding(
                    title="Network share mounted",
                    description=f"Mounted network share accessible for data collection",
                    severity=Severity.MEDIUM,
                    evidence=line[:300],
                    remediation="Restrict network share mount permissions; use read-only where possible",
                )

    def _check_fstab_shares(self, session: Session) -> None:
        result = session.execute("grep -E 'nfs|cifs|smbfs' /etc/fstab 2>/dev/null")
        if result.success and result.output.strip():
            for line in result.output.strip().splitlines():
                if not line.strip().startswith("#"):
                    if "credentials=" in line or "password=" in line:
                        self.add_finding(
                            title="Network share credentials in fstab",
                            description="Mount credentials stored in /etc/fstab — readable by local users",
                            severity=Severity.HIGH,
                            evidence=line[:300],
                            remediation="Use a credentials file with 600 permissions instead",
                        )

    def _check_share_tools(self, session: Session) -> None:
        tools = {"smbclient": "SMB/CIFS client", "showmount": "NFS export lister",
                 "mount.cifs": "CIFS mounter", "mount.nfs": "NFS mounter"}
        for tool, desc in tools.items():
            result = session.execute(f"which {tool} 2>/dev/null")
            if result.success and result.output.strip():
                self.add_finding(
                    title=f"Share enumeration tool: {tool}",
                    description=f"{tool} ({desc}) can discover and access network shares",
                    severity=Severity.LOW,
                    evidence=result.output.strip(),
                    remediation=f"Remove {tool} if network share access is not needed",
                )

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Mount network shares read-only where possible",
            "Store share credentials in files with 600 permissions, not fstab",
            "Remove share client tools from non-admin hosts",
            "Monitor network share access with auditd",
        ]

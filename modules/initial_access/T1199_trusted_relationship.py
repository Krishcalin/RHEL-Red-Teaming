"""T1199 — Trusted Relationship.

Checks trust relationships, SSH keys, and NFS exports on RHEL systems.
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class TrustedRelationshipCheck(BaseModule):
    TECHNIQUE_ID = "T1199"
    TECHNIQUE_NAME = "Trusted Relationship"
    TACTIC = Tactic.INITIAL_ACCESS
    SEVERITY = Severity.HIGH
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        self._check_ssh_trusts(session)
        self._check_nfs_exports(session)
        self._check_sssd_trusts(session)
        self._check_rhosts(session)

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def _check_ssh_trusts(self, session: Session) -> None:
        result = session.execute("find /home /root -name 'authorized_keys' 2>/dev/null | head -10")
        if result.success and result.output.strip():
            for f in result.output.strip().splitlines():
                count = session.execute(f"wc -l < {f.strip()} 2>/dev/null")
                if count.success and count.output.strip():
                    try:
                        n = int(count.output.strip())
                        if n > 10:
                            self.add_finding(
                                title=f"Many SSH keys in {f.strip()} ({n} keys)",
                                description="Large number of authorized SSH keys increases trust exposure",
                                severity=Severity.MEDIUM,
                                evidence=f"{n} keys in {f.strip()}",
                                remediation="Audit and reduce SSH authorized_keys to minimum necessary",
                            )
                    except ValueError:
                        pass

    def _check_nfs_exports(self, session: Session) -> None:
        result = session.execute("cat /etc/exports 2>/dev/null | grep -v '^#' | grep -v '^$'")
        if result.success and result.output.strip():
            for line in result.output.strip().splitlines():
                if "*" in line or "0.0.0.0" in line:
                    self.add_finding(
                        title="NFS export open to all hosts",
                        description="NFS share exported to * or 0.0.0.0 — any host is trusted",
                        severity=Severity.HIGH,
                        evidence=line[:300],
                        remediation="Restrict NFS exports to specific hosts or subnets",
                    )

    def _check_sssd_trusts(self, session: Session) -> None:
        result = session.execute("grep -i 'subdomains_provider\\|ipa_server_mode' /etc/sssd/sssd.conf 2>/dev/null")
        if result.success and result.output.strip():
            self.add_finding(
                title="SSSD trust configuration detected",
                description="Cross-domain trusts extend authentication boundaries",
                severity=Severity.MEDIUM,
                evidence=result.output.strip()[:300],
                remediation="Audit SSSD trust configuration; restrict trust scope",
            )

    def _check_rhosts(self, session: Session) -> None:
        result = session.execute("find /home /root -name '.rhosts' -o -name 'hosts.equiv' 2>/dev/null")
        if result.success and result.output.strip():
            self.add_finding(
                title="Legacy .rhosts/hosts.equiv files found",
                description="Legacy trust files enable passwordless remote access",
                severity=Severity.CRITICAL,
                evidence=result.output.strip()[:300],
                remediation="Remove .rhosts and hosts.equiv files; disable rsh services",
            )

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Audit SSH authorized_keys and reduce to minimum necessary",
            "Restrict NFS exports to specific hosts",
            "Review SSSD cross-domain trust configuration",
            "Remove legacy .rhosts and hosts.equiv files",
        ]

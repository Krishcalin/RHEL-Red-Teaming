"""T1114 — Email Collection.

Checks mail forwarding rules and mail spool access on RHEL systems.
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class EmailCollectionCheck(BaseModule):
    TECHNIQUE_ID = "T1114"
    TECHNIQUE_NAME = "Email Collection"
    TACTIC = Tactic.COLLECTION
    SEVERITY = Severity.MEDIUM
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        self._check_mail_spool(session)
        self._check_forward_files(session)
        self._check_aliases(session)

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def _check_mail_spool(self, session: Session) -> None:
        result = session.execute("find /var/mail /var/spool/mail -type f -readable 2>/dev/null | head -10")
        if result.success and result.output.strip():
            count = len(result.output.strip().splitlines())
            self.add_finding(
                title=f"{count} readable mail spool files",
                description="User mail spools are readable — email content can be collected",
                severity=Severity.HIGH,
                evidence=result.output.strip()[:300],
                remediation="Restrict mail spool permissions to owner only (600)",
            )

    def _check_forward_files(self, session: Session) -> None:
        result = session.execute("find /home /root -name '.forward' 2>/dev/null | head -10")
        if result.success and result.output.strip():
            for f in result.output.strip().splitlines():
                content = session.execute(f"cat {f.strip()} 2>/dev/null")
                if content.success and content.output.strip():
                    self.add_finding(
                        title=f"Mail forwarding rule: {f.strip()}",
                        description="Email forwarding can redirect mail to attacker-controlled addresses",
                        severity=Severity.MEDIUM,
                        evidence=content.output.strip()[:200],
                        remediation=f"Audit {f.strip()}; restrict .forward file creation",
                    )

    def _check_aliases(self, session: Session) -> None:
        result = session.execute("cat /etc/aliases 2>/dev/null | grep -v '^#' | grep -v '^$'")
        if result.success and result.output.strip():
            suspicious = [l for l in result.output.strip().splitlines()
                         if "|" in l or "/" in l]
            if suspicious:
                self.add_finding(
                    title="Mail aliases with pipe/file delivery",
                    description="Mail aliases forward to commands or files — email collection vector",
                    severity=Severity.MEDIUM,
                    evidence="\n".join(suspicious[:5]),
                    remediation="Audit /etc/aliases for unauthorized pipe/file deliveries",
                )

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Restrict mail spool permissions to 600",
            "Audit .forward files and restrict creation",
            "Review /etc/aliases for unauthorized redirections",
        ]

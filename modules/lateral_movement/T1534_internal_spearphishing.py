"""T1534 — Internal Spearphishing.

Checks internal mail relay configuration and user trust relationships
that could facilitate internal spearphishing on RHEL systems.
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class InternalSpearphishingCheck(BaseModule):
    TECHNIQUE_ID = "T1534"
    TECHNIQUE_NAME = "Internal Spearphishing"
    TACTIC = Tactic.LATERAL_MOVEMENT
    SEVERITY = Severity.MEDIUM
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        self._check_internal_relay(session)
        self._check_mail_command(session)
        self._check_user_enumeration(session)

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def _check_internal_relay(self, session: Session) -> None:
        postfix = session.execute("postconf mynetworks 2>/dev/null")
        if postfix.success and postfix.output.strip():
            networks = postfix.output.strip()
            if "0.0.0.0/0" in networks or "any" in networks.lower():
                self.add_finding(
                    title="Postfix relays from any network",
                    description="mynetworks allows all hosts — any compromised host can send spoofed internal mail",
                    severity=Severity.HIGH,
                    evidence=networks[:300],
                    remediation="Restrict mynetworks to trusted subnets only",
                )

    def _check_mail_command(self, session: Session) -> None:
        for tool in ["mail", "sendmail", "mutt"]:
            result = session.execute(f"which {tool} 2>/dev/null")
            if result.success and result.output.strip():
                self.add_finding(
                    title=f"Mail client available: {tool}",
                    description=f"{tool} can be used to send spoofed internal emails",
                    severity=Severity.LOW,
                    evidence=result.output.strip(),
                    remediation=f"Remove {tool} if not needed or restrict with permissions",
                )

    def _check_user_enumeration(self, session: Session) -> None:
        result = session.execute("getent passwd | grep -c '/bin/bash\\|/bin/sh'")
        if result.success and result.output.strip():
            try:
                count = int(result.output.strip())
                if count > 0:
                    users = session.execute("getent passwd | grep '/bin/bash\\|/bin/sh' | cut -d: -f1 | head -20")
                    self.add_finding(
                        title=f"{count} interactive user accounts found",
                        description="User accounts can be enumerated for targeted internal phishing",
                        severity=Severity.INFO,
                        evidence=users.output.strip()[:300] if users.success else f"{count} accounts",
                        remediation="Restrict getent/passwd access; use SSSD enumeration=False",
                    )
            except ValueError:
                pass

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Restrict internal mail relay to authenticated users only",
            "Remove mail client tools from non-mail servers",
            "Implement SPF/DKIM for internal mail domains",
            "Disable user enumeration via SSSD (enumeration=False)",
            "Train users to verify internal email authenticity",
        ]

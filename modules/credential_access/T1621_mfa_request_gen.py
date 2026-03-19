"""T1621 — Multi-Factor Authentication Request Generation.

Checks for MFA fatigue/push spam feasibility.
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class MFARequestGenCheck(BaseModule):
    TECHNIQUE_ID = "T1621"
    TECHNIQUE_NAME = "Multi-Factor Authentication Request Generation"
    TACTIC = Tactic.CREDENTIAL_ACCESS
    SEVERITY = Severity.MEDIUM
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        # Check for push-based MFA that could be susceptible to fatigue
        duo_pam = session.execute("grep -r 'pam_duo' /etc/pam.d/ 2>/dev/null")
        if duo_pam.success and duo_pam.output.strip():
            self.add_finding(
                title="Duo MFA (push-based) configured",
                description="Duo push notifications could be exploited via MFA fatigue attacks",
                severity=Severity.MEDIUM,
                evidence=duo_pam.output.strip()[:300],
                remediation="Enable Duo number matching; configure rate limiting for push requests",
            )

        # Check for MFA rate limiting in PAM
        faillock_mfa = session.execute(
            "grep -r 'deny\\|fail_interval' /etc/security/faillock.conf 2>/dev/null | grep -v '^#'"
        )
        if not faillock_mfa.success or not faillock_mfa.output.strip():
            self.add_finding(
                title="No rate limiting for authentication attempts",
                description="Without rate limiting, MFA push spam attacks are feasible",
                severity=Severity.MEDIUM,
                remediation="Configure pam_faillock with deny=5 and fail_interval=900",
            )

        # Check SSH auth attempts (MFA bypass via rapid auth)
        ssh_max = session.execute("grep -i 'MaxAuthTries' /etc/ssh/sshd_config 2>/dev/null | grep -v '^#'")
        if ssh_max.success and ssh_max.output.strip():
            val = ssh_max.output.strip().split()[-1]
            if val.isdigit() and int(val) > 3:
                self.add_finding(
                    title=f"SSH allows {val} auth attempts per connection",
                    description="High MaxAuthTries enables rapid MFA prompt generation",
                    severity=Severity.LOW,
                    evidence=ssh_max.output.strip(),
                    remediation="Set MaxAuthTries 3 in sshd_config",
                )

        # Check if FIDO2/WebAuthn is configured (phishing-resistant, no push fatigue)
        fido = session.execute("grep -r 'pam_u2f\\|pam_fido' /etc/pam.d/ 2>/dev/null")
        if fido.success and fido.output.strip():
            self.add_finding(
                title="FIDO2/U2F MFA configured (phishing-resistant)",
                description="Hardware-based MFA is in use — immune to push fatigue attacks",
                severity=Severity.INFO,
                evidence=fido.output.strip()[:200],
            )

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Use FIDO2/WebAuthn hardware keys (immune to push fatigue)",
            "Enable number matching on Duo/Okta push MFA",
            "Configure rate limiting for auth attempts (pam_faillock)",
            "Set SSH MaxAuthTries to 3",
            "Monitor for excessive MFA push notifications",
        ]

"""T1201 — Password Policy Discovery.

Checks password policies, aging, complexity, and lockout settings.
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class PasswordPolicyCheck(BaseModule):
    TECHNIQUE_ID = "T1201"
    TECHNIQUE_NAME = "Password Policy Discovery"
    TACTIC = Tactic.DISCOVERY
    SEVERITY = Severity.MEDIUM
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        # PAM password quality
        pwquality = session.execute("cat /etc/security/pwquality.conf 2>/dev/null | grep -v '^#' | grep -v '^$'")
        if pwquality.success and pwquality.output.strip():
            self.add_finding(
                title="Password quality policy readable",
                description="PAM password complexity rules are accessible",
                severity=Severity.INFO,
                evidence=pwquality.output.strip(),
            )
            # Check for weak settings
            config = pwquality.output.lower()
            if "minlen" in config:
                for line in config.splitlines():
                    if "minlen" in line and "=" in line:
                        val = line.split("=")[-1].strip()
                        if val.isdigit() and int(val) < 12:
                            self.add_finding(
                                title=f"Weak minimum password length: {val}",
                                description="Minimum password length is below recommended 12 characters",
                                severity=Severity.MEDIUM,
                                evidence=line.strip(),
                                remediation="Set minlen = 14 in /etc/security/pwquality.conf",
                            )
        else:
            self.add_finding(
                title="No password quality policy found",
                description="pwquality.conf is missing or empty — no password complexity enforcement",
                severity=Severity.HIGH,
                remediation="Configure /etc/security/pwquality.conf with minlen=14, dcredit=-1, ucredit=-1, etc.",
            )

        # Login.defs — password aging
        login_defs = session.execute("grep -E '^PASS_(MAX|MIN|WARN)' /etc/login.defs 2>/dev/null")
        if login_defs.success and login_defs.output.strip():
            self.add_finding(
                title="Password aging policy",
                description="Password aging configuration from /etc/login.defs",
                severity=Severity.INFO,
                evidence=login_defs.output.strip(),
            )
            for line in login_defs.output.splitlines():
                if "PASS_MAX_DAYS" in line:
                    val = line.split()[-1] if line.split() else ""
                    if val.isdigit() and int(val) > 90:
                        self.add_finding(
                            title=f"Password max age too long: {val} days",
                            description="Passwords don't expire frequently enough",
                            severity=Severity.MEDIUM,
                            evidence=line.strip(),
                            remediation="Set PASS_MAX_DAYS to 60-90 in /etc/login.defs",
                        )
                if "PASS_MIN_DAYS" in line:
                    val = line.split()[-1] if line.split() else ""
                    if val.isdigit() and int(val) < 1:
                        self.add_finding(
                            title="No minimum password age set",
                            description="Users can change passwords repeatedly to cycle back to old passwords",
                            severity=Severity.LOW,
                            evidence=line.strip(),
                            remediation="Set PASS_MIN_DAYS to at least 1",
                        )

        # PAM faillock / account lockout
        faillock = session.execute("grep -r faillock /etc/pam.d/ 2>/dev/null | head -10")
        if faillock.success and faillock.output.strip():
            self.add_finding(
                title="Account lockout (faillock) configured",
                description="PAM faillock is configured for brute-force protection",
                severity=Severity.INFO,
                evidence=faillock.output.strip()[:500],
            )
        else:
            self.add_finding(
                title="No account lockout policy detected",
                description="PAM faillock is not configured — no brute-force protection",
                severity=Severity.HIGH,
                remediation="Configure pam_faillock in /etc/pam.d/system-auth and password-auth",
            )

        # Check for empty passwords
        empty_pw = session.execute("awk -F: '($2 == \"\" || $2 == \"!\") {print $1}' /etc/shadow 2>/dev/null")
        if empty_pw.success and empty_pw.output.strip():
            accounts = empty_pw.output.strip().splitlines()
            real_empty = [a for a in accounts if a not in ("*", "!")]
            if real_empty:
                self.add_finding(
                    title=f"Accounts with empty/no password: {len(real_empty)}",
                    description="Accounts without passwords can be accessed without authentication",
                    severity=Severity.CRITICAL,
                    evidence=", ".join(real_empty[:10]),
                    remediation="Set passwords for all accounts or lock them: passwd -l <account>",
                )

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Set minlen=14, dcredit=-1, ucredit=-1, lcredit=-1, ocredit=-1 in pwquality.conf",
            "Configure PASS_MAX_DAYS=90, PASS_MIN_DAYS=1, PASS_WARN_AGE=7",
            "Enable pam_faillock with deny=5, unlock_time=900",
            "Lock all accounts without passwords",
        ]

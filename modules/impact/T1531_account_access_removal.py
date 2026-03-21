"""T1531 — Account Access Removal.

Checks account deletion/lockout feasibility, password management controls,
and user modification permissions on RHEL systems.
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class AccountAccessRemovalCheck(BaseModule):
    TECHNIQUE_ID = "T1531"
    TECHNIQUE_NAME = "Account Access Removal"
    TACTIC = Tactic.IMPACT
    SEVERITY = Severity.HIGH
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        self._check_user_management_access(session)
        self._check_passwd_shadow_perms(session)
        self._check_account_lockout_policy(session)
        self._check_ssh_key_access(session)

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def _check_user_management_access(self, session: Session) -> None:
        cmds = {"userdel": "delete users", "usermod": "modify users",
                "passwd": "change passwords", "chage": "change password aging"}
        for cmd, desc in cmds.items():
            result = session.execute(f"sudo -n {cmd} --help 2>&1 | head -1; echo EXIT=$?")
            if result.success and "EXIT=0" in result.output and "password" not in result.output.lower():
                self.add_finding(
                    title=f"Passwordless sudo access to {cmd}",
                    description=f"User can {desc} without a password via sudo",
                    severity=Severity.HIGH,
                    evidence=result.output.strip()[:300],
                    remediation=f"Remove {cmd} from NOPASSWD sudo rules",
                )

    def _check_passwd_shadow_perms(self, session: Session) -> None:
        files = {"/etc/passwd": "644", "/etc/shadow": "000",
                 "/etc/group": "644", "/etc/gshadow": "000"}
        for path, expected in files.items():
            result = session.execute(f"stat -c '%a' {path} 2>/dev/null")
            if result.success and result.output.strip():
                actual = result.output.strip()
                if int(actual) > int(expected):
                    self.add_finding(
                        title=f"Overly permissive: {path} ({actual})",
                        description=f"{path} has permissions {actual}, expected {expected} or stricter",
                        severity=Severity.HIGH,
                        evidence=f"Permissions: {actual}",
                        remediation=f"Fix permissions: chmod {expected} {path}",
                    )

    def _check_account_lockout_policy(self, session: Session) -> None:
        pam_faillock = session.execute(
            "grep -r 'pam_faillock\\|pam_tally2' /etc/pam.d/ 2>/dev/null"
        )
        if not pam_faillock.success or not pam_faillock.output.strip():
            self.add_finding(
                title="No account lockout policy configured",
                description="pam_faillock/pam_tally2 not found in PAM — no brute-force lockout protection",
                severity=Severity.MEDIUM,
                evidence="No faillock/tally2 entries in /etc/pam.d/",
                remediation="Configure pam_faillock in /etc/pam.d/system-auth and password-auth",
            )

    def _check_ssh_key_access(self, session: Session) -> None:
        result = session.execute(
            "find /home -name 'authorized_keys' -writable 2>/dev/null"
        )
        if result.success and result.output.strip():
            self.add_finding(
                title="Writable authorized_keys files found",
                description="Current user can modify SSH authorized_keys — could remove legitimate access",
                severity=Severity.HIGH,
                evidence=result.output.strip()[:500],
                remediation="Set strict permissions: chmod 600 ~/.ssh/authorized_keys; chown user:user",
            )

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Restrict sudo access to user management commands (userdel, usermod, passwd)",
            "Enforce correct permissions on /etc/passwd, /etc/shadow, /etc/group",
            "Configure pam_faillock for account lockout after failed attempts",
            "Set strict permissions on SSH authorized_keys files",
            "Use centralised identity management (FreeIPA/LDAP) with audit logging",
        ]

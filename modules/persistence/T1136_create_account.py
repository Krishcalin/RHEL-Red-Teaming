"""T1136 — Create Account.

Checks for persistence via local or domain account creation,
UID 0 accounts, and weak login/password policies.
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class CreateAccountCheck(BaseModule):
    TECHNIQUE_ID = "T1136"
    TECHNIQUE_NAME = "Create Account"
    TACTIC = Tactic.PERSISTENCE
    SEVERITY = Severity.HIGH
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    # Standard system account UIDs that are expected to have UID 0
    EXPECTED_UID0 = {"root"}

    # Default system shells that indicate no interactive login
    NOLOGIN_SHELLS = {"/sbin/nologin", "/usr/sbin/nologin", "/bin/false", "/usr/bin/false"}

    def check(self, session: Session) -> ModuleResult:
        self._check_local_accounts(session)
        self._check_domain_accounts(session)
        self._check_useradd_defaults(session)
        self._check_login_defs(session)

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def _check_local_accounts(self, session: Session) -> None:
        """T1136.001: Check for suspicious local accounts."""
        # Check for accounts with UID 0 besides root
        uid0 = session.execute(
            "awk -F: '$3 == 0 && $1 != \"root\" {print $0}' /etc/passwd 2>/dev/null"
        )
        if uid0.success and uid0.output.strip():
            self.add_finding(
                title="Non-root accounts with UID 0",
                description="Accounts with UID 0 have full root privileges — classic backdoor technique",
                severity=Severity.CRITICAL,
                evidence=uid0.output.strip(),
                remediation="Remove or disable UID 0 accounts other than root: userdel <account>",
            )

        # Check for recently created accounts (UID >= 1000, common range for human users)
        recent_accounts = session.execute(
            "awk -F: '$3 >= 1000 && $3 < 65534 {print $1, $3, $7}' /etc/passwd 2>/dev/null"
        )
        if recent_accounts.success and recent_accounts.output.strip():
            lines = recent_accounts.output.strip().splitlines()
            # Also check last password change date to identify recently created accounts
            for line in lines:
                parts = line.strip().split()
                if len(parts) >= 1:
                    username = parts[0]
                    last_change = session.execute(
                        f"chage -l '{username}' 2>/dev/null | grep 'Last password change'"
                    )
                    # We report all non-system accounts for auditing context
            if len(lines) > 0:
                self.add_finding(
                    title=f"Local user accounts found: {len(lines)}",
                    description="Review local accounts to ensure all are authorized",
                    severity=Severity.INFO,
                    evidence=recent_accounts.output.strip()[:500],
                    remediation="Audit local accounts; disable unauthorized ones with usermod -L <user>",
                )

        # Check for accounts with valid shells but no password set
        no_password = session.execute(
            "awk -F: '$2 == \"\" || $2 == \"!\" || $2 == \"!!\" || $2 == \"*\" {print $1}' "
            "/etc/shadow 2>/dev/null"
        )
        passwd_entries = session.execute("cat /etc/passwd 2>/dev/null")
        if no_password.success and no_password.output.strip() and passwd_entries.success:
            no_pass_users = set(no_password.output.strip().splitlines())
            passwd_lines = passwd_entries.output.strip().splitlines()
            risky_users = []
            for line in passwd_lines:
                fields = line.split(":")
                if len(fields) >= 7:
                    username = fields[0]
                    shell = fields[6]
                    if username in no_pass_users and shell not in self.NOLOGIN_SHELLS:
                        risky_users.append(f"{username} (shell: {shell})")
            if risky_users:
                self.add_finding(
                    title=f"Accounts with login shells but no password: {len(risky_users)}",
                    description="Accounts with valid shells and no password allow unauthenticated login",
                    severity=Severity.CRITICAL,
                    evidence="\n".join(risky_users[:10]),
                    remediation="Set passwords or lock accounts: passwd -l <user> or usermod -s /sbin/nologin <user>",
                )

        # Check for system accounts (UID < 1000) with login shells
        sys_with_shell = session.execute(
            "awk -F: '$3 < 1000 && $3 != 0 && $7 != \"/sbin/nologin\" && $7 != \"/usr/sbin/nologin\" "
            "&& $7 != \"/bin/false\" && $7 != \"/usr/bin/false\" {print $1, $3, $7}' "
            "/etc/passwd 2>/dev/null"
        )
        if sys_with_shell.success and sys_with_shell.output.strip():
            self.add_finding(
                title="System accounts with interactive login shells",
                description="System accounts (UID < 1000) should use /sbin/nologin — interactive shells are a risk",
                severity=Severity.HIGH,
                evidence=sys_with_shell.output.strip()[:500],
                remediation="Set nologin shell: usermod -s /sbin/nologin <service_account>",
            )

    def _check_domain_accounts(self, session: Session) -> None:
        """T1136.002: Check for domain join configuration and unmanaged accounts."""
        # Check if SSSD is configured (domain-joined)
        sssd_check = session.execute(
            "systemctl is-active sssd 2>/dev/null"
        )
        winbind_check = session.execute(
            "systemctl is-active winbind 2>/dev/null"
        )

        is_domain_joined = False
        if sssd_check.success and sssd_check.output.strip() == "active":
            is_domain_joined = True
        if winbind_check.success and winbind_check.output.strip() == "active":
            is_domain_joined = True

        if is_domain_joined:
            # Check for local accounts that are not managed by SSSD/Winbind
            local_users = session.execute(
                "awk -F: '$3 >= 1000 && $3 < 65534 {print $1}' /etc/passwd 2>/dev/null"
            )
            if local_users.success and local_users.output.strip():
                self.add_finding(
                    title="Local accounts on domain-joined system",
                    description="Domain-joined systems should use centralized auth — local accounts may bypass domain policies",
                    severity=Severity.HIGH,
                    evidence=local_users.output.strip()[:300],
                    remediation="Migrate local accounts to domain management; disable or remove local accounts",
                )

            # Check SSSD/realm configuration
            realm_info = session.execute("realm list 2>/dev/null")
            if realm_info.success and realm_info.output.strip():
                self.add_finding(
                    title="Domain join configuration",
                    description="System is domain-joined; verify domain trust and access policies",
                    severity=Severity.INFO,
                    evidence=realm_info.output.strip()[:500],
                    remediation="Review realm configuration; ensure permit/deny policies are correct",
                )

    def _check_useradd_defaults(self, session: Session) -> None:
        """Check useradd defaults for insecure settings."""
        useradd_defaults = session.execute(
            "cat /etc/default/useradd 2>/dev/null"
        )
        if useradd_defaults.success and useradd_defaults.output.strip():
            output = useradd_defaults.output
            # Check if default shell is a login shell
            if "SHELL=/bin/bash" in output or "SHELL=/bin/sh" in output:
                # Check INACTIVE setting (account expiry after password expiry)
                if "INACTIVE=-1" in output or "INACTIVE=" not in output:
                    self.add_finding(
                        title="useradd INACTIVE not set or disabled",
                        description="Accounts are not automatically disabled after password expiry",
                        severity=Severity.MEDIUM,
                        evidence=output.strip()[:300],
                        remediation="Set INACTIVE=30 in /etc/default/useradd to disable accounts 30 days after password expiry",
                    )

    def _check_login_defs(self, session: Session) -> None:
        """Check /etc/login.defs for password aging policies."""
        login_defs = session.execute(
            "grep -E '^(PASS_MAX_DAYS|PASS_MIN_DAYS|PASS_MIN_LEN|PASS_WARN_AGE|LOGIN_RETRIES|ENCRYPT_METHOD)' "
            "/etc/login.defs 2>/dev/null"
        )
        if login_defs.success and login_defs.output.strip():
            issues = []
            for line in login_defs.output.strip().splitlines():
                parts = line.split()
                if len(parts) >= 2:
                    key, val = parts[0], parts[1]
                    if key == "PASS_MAX_DAYS" and int(val) > 90:
                        issues.append(f"PASS_MAX_DAYS={val} (recommended: 90 or less)")
                    elif key == "PASS_MIN_DAYS" and int(val) < 1:
                        issues.append(f"PASS_MIN_DAYS={val} (recommended: 1 or more)")
                    elif key == "PASS_MIN_LEN" and int(val) < 12:
                        issues.append(f"PASS_MIN_LEN={val} (recommended: 12 or more)")
                    elif key == "PASS_WARN_AGE" and int(val) < 7:
                        issues.append(f"PASS_WARN_AGE={val} (recommended: 7 or more)")

            if issues:
                self.add_finding(
                    title="Weak password aging policies in login.defs",
                    description="Password policies do not meet security baselines",
                    severity=Severity.MEDIUM,
                    evidence="\n".join(issues),
                    remediation="Update /etc/login.defs: PASS_MAX_DAYS=90, PASS_MIN_DAYS=1, PASS_MIN_LEN=12, PASS_WARN_AGE=7",
                )
        else:
            self.add_finding(
                title="Unable to read password policies from login.defs",
                description="Could not verify password aging policies",
                severity=Severity.LOW,
                evidence="Failed to read /etc/login.defs",
                remediation="Ensure /etc/login.defs is readable and properly configured",
            )

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Monitor /etc/passwd and /etc/shadow with auditd: -w /etc/passwd -p wa -k account_changes",
            "Enforce password policies via /etc/login.defs and /etc/security/pwquality.conf",
            "Set all system/service accounts to /sbin/nologin shell: usermod -s /sbin/nologin <account>",
            "Use centralized identity management (IdM/FreeIPA or AD via SSSD) instead of local accounts",
            "Set INACTIVE=30 in /etc/default/useradd to auto-disable stale accounts",
        ]

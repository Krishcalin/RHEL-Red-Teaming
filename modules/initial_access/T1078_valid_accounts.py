"""T1078 — Valid Accounts.

Checks for default/vendor accounts and password policy on RHEL systems.
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class ValidAccountsCheck(BaseModule):
    TECHNIQUE_ID = "T1078"
    TECHNIQUE_NAME = "Valid Accounts"
    TACTIC = Tactic.INITIAL_ACCESS
    SEVERITY = Severity.HIGH
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    DEFAULT_ACCOUNTS = ["admin", "guest", "test", "user", "oracle",
                        "postgres", "mysql", "ftp", "operator"]

    def check(self, session: Session) -> ModuleResult:
        self._check_default_accounts(session)
        self._check_password_aging(session)
        self._check_inactive_accounts(session)
        self._check_empty_passwords(session)

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def _check_default_accounts(self, session: Session) -> None:
        for acct in self.DEFAULT_ACCOUNTS:
            result = session.execute(f"id {acct} 2>/dev/null")
            if result.success and result.output.strip():
                shell = session.execute(f"getent passwd {acct} 2>/dev/null | cut -d: -f7")
                if shell.success and shell.output.strip() not in ("/sbin/nologin", "/bin/false", "/usr/sbin/nologin"):
                    self.add_finding(
                        title=f"Default account with login shell: {acct}",
                        description=f"Account '{acct}' exists with an interactive shell",
                        severity=Severity.HIGH,
                        evidence=result.output.strip()[:200],
                        remediation=f"Disable: usermod -s /sbin/nologin {acct} or userdel {acct}",
                    )

    def _check_password_aging(self, session: Session) -> None:
        result = session.execute("grep '^PASS_MAX_DAYS' /etc/login.defs 2>/dev/null")
        if result.success and result.output.strip():
            try:
                days = int(result.output.strip().split()[-1])
                if days > 365 or days == 99999:
                    self.add_finding(
                        title=f"Password max age is {days} days",
                        description="Passwords never expire or have very long lifetimes",
                        severity=Severity.MEDIUM,
                        evidence=result.output.strip(),
                        remediation="Set PASS_MAX_DAYS 90 in /etc/login.defs",
                    )
            except ValueError:
                pass

    def _check_inactive_accounts(self, session: Session) -> None:
        result = session.execute(
            "lastlog -b 90 2>/dev/null | grep -v 'Never logged in' | grep -v Username | wc -l"
        )
        inactive = session.execute(
            "lastlog 2>/dev/null | grep 'Never logged in' | wc -l"
        )
        if inactive.success and inactive.output.strip():
            try:
                count = int(inactive.output.strip())
                if count > 10:
                    self.add_finding(
                        title=f"{count} accounts never logged in",
                        description="Many inactive accounts increase the attack surface",
                        severity=Severity.LOW,
                        evidence=f"{count} accounts never logged in",
                        remediation="Disable or remove unused accounts",
                    )
            except ValueError:
                pass

    def _check_empty_passwords(self, session: Session) -> None:
        result = session.execute("awk -F: '($2==\"\" || $2==\"!\") {print $1}' /etc/shadow 2>/dev/null")
        if result.success and result.output.strip():
            accounts = result.output.strip().splitlines()
            interactive = []
            for acct in accounts:
                shell = session.execute(f"getent passwd {acct.strip()} 2>/dev/null | cut -d: -f7")
                if shell.success and shell.output.strip() not in ("/sbin/nologin", "/bin/false", "/usr/sbin/nologin"):
                    interactive.append(acct.strip())
            if interactive:
                self.add_finding(
                    title=f"Accounts with empty/no password: {', '.join(interactive)}",
                    description="Accounts without passwords can be accessed without credentials",
                    severity=Severity.CRITICAL,
                    evidence=", ".join(interactive),
                    remediation="Set passwords or lock accounts: passwd -l <user>",
                )

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Disable or remove default and vendor accounts",
            "Set PASS_MAX_DAYS 90 for password expiration",
            "Lock or remove inactive accounts",
            "Ensure all interactive accounts have strong passwords",
        ]

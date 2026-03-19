"""T1078 — Valid Accounts.

Checks for default, domain, and local account privilege escalation paths.
Sub-techniques: T1078.001 (Default), T1078.002 (Domain), T1078.003 (Local).
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule

DEFAULT_ACCOUNTS = [
    "admin", "administrator", "test", "guest", "user", "demo",
    "oracle", "postgres", "mysql", "webmaster", "ftpuser",
    "operator", "backup", "nagios", "zabbix", "monitor",
]


class ValidAccountsCheck(BaseModule):
    TECHNIQUE_ID = "T1078"
    TECHNIQUE_NAME = "Valid Accounts"
    TACTIC = Tactic.PRIVILEGE_ESCALATION
    SEVERITY = Severity.MEDIUM
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        # T1078.001 — Default Accounts
        passwd = session.execute("cat /etc/passwd 2>/dev/null")
        if passwd.success:
            existing = set()
            for line in passwd.output.splitlines():
                if line and not line.startswith("#"):
                    existing.add(line.split(":")[0])

            found_defaults = [a for a in DEFAULT_ACCOUNTS if a in existing]
            if found_defaults:
                # Check which have login shells
                with_shell = []
                for acct in found_defaults:
                    for line in passwd.output.splitlines():
                        if line.startswith(f"{acct}:"):
                            parts = line.split(":")
                            if len(parts) >= 7 and parts[6] not in ("/sbin/nologin", "/bin/false", "/usr/sbin/nologin"):
                                with_shell.append(acct)

                if with_shell:
                    self.add_finding(
                        title=f"Default accounts with login shells: {', '.join(with_shell)}",
                        description="Common/default accounts with active login shells",
                        severity=Severity.HIGH,
                        evidence=f"Accounts with shells: {', '.join(with_shell)}",
                        remediation="Disable login: usermod -s /sbin/nologin <account>",
                    )
                elif found_defaults:
                    self.add_finding(
                        title=f"Default account names exist: {', '.join(found_defaults)}",
                        description="Accounts with common default names (shells disabled)",
                        severity=Severity.LOW,
                        evidence=f"Default accounts: {', '.join(found_defaults)}",
                    )

        # T1078.003 — Local Accounts
        # Check for accounts with empty passwords
        empty_pw = session.execute("awk -F: '($2 == \"\") {print $1}' /etc/shadow 2>/dev/null")
        if empty_pw.success and empty_pw.output.strip():
            accounts = [a.strip() for a in empty_pw.output.strip().splitlines() if a.strip()]
            if accounts:
                self.add_finding(
                    title=f"Accounts with empty passwords: {', '.join(accounts)}",
                    description="These accounts can be accessed without a password",
                    severity=Severity.CRITICAL,
                    evidence=", ".join(accounts),
                    remediation="Lock accounts: passwd -l <account>; or set a password",
                )

        # Check for accounts that never expire
        no_expire = session.execute(
            "awk -F: '$5 == \"\" || $5 == \"99999\" || $5 == \"-1\" {print $1}' /etc/shadow 2>/dev/null | head -15"
        )
        if no_expire.success and no_expire.output.strip():
            accounts = no_expire.output.strip().splitlines()
            shell_accounts = []
            if passwd.success:
                for acct in accounts:
                    for line in passwd.output.splitlines():
                        if line.startswith(f"{acct}:"):
                            parts = line.split(":")
                            if len(parts) >= 7 and parts[6] not in ("/sbin/nologin", "/bin/false", "/usr/sbin/nologin"):
                                shell_accounts.append(acct)
            if shell_accounts:
                self.add_finding(
                    title=f"Login accounts without password expiry: {len(shell_accounts)}",
                    description="Accounts with login shells that never require password changes",
                    severity=Severity.MEDIUM,
                    evidence=", ".join(shell_accounts[:15]),
                    remediation="Set password expiry: chage -M 90 <account>",
                )

        # T1078.002 — Domain Accounts
        sssd = session.execute("systemctl is-active sssd 2>/dev/null")
        if sssd.success and sssd.output.strip() == "active":
            # Check if domain admin accounts can log in
            ssh_allow = session.execute("grep -i 'AllowUsers\\|AllowGroups' /etc/ssh/sshd_config 2>/dev/null | grep -v '^#'")
            if not ssh_allow.success or not ssh_allow.output.strip():
                self.add_finding(
                    title="SSH does not restrict domain accounts",
                    description="No AllowUsers/AllowGroups in sshd_config — any domain user may SSH in",
                    severity=Severity.MEDIUM,
                    evidence="SSSD active; no SSH AllowUsers/AllowGroups",
                    remediation="Add AllowGroups with specific groups in /etc/ssh/sshd_config",
                )

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Disable login shells for default/service accounts",
            "Lock accounts with empty passwords",
            "Set password expiry (PASS_MAX_DAYS) for all login accounts",
            "Use AllowGroups in sshd_config to restrict SSH access",
            "Remove or rename default accounts",
        ]

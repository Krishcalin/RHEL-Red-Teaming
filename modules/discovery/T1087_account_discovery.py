"""T1087 — Account Discovery (Local + Domain).

Checks accessibility of local and domain account enumeration.
Sub-techniques: T1087.001 (Local Account), T1087.002 (Domain Account).
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class AccountDiscoveryCheck(BaseModule):
    TECHNIQUE_ID = "T1087"
    TECHNIQUE_NAME = "Account Discovery"
    TACTIC = Tactic.DISCOVERY
    SEVERITY = Severity.LOW
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        # T1087.001 — Local Account Discovery
        passwd = session.execute("cat /etc/passwd")
        if passwd.success:
            users = [
                line.split(":")[0]
                for line in passwd.output.splitlines()
                if line and not line.startswith("#")
            ]
            shell_users = []
            for line in passwd.output.splitlines():
                parts = line.split(":")
                if len(parts) >= 7 and parts[6] not in ("/sbin/nologin", "/bin/false", "/usr/sbin/nologin"):
                    shell_users.append(parts[0])

            self.add_finding(
                title="Local accounts enumerable via /etc/passwd",
                description=f"{len(users)} total accounts, {len(shell_users)} with login shells",
                severity=Severity.INFO,
                evidence=f"Login shell users: {', '.join(shell_users[:20])}",
                remediation="Restrict unnecessary login shells; use /sbin/nologin for service accounts",
            )

            # Check for UID 0 accounts beyond root
            uid0 = [
                line.split(":")[0]
                for line in passwd.output.splitlines()
                if line and len(line.split(":")) > 2 and line.split(":")[2] == "0" and line.split(":")[0] != "root"
            ]
            if uid0:
                self.add_finding(
                    title="Non-root accounts with UID 0",
                    description="Accounts other than root have UID 0, granting full privileges",
                    severity=Severity.CRITICAL,
                    evidence=f"UID 0 accounts: {', '.join(uid0)}",
                    remediation="Remove or reassign UID for non-root UID 0 accounts",
                )

        # Check getent for additional sources (LDAP/SSSD)
        getent = session.execute("getent passwd 2>/dev/null | wc -l")
        passwd_lines = len(passwd.output.splitlines()) if passwd.success else 0
        if getent.success and getent.output.strip().isdigit():
            getent_count = int(getent.output.strip())
            if getent_count > passwd_lines:
                self.add_finding(
                    title="Domain/directory accounts enumerable",
                    description=f"getent returns {getent_count} accounts vs {passwd_lines} in /etc/passwd",
                    severity=Severity.LOW,
                    evidence=f"Additional accounts from SSSD/LDAP/NIS: {getent_count - passwd_lines}",
                    remediation="Restrict SSSD enumerate = false in sssd.conf",
                )

        # T1087.002 — Domain Account Discovery
        # Check SSSD
        sssd = session.execute("systemctl is-active sssd 2>/dev/null")
        if sssd.success and sssd.output.strip() == "active":
            sssd_conf = session.execute("cat /etc/sssd/sssd.conf 2>/dev/null | grep -i enumerate")
            enum_enabled = sssd_conf.success and "true" in sssd_conf.output.lower()
            if enum_enabled:
                self.add_finding(
                    title="SSSD enumeration enabled",
                    description="SSSD is configured with enumerate = true, allowing full directory listing",
                    severity=Severity.MEDIUM,
                    evidence=sssd_conf.output.strip(),
                    remediation="Set enumerate = false in /etc/sssd/sssd.conf",
                )

        # Check for lastlog / last access
        last = session.execute("last -10 2>/dev/null")
        if last.success and last.output:
            self.add_finding(
                title="Login history accessible",
                description="Login history via 'last' command is readable",
                severity=Severity.INFO,
                evidence=last.output[:500],
                remediation="Restrict /var/log/wtmp permissions if needed",
            )

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Set enumerate = false in SSSD configuration",
            "Use /sbin/nologin for all service accounts",
            "Ensure no non-root accounts have UID 0",
            "Restrict /var/log/wtmp and /var/log/btmp permissions",
            "Limit shell access to authorized users only",
        ]

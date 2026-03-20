"""T1078 — Valid Accounts (Defense Evasion perspective).

Checks for default/vendor accounts, shared accounts, service accounts with
interactive login, accounts bypassing wheel group for su, password aging
issues, and failed login patterns on RHEL systems.
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class ValidAccountsEvasionCheck(BaseModule):
    TECHNIQUE_ID = "T1078"
    TECHNIQUE_NAME = "Valid Accounts"
    TACTIC = Tactic.DEFENSE_EVASION
    SEVERITY = Severity.HIGH
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        self._check_default_accounts(session)
        self._check_local_account_abuse(session)
        self._check_su_without_wheel(session)
        self._check_password_aging(session)
        self._check_failed_login_patterns(session)

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    # -- T1078.001 Default Accounts -------------------------------------------

    def _check_default_accounts(self, session: Session) -> None:
        # Common default/vendor accounts that should be disabled
        default_accounts = [
            "guest", "test", "oracle", "postgres", "mysql", "ftp",
            "admin", "user", "demo", "nagios", "zabbix", "ansible",
        ]
        for account in default_accounts:
            result = session.execute(f"getent passwd {account} 2>/dev/null || true")
            if result.success and result.output.strip():
                # Check if account is enabled (has a valid shell and is not locked)
                fields = result.output.strip().split(":")
                if len(fields) >= 7:
                    shell = fields[6]
                    nologin_shells = ["/sbin/nologin", "/bin/false", "/usr/sbin/nologin"]
                    if shell not in nologin_shells:
                        # Check if account is locked
                        locked = session.execute(f"passwd -S {account} 2>/dev/null || true")
                        is_locked = locked.success and ("LK" in locked.output or "L " in locked.output)
                        if not is_locked:
                            self.add_finding(
                                title=f"Default/vendor account enabled: {account}",
                                description=(
                                    f"The account '{account}' has an interactive shell ({shell}) "
                                    "and is not locked. Attackers commonly target default accounts "
                                    "to blend in with legitimate activity."
                                ),
                                severity=Severity.HIGH,
                                evidence=result.output.strip(),
                                remediation=f"Lock the account: usermod -L {account} -s /sbin/nologin",
                            )

    # -- T1078.003 Local Accounts ---------------------------------------------

    def _check_local_account_abuse(self, session: Session) -> None:
        # Check for accounts used outside normal hours via lastlog
        last_output = session.execute("last -n 50 2>/dev/null | head -50 || true")
        if last_output.success and last_output.output.strip():
            # Look for logins during unusual hours (00:00-05:59)
            unusual_logins = []
            for line in last_output.output.strip().splitlines():
                parts = line.split()
                # Try to find time field (HH:MM) and check if it's off-hours
                for part in parts:
                    if ":" in part and len(part) == 5:
                        try:
                            hour = int(part.split(":")[0])
                            if 0 <= hour < 6:
                                unusual_logins.append(line.strip())
                                break
                        except ValueError:
                            pass
            if unusual_logins:
                self.add_finding(
                    title=f"Off-hours logins detected ({len(unusual_logins)} sessions)",
                    description="Login sessions occurred between 00:00-05:59, which may indicate unauthorized access using compromised credentials",
                    severity=Severity.MEDIUM,
                    evidence="\n".join(unusual_logins[:10]),
                    remediation="Investigate off-hours logins; consider implementing time-based access controls via pam_time",
                )

        # Check for shared accounts (multiple UIDs with UID 0)
        uid0 = session.execute("awk -F: '$3 == 0 {print $1}' /etc/passwd 2>/dev/null")
        if uid0.success and uid0.output.strip():
            accounts = uid0.output.strip().splitlines()
            if len(accounts) > 1:
                self.add_finding(
                    title=f"Multiple accounts with UID 0: {', '.join(accounts)}",
                    description="Multiple accounts share UID 0 (root privileges), making it impossible to distinguish which account performed actions",
                    severity=Severity.CRITICAL,
                    evidence=uid0.output.strip(),
                    remediation="Remove duplicate UID 0 accounts; use sudo for privilege escalation instead",
                )

        # Check for service accounts with interactive login
        service_accounts = session.execute(
            "awk -F: '$3 >= 1 && $3 < 1000 && $7 !~ /nologin|false/ {print $1 \":\" $7}' /etc/passwd 2>/dev/null"
        )
        if service_accounts.success and service_accounts.output.strip():
            lines = service_accounts.output.strip().splitlines()
            if lines:
                self.add_finding(
                    title=f"Service accounts with interactive shells ({len(lines)} found)",
                    description="System/service accounts have interactive login shells, allowing attackers to use them for stealthy access",
                    severity=Severity.HIGH,
                    evidence="\n".join(lines[:10]),
                    remediation="Set service account shells to /sbin/nologin: usermod -s /sbin/nologin <account>",
                )

    # -- Accounts that can su to root without wheel group ---------------------

    def _check_su_without_wheel(self, session: Session) -> None:
        # Check if pam_wheel is enforced for su
        pam_su = session.execute("grep -n 'pam_wheel' /etc/pam.d/su 2>/dev/null || true")
        if pam_su.success:
            output = pam_su.output.strip()
            if not output:
                self.add_finding(
                    title="pam_wheel not configured for su",
                    description="Any user can attempt su to root without being in the wheel group, enabling credential-based evasion",
                    severity=Severity.HIGH,
                    evidence="No pam_wheel entry in /etc/pam.d/su",
                    remediation="Add 'auth required pam_wheel.so use_uid' to /etc/pam.d/su",
                )
            elif all(line.strip().startswith("#") for line in output.splitlines() if "pam_wheel" in line):
                self.add_finding(
                    title="pam_wheel is commented out in /etc/pam.d/su",
                    description="The pam_wheel restriction for su is disabled (commented out), allowing unrestricted su access",
                    severity=Severity.HIGH,
                    evidence=output,
                    remediation="Uncomment the pam_wheel.so line in /etc/pam.d/su",
                )

    # -- Password aging (chage -l) --------------------------------------------

    def _check_password_aging(self, session: Session) -> None:
        # Get all human accounts (UID >= 1000) and check password aging
        users = session.execute(
            "awk -F: '$3 >= 1000 && $7 !~ /nologin|false/ {print $1}' /etc/passwd 2>/dev/null"
        )
        if not users.success or not users.output.strip():
            return

        no_aging = []
        for user in users.output.strip().splitlines()[:20]:
            user = user.strip()
            if not user:
                continue
            chage = session.execute(f"chage -l {user} 2>/dev/null || true")
            if chage.success and chage.output.strip():
                if "Maximum number of days between password change" in chage.output:
                    for line in chage.output.splitlines():
                        if "Maximum" in line and ("99999" in line or "-1" in line or "never" in line.lower()):
                            no_aging.append(user)
                            break

        if no_aging:
            self.add_finding(
                title=f"Accounts with no password expiration ({len(no_aging)} found)",
                description=(
                    "Accounts have password aging disabled (max days = 99999 or never). "
                    "Compromised credentials remain valid indefinitely, making detection harder."
                ),
                severity=Severity.MEDIUM,
                evidence=f"Accounts: {', '.join(no_aging[:15])}",
                remediation="Set password aging: chage -M 90 -m 7 -W 14 <username>",
            )

    # -- Failed login attempt patterns ----------------------------------------

    def _check_failed_login_patterns(self, session: Session) -> None:
        # Check lastb for concentrated failures on specific accounts
        lastb = session.execute("lastb -n 100 2>/dev/null | awk '{print $1}' | sort | uniq -c | sort -rn | head -10 || true")
        if lastb.success and lastb.output.strip():
            for line in lastb.output.strip().splitlines():
                parts = line.strip().split()
                if len(parts) >= 2:
                    try:
                        count = int(parts[0])
                        account = parts[1]
                        if count >= 10:
                            self.add_finding(
                                title=f"High failed login count for account: {account} ({count} attempts)",
                                description=(
                                    f"Account '{account}' has {count} recent failed login attempts, "
                                    "which may indicate brute force activity or credential testing"
                                ),
                                severity=Severity.MEDIUM,
                                evidence=line.strip(),
                                remediation="Investigate the source of failed logins; ensure pam_faillock is configured for account lockout",
                            )
                    except ValueError:
                        pass

        # Check for failed root logins specifically
        root_fails = session.execute("lastb -n 100 2>/dev/null | grep '^root ' | wc -l || true")
        if root_fails.success and root_fails.output.strip():
            try:
                count = int(root_fails.output.strip())
                if count >= 5:
                    self.add_finding(
                        title=f"Root account targeted in failed logins ({count} attempts)",
                        description="The root account has multiple failed login attempts, indicating targeted brute force",
                        severity=Severity.HIGH,
                        evidence=f"Root failed logins: {count}",
                        remediation="Disable direct root login via SSH (PermitRootLogin no) and use sudo instead",
                    )
            except ValueError:
                pass

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Disable or lock all default/vendor accounts: usermod -L -s /sbin/nologin <account>",
            "Enforce wheel group for su access: enable pam_wheel.so in /etc/pam.d/su",
            "Set password aging on all human accounts: chage -M 90 -m 7 -W 14 <username>",
            "Disable direct root SSH login: set PermitRootLogin no in /etc/ssh/sshd_config",
            "Implement time-based access controls with pam_time for sensitive accounts",
        ]

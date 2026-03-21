"""T1564.002 — Hidden Users.

Checks for UID manipulation and hidden user accounts that evade
standard enumeration on RHEL systems.
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class HiddenUsersCheck(BaseModule):
    TECHNIQUE_ID = "T1564.002"
    TECHNIQUE_NAME = "Hidden Users"
    TACTIC = Tactic.DEFENSE_EVASION
    SEVERITY = Severity.HIGH
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        self._check_uid_zero(session)
        self._check_uid_manipulation(session)
        self._check_nologin_with_keys(session)

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def _check_uid_zero(self, session: Session) -> None:
        result = session.execute("awk -F: '$3==0 {print $1}' /etc/passwd 2>/dev/null")
        if result.success and result.output.strip():
            uid0_users = result.output.strip().splitlines()
            non_root = [u for u in uid0_users if u.strip() != "root"]
            if non_root:
                self.add_finding(
                    title=f"Non-root accounts with UID 0: {', '.join(non_root)}",
                    description="Accounts with UID 0 have root privileges — hidden admin accounts",
                    severity=Severity.CRITICAL,
                    evidence=", ".join(non_root),
                    remediation="Remove unauthorized UID 0 accounts: userdel <account>",
                )

    def _check_uid_manipulation(self, session: Session) -> None:
        # Users with UIDs below the system threshold but not in known system accounts
        result = session.execute(
            "awk -F: '$3>=1000 && $3<60000 && $7!=\"/sbin/nologin\" && $7!=\"/bin/false\" && $7!=\"/usr/sbin/nologin\" {print $1\":\"$3}' /etc/passwd 2>/dev/null"
        )
        if result.success and result.output.strip():
            users = result.output.strip().splitlines()
            # Check for duplicate UIDs (hiding behind existing users)
            uids = {}
            for entry in users:
                parts = entry.split(":")
                if len(parts) == 2:
                    uid = parts[1]
                    uids.setdefault(uid, []).append(parts[0])
            for uid, names in uids.items():
                if len(names) > 1:
                    self.add_finding(
                        title=f"Duplicate UID {uid}: {', '.join(names)}",
                        description="Multiple accounts share the same UID — one may be a hidden account",
                        severity=Severity.HIGH,
                        evidence=f"UID {uid} shared by: {', '.join(names)}",
                        remediation="Investigate and remove duplicate UID accounts",
                    )

    def _check_nologin_with_keys(self, session: Session) -> None:
        result = session.execute(
            "awk -F: '$7==\"/sbin/nologin\" || $7==\"/bin/false\" || $7==\"/usr/sbin/nologin\" {print $1\":\"$6}' /etc/passwd 2>/dev/null"
        )
        if result.success and result.output.strip():
            for entry in result.output.strip().splitlines():
                parts = entry.split(":")
                if len(parts) == 2:
                    user, home = parts
                    keys = session.execute(f"test -f {home}/.ssh/authorized_keys && echo exists 2>/dev/null")
                    if keys.success and "exists" in keys.output:
                        self.add_finding(
                            title=f"Service account with SSH keys: {user}",
                            description=f"Account {user} has nologin shell but SSH authorized_keys — potential backdoor",
                            severity=Severity.HIGH,
                            evidence=f"{user} (nologin) has {home}/.ssh/authorized_keys",
                            remediation=f"Remove authorized_keys from {home}/.ssh/ if SSH is not needed",
                        )

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Ensure only root has UID 0",
            "Check for duplicate UIDs regularly",
            "Remove SSH keys from service accounts with nologin shells",
            "Monitor /etc/passwd changes with auditd",
        ]

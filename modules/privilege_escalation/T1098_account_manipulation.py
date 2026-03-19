"""T1098 — Account Manipulation.

Checks for SSH authorized_keys and group manipulation escalation.
Sub-techniques: T1098.004 (SSH Authorized Keys), T1098.007 (Additional Groups).
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class AccountManipulationCheck(BaseModule):
    TECHNIQUE_ID = "T1098"
    TECHNIQUE_NAME = "Account Manipulation"
    TACTIC = Tactic.PRIVILEGE_ESCALATION
    SEVERITY = Severity.HIGH
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        # T1098.004 — SSH Authorized Keys
        # Check root authorized_keys
        root_auth = session.execute("test -r /root/.ssh/authorized_keys && wc -l /root/.ssh/authorized_keys 2>/dev/null")
        if root_auth.success and root_auth.output.strip():
            count = root_auth.output.strip().split()[0]
            self.add_finding(
                title=f"Root authorized_keys accessible ({count} keys)",
                description="SSH keys authorized for root access are readable",
                severity=Severity.HIGH,
                evidence=root_auth.output.strip(),
                remediation="Restrict /root/.ssh to 700; authorized_keys to 600",
            )

        # Check if current user can write to any authorized_keys
        auth_writable = session.execute(
            "find /home /root -name 'authorized_keys' -writable 2>/dev/null | head -5"
        )
        if auth_writable.success and auth_writable.output.strip():
            self.add_finding(
                title="Writable authorized_keys files found",
                description="Current user can inject SSH keys for other accounts",
                severity=Severity.CRITICAL,
                evidence=auth_writable.output.strip(),
                remediation="Set authorized_keys to 600 owned by the account user",
            )

        # Check SSH AuthorizedKeysFile directive
        ssh_authkeys = session.execute(
            "grep -i 'AuthorizedKeysFile' /etc/ssh/sshd_config 2>/dev/null | grep -v '^#'"
        )
        if ssh_authkeys.success and ssh_authkeys.output.strip():
            if "/etc/" in ssh_authkeys.output or "%h" not in ssh_authkeys.output:
                self.add_finding(
                    title="Non-standard AuthorizedKeysFile path",
                    description="SSH authorized keys file may be in a centrally managed location",
                    severity=Severity.INFO,
                    evidence=ssh_authkeys.output.strip(),
                )

        # T1098.007 — Additional Groups
        # Check if current user can modify group memberships
        usermod = session.execute("which usermod 2>/dev/null && test -x $(which usermod 2>/dev/null) && echo executable")
        groupadd = session.execute("which groupadd 2>/dev/null && test -x $(which groupadd 2>/dev/null) && echo executable")

        # Check /etc/group writable
        group_writable = session.execute("test -w /etc/group && echo writable 2>/dev/null")
        if group_writable.success and group_writable.output.strip() == "writable":
            self.add_finding(
                title="/etc/group is writable!",
                description="Current user can add themselves to privileged groups (wheel, sudo, docker)",
                severity=Severity.CRITICAL,
                evidence="/etc/group is writable",
                remediation="chmod 644 /etc/group; chown root:root",
            )

        # Check /etc/passwd writable
        passwd_writable = session.execute("test -w /etc/passwd && echo writable 2>/dev/null")
        if passwd_writable.success and passwd_writable.output.strip() == "writable":
            self.add_finding(
                title="/etc/passwd is writable!",
                description="Current user can add accounts or change UIDs — instant root escalation",
                severity=Severity.CRITICAL,
                evidence="/etc/passwd is writable",
                remediation="chmod 644 /etc/passwd; chown root:root",
            )

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Set authorized_keys to 600 owned by the user",
            "Set .ssh directories to 700",
            "Set /etc/passwd and /etc/group to 644 root:root",
            "Monitor authorized_keys changes with auditd",
            "Use centralized SSH key management (IPA, LDAP)",
        ]

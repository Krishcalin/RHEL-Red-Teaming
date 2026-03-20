"""T1098 — Account Manipulation.

Checks for persistence via SSH authorized keys manipulation and
unauthorized additions to privileged groups.
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class AccountManipulationCheck(BaseModule):
    TECHNIQUE_ID = "T1098"
    TECHNIQUE_NAME = "Account Manipulation"
    TACTIC = Tactic.PERSISTENCE
    SEVERITY = Severity.HIGH
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    PRIVILEGED_GROUPS = ["wheel", "sudo", "root", "docker", "adm", "systemd-journal"]

    def check(self, session: Session) -> ModuleResult:
        self._check_ssh_authorized_keys(session)
        self._check_privileged_groups(session)

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def _check_ssh_authorized_keys(self, session: Session) -> None:
        """T1098.004: Check SSH authorized keys for suspicious entries."""
        # Find all authorized_keys files
        auth_keys_files = session.execute(
            "find /root /home -name 'authorized_keys' -o -name 'authorized_keys2' 2>/dev/null | head -20"
        )
        if auth_keys_files.success and auth_keys_files.output.strip():
            for keyfile in auth_keys_files.output.strip().splitlines():
                keyfile = keyfile.strip()
                if not keyfile:
                    continue

                # Check file permissions (should be 600 or 644)
                perms = session.execute(f"stat -c '%a %U:%G' '{keyfile}' 2>/dev/null")
                if perms.success and perms.output.strip():
                    perm_val = perms.output.strip().split()[0]
                    if perm_val not in ("600", "644", "400"):
                        self.add_finding(
                            title=f"Insecure permissions on {keyfile}",
                            description=f"authorized_keys has permissions {perm_val} (expected 600)",
                            severity=Severity.HIGH,
                            evidence=perms.output.strip(),
                            remediation=f"Fix: chmod 600 '{keyfile}'",
                        )

                # Check for keys without "from=" restriction
                unrestricted = session.execute(
                    f"grep -c '^[^#]' '{keyfile}' 2>/dev/null"
                )
                restricted = session.execute(
                    f"grep -c '^from=' '{keyfile}' 2>/dev/null"
                )
                if unrestricted.success and restricted.success:
                    total = int(unrestricted.output.strip() or "0")
                    with_from = int(restricted.output.strip() or "0")
                    unrestricted_count = total - with_from
                    if unrestricted_count > 0:
                        self.add_finding(
                            title=f"SSH keys without from= restriction in {keyfile}",
                            description=f"{unrestricted_count} of {total} keys lack source IP restrictions",
                            severity=Severity.MEDIUM,
                            evidence=f"Total keys: {total}, Without from= restriction: {unrestricted_count}",
                            remediation=f"Add from= option to limit key usage by source IP in {keyfile}",
                        )

                # Count keys and flag if unusually many
                if unrestricted.success:
                    total = int(unrestricted.output.strip() or "0")
                    if total > 5:
                        key_list = session.execute(
                            f"awk '{{print NR, $1, $NF}}' '{keyfile}' 2>/dev/null | head -10"
                        )
                        self.add_finding(
                            title=f"Large number of SSH keys in {keyfile}: {total}",
                            description="An unusually high number of authorized keys may indicate unauthorized access",
                            severity=Severity.HIGH,
                            evidence=key_list.output.strip() if key_list.success else f"{total} keys found",
                            remediation=f"Audit all keys in {keyfile}; remove unauthorized entries",
                        )

        # Check for authorized_keys in non-standard locations
        nonstandard = session.execute(
            "find / -name 'authorized_keys' -not -path '*/home/*' -not -path '/root/*' "
            "-not -path '*/proc/*' -not -path '*/sys/*' 2>/dev/null | head -5"
        )
        if nonstandard.success and nonstandard.output.strip():
            self.add_finding(
                title="authorized_keys in non-standard locations",
                description="SSH keys found outside expected home directories may indicate persistence via AuthorizedKeysFile override",
                severity=Severity.CRITICAL,
                evidence=nonstandard.output.strip(),
                remediation="Check sshd_config AuthorizedKeysFile; remove unauthorized key files",
            )

        # Check sshd_config for AuthorizedKeysFile override
        authkeys_config = session.execute(
            "grep -i 'AuthorizedKeysFile' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null "
            "| grep -v '^#' | head -5"
        )
        if authkeys_config.success and authkeys_config.output.strip():
            if ".ssh/authorized_keys" not in authkeys_config.output:
                self.add_finding(
                    title="Non-default AuthorizedKeysFile in sshd_config",
                    description="SSH is configured to read authorized keys from a non-standard location",
                    severity=Severity.HIGH,
                    evidence=authkeys_config.output.strip(),
                    remediation="Verify AuthorizedKeysFile setting is intentional; reset to default if unauthorized",
                )

    def _check_privileged_groups(self, session: Session) -> None:
        """T1098.007: Check for unauthorized members of privileged groups."""
        for group in self.PRIVILEGED_GROUPS:
            members = session.execute(
                f"getent group {group} 2>/dev/null"
            )
            if members.success and members.output.strip():
                parts = members.output.strip().split(":")
                if len(parts) >= 4 and parts[3]:
                    member_list = parts[3]
                    self.add_finding(
                        title=f"Members of privileged group '{group}': {member_list}",
                        description=f"Users in group '{group}' have elevated privileges; verify all members are authorized",
                        severity=Severity.MEDIUM,
                        evidence=members.output.strip(),
                        remediation=f"Audit membership of '{group}'; remove unauthorized users with gpasswd -d <user> {group}",
                    )

        # Check for users with GID 0
        gid0_users = session.execute(
            "awk -F: '$4 == 0 && $1 != \"root\"' /etc/passwd 2>/dev/null"
        )
        if gid0_users.success and gid0_users.output.strip():
            self.add_finding(
                title="Non-root users with GID 0",
                description="Users with primary group ID 0 have root group privileges",
                severity=Severity.CRITICAL,
                evidence=gid0_users.output.strip(),
                remediation="Change GID for non-root users: usermod -g <appropriate_group> <user>",
            )

        # Check /etc/group for unexpected changes (recently modified)
        group_modified = session.execute(
            "find /etc/group -mtime -7 2>/dev/null && echo 'RECENTLY_MODIFIED'"
        )
        if group_modified.success and "RECENTLY_MODIFIED" in group_modified.output:
            self.add_finding(
                title="/etc/group recently modified",
                description="Group file modified in the last 7 days — check for unauthorized privilege grants",
                severity=Severity.MEDIUM,
                evidence="File /etc/group modified within last 7 days",
                remediation="Review /etc/group changes; monitor with auditd: -w /etc/group -p wa -k group_changes",
            )

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Monitor authorized_keys files with auditd: -w /root/.ssh/authorized_keys -p wa -k ssh_keys",
            "Enforce strict permissions on .ssh directories (700) and authorized_keys files (600)",
            "Use AllowGroups/AllowUsers in sshd_config to restrict SSH access to authorized accounts",
            "Regularly audit privileged group membership (wheel, docker, root) and compare against approved lists",
            "Deploy centralized key management (e.g., SSSD with IPA) instead of local authorized_keys files",
        ]

"""T1083 — File and Directory Discovery.

Checks for sensitive file accessibility and world-readable paths.
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule

SENSITIVE_FILES = [
    ("/etc/shadow", "Password hashes", Severity.CRITICAL),
    ("/etc/gshadow", "Group password hashes", Severity.HIGH),
    ("/etc/sudoers", "Sudo configuration", Severity.HIGH),
    ("/etc/ssh/sshd_config", "SSH server configuration", Severity.MEDIUM),
    ("/etc/sssd/sssd.conf", "SSSD / directory config", Severity.HIGH),
    ("/etc/krb5.keytab", "Kerberos keytab", Severity.CRITICAL),
    ("/root/.ssh/id_rsa", "Root SSH private key", Severity.CRITICAL),
    ("/root/.ssh/authorized_keys", "Root authorized keys", Severity.HIGH),
    ("/root/.bash_history", "Root command history", Severity.MEDIUM),
    ("/etc/openldap/ldap.conf", "LDAP client configuration", Severity.MEDIUM),
    ("/var/log/secure", "Security log", Severity.MEDIUM),
    ("/var/log/audit/audit.log", "Audit log", Severity.MEDIUM),
]

SENSITIVE_DIRS = [
    "/tmp",
    "/var/tmp",
    "/dev/shm",
    "/var/spool/cron",
    "/etc/cron.d",
]


class FileDiscoveryCheck(BaseModule):
    TECHNIQUE_ID = "T1083"
    TECHNIQUE_NAME = "File and Directory Discovery"
    TACTIC = Tactic.DISCOVERY
    SEVERITY = Severity.MEDIUM
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        # Check sensitive file readability
        for path, desc, severity in SENSITIVE_FILES:
            result = session.execute(f"test -r {path} && echo readable || echo denied")
            if result.success and result.output.strip() == "readable":
                perms = session.execute(f"ls -la {path} 2>/dev/null")
                self.add_finding(
                    title=f"Sensitive file readable: {path}",
                    description=f"{desc} is readable by the current user",
                    severity=severity,
                    evidence=perms.output.strip() if perms.success else path,
                    remediation=f"Restrict permissions on {path}",
                )

        # Check world-writable directories
        for dir_path in SENSITIVE_DIRS:
            result = session.execute(f"test -d {dir_path} && stat -c '%a' {dir_path} 2>/dev/null")
            if result.success and result.output.strip():
                perms = result.output.strip()
                if perms.endswith("7") or perms.endswith("6") or perms.endswith("3") or perms.endswith("2"):
                    # Check sticky bit
                    sticky = session.execute(f"test -k {dir_path} && echo sticky || echo no-sticky")
                    has_sticky = sticky.success and sticky.output.strip() == "sticky"
                    if not has_sticky:
                        self.add_finding(
                            title=f"World-writable directory without sticky bit: {dir_path}",
                            description="Any user can create/delete files owned by others",
                            severity=Severity.HIGH,
                            evidence=f"{dir_path} permissions: {perms}",
                            remediation=f"Set sticky bit: chmod +t {dir_path}",
                        )

        # Find world-readable files in /etc with potential secrets
        find_result = session.execute(
            "find /etc -maxdepth 2 -type f \\( -name '*.conf' -o -name '*.cfg' -o -name '*.ini' \\) "
            "-readable -exec grep -li 'password\\|secret\\|key\\|token\\|credential' {} \\; 2>/dev/null | head -20"
        )
        if find_result.success and find_result.output.strip():
            files = find_result.output.strip().splitlines()
            self.add_finding(
                title=f"Config files with potential credentials: {len(files)}",
                description="Readable config files contain keywords suggesting embedded credentials",
                severity=Severity.MEDIUM,
                evidence="\n".join(files[:15]),
                remediation="Review and restrict permissions on files containing credentials",
            )

        # Check for SUID/SGID files in unusual locations
        suid = session.execute(
            "find /home /tmp /var/tmp /opt -perm -4000 -type f 2>/dev/null | head -20"
        )
        if suid.success and suid.output.strip():
            self.add_finding(
                title="SUID files in non-standard locations",
                description="SUID binaries found outside /usr/bin, /usr/sbin — potential privilege escalation",
                severity=Severity.HIGH,
                evidence=suid.output.strip(),
                remediation="Remove SUID bit from non-essential binaries: chmod u-s <file>",
            )

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Restrict /etc/shadow, /etc/gshadow to root:shadow with 640 permissions",
            "Set sticky bit on all world-writable directories",
            "Remove SUID/SGID from unnecessary binaries",
            "Avoid storing credentials in plaintext config files",
            "Use SELinux file contexts to protect sensitive paths",
        ]

"""T1003.008 — /etc/passwd and /etc/shadow.

Checks shadow file access controls and password hash security
on RHEL systems.
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class ShadowFileCheck(BaseModule):
    TECHNIQUE_ID = "T1003.008"
    TECHNIQUE_NAME = "/etc/passwd and /etc/shadow"
    TACTIC = Tactic.CREDENTIAL_ACCESS
    SEVERITY = Severity.CRITICAL
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        self._check_shadow_permissions(session)
        self._check_shadow_readable(session)
        self._check_hash_algorithm(session)
        self._check_passwd_hashes(session)

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def _check_shadow_permissions(self, session: Session) -> None:
        for f, expected in [("/etc/shadow", "000"), ("/etc/shadow-", "000"),
                            ("/etc/gshadow", "000"), ("/etc/gshadow-", "000")]:
            result = session.execute(f"stat -c '%a %U %G' {f} 2>/dev/null")
            if result.success and result.output.strip():
                parts = result.output.strip().split()
                if len(parts) >= 3:
                    perms, owner, group = parts[0], parts[1], parts[2]
                    if int(perms) > int(expected) or owner != "root":
                        self.add_finding(
                            title=f"Insecure permissions on {f}: {perms} {owner}:{group}",
                            description=f"{f} should be 000 root:root but is {perms} {owner}:{group}",
                            severity=Severity.CRITICAL,
                            evidence=result.output.strip(),
                            remediation=f"Fix: chmod {expected} {f}; chown root:root {f}",
                        )

    def _check_shadow_readable(self, session: Session) -> None:
        result = session.execute("test -r /etc/shadow && echo readable")
        if result.success and "readable" in result.output:
            whoami = session.execute("whoami 2>/dev/null")
            user = whoami.output.strip() if whoami.success else "unknown"
            if user != "root":
                self.add_finding(
                    title=f"/etc/shadow is readable by non-root user ({user})",
                    description="Password hashes in /etc/shadow can be extracted for offline cracking",
                    severity=Severity.CRITICAL,
                    evidence=f"User {user} can read /etc/shadow",
                    remediation="Fix permissions: chmod 000 /etc/shadow",
                )

    def _check_hash_algorithm(self, session: Session) -> None:
        result = session.execute("grep '^ENCRYPT_METHOD' /etc/login.defs 2>/dev/null")
        if result.success and result.output.strip():
            method = result.output.strip().split()[-1] if result.output.strip().split() else ""
            weak = ["DES", "MD5", "SHA256"]
            if method.upper() in weak:
                self.add_finding(
                    title=f"Weak password hash algorithm: {method}",
                    description=f"ENCRYPT_METHOD is {method} — vulnerable to fast offline cracking",
                    severity=Severity.HIGH,
                    evidence=result.output.strip(),
                    remediation="Set ENCRYPT_METHOD SHA512 or yescrypt in /etc/login.defs",
                )

        # Check pam for algorithm
        pam = session.execute("grep 'pam_unix.so' /etc/pam.d/system-auth 2>/dev/null | grep password")
        if pam.success and pam.output.strip():
            if "sha512" not in pam.output and "yescrypt" not in pam.output:
                self.add_finding(
                    title="PAM not enforcing strong hash algorithm",
                    description="pam_unix.so password line does not specify sha512 or yescrypt",
                    severity=Severity.MEDIUM,
                    evidence=pam.output.strip()[:300],
                    remediation="Add sha512 or yescrypt to pam_unix.so password line",
                )

    def _check_passwd_hashes(self, session: Session) -> None:
        result = session.execute("awk -F: '$2!=\"x\" && $2!=\"*\" && $2!=\"!\" && $2!=\"!!\" && $2!=\"\" {print $1}' /etc/passwd 2>/dev/null")
        if result.success and result.output.strip():
            users = result.output.strip().splitlines()
            self.add_finding(
                title=f"Password hashes in /etc/passwd: {', '.join(users)}",
                description="Hashes in /etc/passwd (not shadow) are world-readable",
                severity=Severity.CRITICAL,
                evidence=", ".join(users),
                remediation="Migrate hashes to /etc/shadow: pwconv",
            )

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Set /etc/shadow permissions to 000 owned by root",
            "Use SHA512 or yescrypt for password hashing",
            "Ensure all password hashes are in /etc/shadow (pwconv)",
            "Monitor shadow file access with auditd",
        ]

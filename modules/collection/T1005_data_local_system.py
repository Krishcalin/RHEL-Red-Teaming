"""T1005 — Data from Local System.

Checks sensitive file access on RHEL systems.
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class DataLocalSystemCheck(BaseModule):
    TECHNIQUE_ID = "T1005"
    TECHNIQUE_NAME = "Data from Local System"
    TACTIC = Tactic.COLLECTION
    SEVERITY = Severity.HIGH
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        self._check_sensitive_files(session)
        self._check_ssh_keys(session)
        self._check_history_files(session)
        self._check_config_passwords(session)

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def _check_sensitive_files(self, session: Session) -> None:
        files = {"/etc/shadow": "password hashes", "/etc/gshadow": "group passwords",
                 "/etc/sudoers": "sudo configuration"}
        for f, desc in files.items():
            result = session.execute(f"test -r {f} && echo readable")
            if result.success and "readable" in result.output:
                self.add_finding(
                    title=f"Sensitive file readable: {f}",
                    description=f"{f} ({desc}) is readable by current user",
                    severity=Severity.CRITICAL,
                    evidence=f"{f} is readable",
                    remediation=f"Fix permissions on {f}",
                )

    def _check_ssh_keys(self, session: Session) -> None:
        result = session.execute("find /home /root -name 'id_rsa' -o -name 'id_ed25519' -o -name 'id_ecdsa' 2>/dev/null | head -10")
        if result.success and result.output.strip():
            for key in result.output.strip().splitlines():
                readable = session.execute(f"test -r {key.strip()} && echo readable")
                if readable.success and "readable" in readable.output:
                    self.add_finding(
                        title=f"SSH private key readable: {key.strip()}",
                        description="SSH private keys can be used for lateral movement",
                        severity=Severity.HIGH,
                        evidence=key.strip(),
                        remediation="Set SSH key permissions to 600; restrict to owner only",
                    )

    def _check_history_files(self, session: Session) -> None:
        result = session.execute("find /home /root -name '.bash_history' -readable 2>/dev/null | head -10")
        if result.success and result.output.strip():
            count = len(result.output.strip().splitlines())
            self.add_finding(
                title=f"{count} readable .bash_history files",
                description="Bash history may contain passwords, tokens, and sensitive commands",
                severity=Severity.MEDIUM,
                evidence=result.output.strip()[:300],
                remediation="Set permissions: chmod 600 ~/.bash_history for all users",
            )

    def _check_config_passwords(self, session: Session) -> None:
        result = session.execute(
            "grep -rli 'password\\|passwd\\|secret\\|api_key\\|token' "
            "/etc/*.conf /opt/*/config* /var/www/*/config* 2>/dev/null | head -10"
        )
        if result.success and result.output.strip():
            count = len(result.output.strip().splitlines())
            self.add_finding(
                title=f"{count} config files may contain credentials",
                description="Configuration files with password/secret keywords found",
                severity=Severity.HIGH,
                evidence=result.output.strip()[:500],
                remediation="Move secrets to a vault; restrict config file permissions",
            )

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Enforce strict permissions on /etc/shadow, SSH keys, and history files",
            "Move credentials from config files to a secrets vault",
            "Monitor access to sensitive files with auditd",
            "Use SELinux to restrict file access by context",
        ]

"""T1486 — Data Encrypted for Impact.

Checks ransomware feasibility: encryption tool availability, backup isolation,
and file-system write access to critical data stores on RHEL systems.
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class DataEncryptedCheck(BaseModule):
    TECHNIQUE_ID = "T1486"
    TECHNIQUE_NAME = "Data Encrypted for Impact"
    TACTIC = Tactic.IMPACT
    SEVERITY = Severity.CRITICAL
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        self._check_encryption_tools(session)
        self._check_writable_data_dirs(session)
        self._check_backup_isolation(session)
        self._check_luks_status(session)

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def _check_encryption_tools(self, session: Session) -> None:
        tools = {"openssl": "general-purpose crypto", "gpg": "PGP encryption",
                 "ccrypt": "file encryption", "7z": "archive encryption"}
        for tool, desc in tools.items():
            result = session.execute(f"which {tool} 2>/dev/null")
            if result.success and result.output.strip():
                self.add_finding(
                    title=f"Encryption tool available: {tool}",
                    description=f"{tool} ({desc}) could be used to encrypt data for ransom",
                    severity=Severity.LOW,
                    evidence=result.output.strip(),
                    remediation=f"Monitor use of {tool} with auditd rules; restrict if not needed",
                )

    def _check_writable_data_dirs(self, session: Session) -> None:
        dirs = ["/var/lib/mysql", "/var/lib/pgsql", "/var/www",
                "/home", "/srv", "/opt"]
        for d in dirs:
            result = session.execute(f"test -d {d} && find {d} -maxdepth 0 -writable 2>/dev/null")
            if result.success and result.output.strip():
                self.add_finding(
                    title=f"Data directory writable: {d}",
                    description=f"Current user has write access to {d} — data could be encrypted in place",
                    severity=Severity.HIGH,
                    evidence=f"{d} is writable",
                    remediation=f"Restrict write permissions on {d}; use separate service accounts",
                )

    def _check_backup_isolation(self, session: Session) -> None:
        local_backups = session.execute(
            "find /var/backups /backup /tmp /root -name '*.tar*' -o -name '*.bak' "
            "-o -name '*.sql' 2>/dev/null | head -20"
        )
        if local_backups.success and local_backups.output.strip():
            self.add_finding(
                title="Local backup files found on same host",
                description="Backups stored locally can be encrypted alongside production data",
                severity=Severity.HIGH,
                evidence=local_backups.output.strip()[:500],
                remediation="Store backups on isolated, air-gapped, or immutable storage",
            )

    def _check_luks_status(self, session: Session) -> None:
        luks = session.execute("lsblk -o NAME,FSTYPE 2>/dev/null | grep -i crypt")
        if not luks.success or not luks.output.strip():
            self.add_finding(
                title="No LUKS-encrypted volumes detected",
                description="Disk-level encryption is not in use — data at rest is unprotected",
                severity=Severity.MEDIUM,
                evidence="No LUKS volumes in lsblk output",
                remediation="Consider LUKS encryption for sensitive volumes",
            )

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Maintain offline, immutable backups tested with regular restore drills",
            "Segment backup storage from production networks",
            "Monitor mass file-encryption patterns with auditd/AIDE",
            "Use application-level access controls to limit write access to data stores",
            "Deploy endpoint detection for ransomware behavioral patterns",
        ]

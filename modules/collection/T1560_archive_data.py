"""T1560 — Archive Collected Data.

Checks for archiving and compression tool availability on RHEL systems.
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class ArchiveDataCheck(BaseModule):
    TECHNIQUE_ID = "T1560"
    TECHNIQUE_NAME = "Archive Collected Data"
    TACTIC = Tactic.COLLECTION
    SEVERITY = Severity.LOW
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        self._check_archive_tools(session)
        self._check_encryption_archive(session)

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def _check_archive_tools(self, session: Session) -> None:
        tools = {"tar": "archive creation", "gzip": "compression",
                 "bzip2": "compression", "xz": "compression",
                 "zip": "archive+compression", "7z": "multi-format archive",
                 "rar": "RAR archive", "cpio": "copy archive"}
        for tool, desc in tools.items():
            result = session.execute(f"which {tool} 2>/dev/null")
            if result.success and result.output.strip():
                self.add_finding(
                    title=f"Archive tool available: {tool}",
                    description=f"{tool} ({desc}) can be used to bundle data for exfiltration",
                    severity=Severity.LOW,
                    evidence=result.output.strip(),
                    remediation=f"Monitor {tool} usage with auditd on sensitive directories",
                )

    def _check_encryption_archive(self, session: Session) -> None:
        result = session.execute("which gpg 2>/dev/null")
        if result.success and result.output.strip():
            self.add_finding(
                title="GPG available for encrypted archives",
                description="gpg can encrypt archived data before exfiltration, defeating DLP",
                severity=Severity.LOW,
                evidence=result.output.strip(),
                remediation="Monitor gpg usage with auditd rules",
            )

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Monitor archive tool usage with auditd rules",
            "Restrict archive creation in sensitive directories",
            "Deploy DLP to detect compressed data in transit",
        ]

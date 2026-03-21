"""T1074 — Data Staged.

Checks world-writable staging directories on RHEL systems.
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class DataStagedCheck(BaseModule):
    TECHNIQUE_ID = "T1074"
    TECHNIQUE_NAME = "Data Staged"
    TACTIC = Tactic.COLLECTION
    SEVERITY = Severity.MEDIUM
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        self._check_staging_dirs(session)
        self._check_large_files(session)
        self._check_hidden_dirs(session)

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def _check_staging_dirs(self, session: Session) -> None:
        dirs = {"/tmp": "temporary files", "/var/tmp": "persistent temp",
                "/dev/shm": "shared memory"}
        for d, desc in dirs.items():
            result = session.execute(f"test -w {d} && df -h {d} 2>/dev/null | tail -1")
            if result.success and result.output.strip():
                mount = session.execute(f"mount 2>/dev/null | grep ' {d} '")
                noexec = "noexec" in (mount.output if mount.success else "")
                if not noexec:
                    self.add_finding(
                        title=f"Staging dir writable+executable: {d}",
                        description=f"{d} ({desc}) is writable and allows execution — ideal for data staging",
                        severity=Severity.MEDIUM,
                        evidence=result.output.strip()[:200],
                        remediation=f"Mount {d} with noexec,nosuid,nodev",
                    )

    def _check_large_files(self, session: Session) -> None:
        result = session.execute("find /tmp /var/tmp /dev/shm -type f -size +10M 2>/dev/null | head -10")
        if result.success and result.output.strip():
            count = len(result.output.strip().splitlines())
            self.add_finding(
                title=f"{count} large files in staging directories",
                description="Large files in temp directories may indicate data staging for exfiltration",
                severity=Severity.MEDIUM,
                evidence=result.output.strip()[:500],
                remediation="Investigate large files in temp directories; implement tmpfiles.d cleanup",
            )

    def _check_hidden_dirs(self, session: Session) -> None:
        result = session.execute("find /tmp /var/tmp -maxdepth 2 -name '.*' -type d 2>/dev/null | head -10")
        if result.success and result.output.strip():
            count = len(result.output.strip().splitlines())
            self.add_finding(
                title=f"{count} hidden directories in staging areas",
                description="Hidden directories in temp areas may conceal staged data",
                severity=Severity.MEDIUM,
                evidence=result.output.strip()[:300],
                remediation="Investigate hidden directories; configure tmpfiles.d for cleanup",
            )

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Mount /tmp, /var/tmp, /dev/shm with noexec,nosuid,nodev",
            "Configure tmpfiles.d for automatic cleanup of old files",
            "Monitor for large file creation in staging directories",
            "Alert on hidden directory creation in temp paths",
        ]

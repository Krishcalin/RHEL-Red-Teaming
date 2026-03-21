"""T1104 — Multi-Stage Channels.

Checks for staged download feasibility and multi-stage C2 capabilities
on RHEL systems.
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class MultiStageCheck(BaseModule):
    TECHNIQUE_ID = "T1104"
    TECHNIQUE_NAME = "Multi-Stage Channels"
    TACTIC = Tactic.COMMAND_AND_CONTROL
    SEVERITY = Severity.MEDIUM
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        self._check_staging_directories(session)
        self._check_execution_paths(session)
        self._check_outbound_access(session)

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def _check_staging_directories(self, session: Session) -> None:
        dirs = ["/tmp", "/var/tmp", "/dev/shm", "/run/user"]
        for d in dirs:
            result = session.execute(f"test -d {d} && test -w {d} && echo writable")
            if result.success and "writable" in result.output:
                stat = session.execute(f"df -h {d} 2>/dev/null | tail -1")
                self.add_finding(
                    title=f"Writable staging directory: {d}",
                    description=f"{d} is writable — can be used to stage multi-stage payloads",
                    severity=Severity.LOW,
                    evidence=stat.output.strip()[:200] if stat.success else f"{d} is writable",
                    remediation=f"Mount {d} with noexec,nosuid; restrict with tmpfiles.d size limits",
                )

    def _check_execution_paths(self, session: Session) -> None:
        result = session.execute("echo $PATH")
        if result.success and result.output.strip():
            paths = result.output.strip().split(":")
            for p in paths:
                writable = session.execute(f"test -w {p} && echo writable 2>/dev/null")
                if writable.success and "writable" in writable.output:
                    self.add_finding(
                        title=f"Writable PATH directory: {p}",
                        description=f"User can write to {p} in PATH — planted executables will be found",
                        severity=Severity.HIGH,
                        evidence=f"{p} is writable and in PATH",
                        remediation=f"Remove write permissions from {p} for non-root users",
                    )

    def _check_outbound_access(self, session: Session) -> None:
        result = session.execute("ss -tuln 2>/dev/null | grep -c ESTAB")
        if result.success and result.output.strip():
            try:
                connections = int(result.output.strip())
                if connections > 50:
                    self.add_finding(
                        title=f"High number of established connections ({connections})",
                        description="Many outbound connections may mask multi-stage C2 traffic",
                        severity=Severity.INFO,
                        evidence=f"{connections} established connections",
                        remediation="Audit outbound connections; implement egress filtering",
                    )
            except ValueError:
                pass

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Mount staging directories with noexec,nosuid,nodev",
            "Ensure PATH directories are not writable by non-root users",
            "Implement egress filtering to restrict outbound connections",
            "Monitor for staged file creation in temporary directories",
        ]

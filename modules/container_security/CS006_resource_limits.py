"""CS006 — Container Resource Limits.

Checks CPU, memory, and PID limits on running containers
to prevent resource abuse on RHEL systems.
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class ResourceLimitsCheck(BaseModule):
    TECHNIQUE_ID = "CS006"
    TECHNIQUE_NAME = "Container Resource Limits"
    TACTIC = Tactic.IMPACT
    SEVERITY = Severity.MEDIUM
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        self._check_memory_limits(session)
        self._check_cpu_limits(session)
        self._check_pids_limit(session)

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def _check_memory_limits(self, session: Session) -> None:
        result = session.execute(
            "podman inspect --format '{{.Name}} {{.HostConfig.Memory}}' $(podman ps -q) 2>/dev/null || "
            "docker inspect --format '{{.Name}} {{.HostConfig.Memory}}' $(docker ps -q) 2>/dev/null"
        )
        if result.success and result.output.strip():
            for line in result.output.strip().splitlines():
                parts = line.split()
                if len(parts) >= 2 and parts[-1] == "0":
                    self.add_finding(
                        title=f"No memory limit on container: {parts[0]}",
                        description=f"{parts[0]} has no memory limit — can consume all host memory",
                        severity=Severity.MEDIUM,
                        evidence=line.strip(),
                        remediation=f"Set memory limit: --memory=512m on {parts[0]}",
                    )

    def _check_cpu_limits(self, session: Session) -> None:
        result = session.execute(
            "podman inspect --format '{{.Name}} {{.HostConfig.NanoCpus}}' $(podman ps -q) 2>/dev/null || "
            "docker inspect --format '{{.Name}} {{.HostConfig.NanoCpus}}' $(docker ps -q) 2>/dev/null"
        )
        if result.success and result.output.strip():
            for line in result.output.strip().splitlines():
                parts = line.split()
                if len(parts) >= 2 and parts[-1] == "0":
                    self.add_finding(
                        title=f"No CPU limit on container: {parts[0]}",
                        description=f"{parts[0]} has no CPU limit — can starve host and other containers",
                        severity=Severity.LOW,
                        evidence=line.strip(),
                        remediation=f"Set CPU limit: --cpus=1.0 on {parts[0]}",
                    )

    def _check_pids_limit(self, session: Session) -> None:
        result = session.execute(
            "podman inspect --format '{{.Name}} {{.HostConfig.PidsLimit}}' $(podman ps -q) 2>/dev/null || "
            "docker inspect --format '{{.Name}} {{.HostConfig.PidsLimit}}' $(docker ps -q) 2>/dev/null"
        )
        if result.success and result.output.strip():
            for line in result.output.strip().splitlines():
                parts = line.split()
                if len(parts) >= 2 and (parts[-1] == "0" or parts[-1] == "-1"):
                    self.add_finding(
                        title=f"No PID limit on container: {parts[0]}",
                        description=f"{parts[0]} has no PID limit — fork bombs can crash the host",
                        severity=Severity.MEDIUM,
                        evidence=line.strip(),
                        remediation=f"Set PID limit: --pids-limit=256 on {parts[0]}",
                    )

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Set memory limits on all containers (--memory)",
            "Set CPU limits on all containers (--cpus)",
            "Set PID limits to prevent fork bombs (--pids-limit)",
        ]

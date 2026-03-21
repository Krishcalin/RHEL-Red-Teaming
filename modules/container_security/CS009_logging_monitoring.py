"""CS009 — Container Logging and Monitoring.

Checks container log configuration, log driver settings, and
health check enforcement on RHEL systems.
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class LoggingMonitoringCheck(BaseModule):
    TECHNIQUE_ID = "CS009"
    TECHNIQUE_NAME = "Container Logging and Monitoring"
    TACTIC = Tactic.DISCOVERY
    SEVERITY = Severity.MEDIUM
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        self._check_log_driver(session)
        self._check_health_checks(session)
        self._check_log_size(session)

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def _check_log_driver(self, session: Session) -> None:
        result = session.execute(
            "podman inspect --format '{{.Name}} {{.HostConfig.LogConfig.Type}}' $(podman ps -q) 2>/dev/null || "
            "docker inspect --format '{{.Name}} {{.HostConfig.LogConfig.Type}}' $(docker ps -q) 2>/dev/null"
        )
        if result.success and result.output.strip():
            for line in result.output.strip().splitlines():
                if "none" in line.lower().split()[-1] if line.split() else "":
                    name = line.split()[0] if line.split() else "unknown"
                    self.add_finding(
                        title=f"Logging disabled for container: {name}",
                        description=f"{name} has log driver set to none — no audit trail",
                        severity=Severity.HIGH,
                        evidence=line.strip(),
                        remediation=f"Set log driver: --log-driver=journald or json-file",
                    )

    def _check_health_checks(self, session: Session) -> None:
        result = session.execute(
            "podman inspect --format '{{.Name}} {{.Config.Healthcheck}}' $(podman ps -q) 2>/dev/null || "
            "docker inspect --format '{{.Name}} {{.Config.Healthcheck}}' $(docker ps -q) 2>/dev/null"
        )
        if result.success and result.output.strip():
            no_health = 0
            for line in result.output.strip().splitlines():
                if "<nil>" in line or "{}" in line or "map[]" in line:
                    no_health += 1
            if no_health > 0:
                self.add_finding(
                    title=f"{no_health} containers without health checks",
                    description="Containers without HEALTHCHECK cannot be auto-restarted on failure",
                    severity=Severity.LOW,
                    evidence=f"{no_health} containers missing health checks",
                    remediation="Add HEALTHCHECK to Containerfile or use --health-cmd flag",
                )

    def _check_log_size(self, session: Session) -> None:
        result = session.execute(
            "podman inspect --format '{{.Name}} {{.HostConfig.LogConfig.Config}}' $(podman ps -q) 2>/dev/null || "
            "docker inspect --format '{{.Name}} {{.HostConfig.LogConfig.Config}}' $(docker ps -q) 2>/dev/null"
        )
        if result.success and result.output.strip():
            for line in result.output.strip().splitlines():
                if "max-size" not in line.lower() and "map[]" in line:
                    name = line.split()[0] if line.split() else "unknown"
                    self.add_finding(
                        title=f"No log size limit on container: {name}",
                        description=f"{name} has no log size limit — logs can fill disk",
                        severity=Severity.LOW,
                        evidence=line.strip()[:200],
                        remediation="Set log size: --log-opt max-size=10m --log-opt max-file=3",
                    )

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Never disable container logging (avoid log-driver=none)",
            "Add HEALTHCHECK to all production containers",
            "Set log rotation limits (max-size, max-file)",
            "Forward container logs to centralized SIEM",
        ]

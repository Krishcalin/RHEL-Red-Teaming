"""CS004 — Container Network Security.

Checks container network isolation, port exposure, and
inter-container communication controls on RHEL systems.
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class ContainerNetworkCheck(BaseModule):
    TECHNIQUE_ID = "CS004"
    TECHNIQUE_NAME = "Container Network Security"
    TACTIC = Tactic.LATERAL_MOVEMENT
    SEVERITY = Severity.MEDIUM
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        self._check_published_ports(session)
        self._check_network_mode(session)
        self._check_icc(session)

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def _check_published_ports(self, session: Session) -> None:
        result = session.execute(
            "podman ps --format '{{.Names}} {{.Ports}}' 2>/dev/null || "
            "docker ps --format '{{.Names}} {{.Ports}}' 2>/dev/null"
        )
        if result.success and result.output.strip():
            for line in result.output.strip().splitlines():
                if "0.0.0.0:" in line:
                    name = line.split()[0] if line.split() else "unknown"
                    self.add_finding(
                        title=f"Container ports exposed on all interfaces: {name}",
                        description=f"{name} binds ports to 0.0.0.0 — accessible from all networks",
                        severity=Severity.MEDIUM,
                        evidence=line.strip()[:300],
                        remediation=f"Bind to specific IP: -p 127.0.0.1:<port>:<port>",
                    )

    def _check_network_mode(self, session: Session) -> None:
        result = session.execute(
            "podman inspect --format '{{.Name}} {{.HostConfig.NetworkMode}}' $(podman ps -q) 2>/dev/null || "
            "docker inspect --format '{{.Name}} {{.HostConfig.NetworkMode}}' $(docker ps -q) 2>/dev/null"
        )
        if result.success and result.output.strip():
            for line in result.output.strip().splitlines():
                if "host" in line.lower().split()[-1] if line.split() else "":
                    name = line.split()[0] if line.split() else "unknown"
                    self.add_finding(
                        title=f"Container using host network: {name}",
                        description="Host network mode exposes all host ports and bypasses network isolation",
                        severity=Severity.HIGH,
                        evidence=line.strip(),
                        remediation="Use bridge or custom network: podman network create mynet",
                    )

    def _check_icc(self, session: Session) -> None:
        result = session.execute("cat /etc/docker/daemon.json 2>/dev/null")
        if result.success and result.output.strip():
            if '"icc": true' in result.output or '"icc":true' in result.output:
                self.add_finding(
                    title="Docker inter-container communication enabled",
                    description="ICC allows any container to communicate with any other — no segmentation",
                    severity=Severity.MEDIUM,
                    evidence="icc: true in daemon.json",
                    remediation='Set "icc": false in /etc/docker/daemon.json',
                )

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Bind container ports to specific IPs, not 0.0.0.0",
            "Use custom networks instead of host network mode",
            "Disable inter-container communication (icc=false)",
            "Use network policies to segment container traffic",
        ]

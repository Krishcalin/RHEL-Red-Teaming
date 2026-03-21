"""CS001 — Container Runtime Configuration.

Checks Podman/Docker daemon configuration, rootless mode, and
runtime security settings on RHEL systems.
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class RuntimeConfigCheck(BaseModule):
    TECHNIQUE_ID = "CS001"
    TECHNIQUE_NAME = "Container Runtime Configuration"
    TACTIC = Tactic.DEFENSE_EVASION
    SEVERITY = Severity.HIGH
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        self._check_runtime_installed(session)
        self._check_rootless_mode(session)
        self._check_docker_daemon(session)
        self._check_registries_conf(session)

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def _check_runtime_installed(self, session: Session) -> None:
        podman = session.execute("which podman 2>/dev/null")
        docker = session.execute("which docker 2>/dev/null")
        if docker.success and docker.output.strip():
            self.add_finding(
                title="Docker is installed (prefer Podman on RHEL)",
                description="Docker requires a daemon running as root; Podman is daemonless and rootless by default",
                severity=Severity.MEDIUM,
                evidence=docker.output.strip(),
                remediation="Migrate to Podman: dnf install podman; alias docker=podman",
            )
        if not podman.success or not podman.output.strip():
            if not docker.success or not docker.output.strip():
                return  # No container runtime — nothing to check

    def _check_rootless_mode(self, session: Session) -> None:
        # Check if containers are running as root
        result = session.execute("podman ps --format '{{.ID}} {{.User}}' 2>/dev/null || docker ps --format '{{.ID}}' 2>/dev/null")
        if result.success and result.output.strip():
            root_containers = session.execute(
                "podman inspect --format '{{.Config.User}}' $(podman ps -q) 2>/dev/null | grep -c '^$\\|^0\\|^root'"
            )
            if root_containers.success and root_containers.output.strip():
                try:
                    count = int(root_containers.output.strip())
                    if count > 0:
                        self.add_finding(
                            title=f"{count} containers running as root user",
                            description="Containers running as root increase escape and privilege escalation risk",
                            severity=Severity.HIGH,
                            evidence=f"{count} root containers",
                            remediation="Set USER directive in Containerfile or run with --user flag",
                        )
                except ValueError:
                    pass

        # Check if podman is running rootless
        subuid = session.execute("cat /etc/subuid 2>/dev/null | wc -l")
        if subuid.success and subuid.output.strip():
            try:
                if int(subuid.output.strip()) == 0:
                    self.add_finding(
                        title="No subordinate UID ranges configured",
                        description="/etc/subuid is empty — rootless containers cannot run",
                        severity=Severity.MEDIUM,
                        evidence="Empty /etc/subuid",
                        remediation="Configure subordinate UIDs: usermod --add-subuids 100000-165535 <user>",
                    )
            except ValueError:
                pass

    def _check_docker_daemon(self, session: Session) -> None:
        result = session.execute("systemctl is-active docker 2>/dev/null")
        if result.success and result.output.strip() == "active":
            socket = session.execute("ls -la /var/run/docker.sock 2>/dev/null")
            if socket.success and socket.output.strip():
                if "rw-rw" in socket.output:
                    self.add_finding(
                        title="Docker socket is group-writable",
                        description="Users in the docker group have root-equivalent access via the socket",
                        severity=Severity.CRITICAL,
                        evidence=socket.output.strip()[:200],
                        remediation="Restrict docker group membership; migrate to rootless Podman",
                    )

    def _check_registries_conf(self, session: Session) -> None:
        result = session.execute("cat /etc/containers/registries.conf 2>/dev/null")
        if result.success and result.output.strip():
            if "docker.io" in result.output and "unqualified-search-registries" in result.output:
                if "docker.io" in result.output:
                    pass  # Expected
            else:
                self.add_finding(
                    title="Container registries not explicitly configured",
                    description="Default registry config may pull from untrusted sources",
                    severity=Severity.LOW,
                    evidence="registries.conf missing explicit configuration",
                    remediation="Configure trusted registries in /etc/containers/registries.conf",
                )

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Use Podman instead of Docker on RHEL (daemonless, rootless by default)",
            "Run containers as non-root users (USER directive in Containerfile)",
            "Configure subordinate UID/GID ranges for rootless containers",
            "Restrict Docker socket access if Docker is required",
            "Configure trusted container registries in registries.conf",
        ]

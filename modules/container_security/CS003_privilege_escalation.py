"""CS003 — Container Privilege Escalation.

Checks for privileged containers, dangerous capabilities, and
host namespace sharing on RHEL systems.
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class ContainerPrivescCheck(BaseModule):
    TECHNIQUE_ID = "CS003"
    TECHNIQUE_NAME = "Container Privilege Escalation"
    TACTIC = Tactic.PRIVILEGE_ESCALATION
    SEVERITY = Severity.CRITICAL
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        self._check_privileged_containers(session)
        self._check_dangerous_capabilities(session)
        self._check_host_namespaces(session)
        self._check_host_mounts(session)

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def _check_privileged_containers(self, session: Session) -> None:
        result = session.execute(
            "podman inspect --format '{{.Name}} {{.HostConfig.Privileged}}' $(podman ps -q) 2>/dev/null || "
            "docker inspect --format '{{.Name}} {{.HostConfig.Privileged}}' $(docker ps -q) 2>/dev/null"
        )
        if result.success and result.output.strip():
            for line in result.output.strip().splitlines():
                if "true" in line.lower():
                    name = line.split()[0] if line.split() else "unknown"
                    self.add_finding(
                        title=f"Privileged container: {name}",
                        description="Privileged containers have full host access — equivalent to root on host",
                        severity=Severity.CRITICAL,
                        evidence=line.strip(),
                        remediation=f"Remove --privileged flag from {name}; use specific capabilities instead",
                    )

    def _check_dangerous_capabilities(self, session: Session) -> None:
        dangerous = ["SYS_ADMIN", "SYS_PTRACE", "NET_ADMIN", "NET_RAW",
                      "DAC_OVERRIDE", "SYS_MODULE", "MKNOD"]
        result = session.execute(
            "podman inspect --format '{{.Name}} {{.HostConfig.CapAdd}}' $(podman ps -q) 2>/dev/null || "
            "docker inspect --format '{{.Name}} {{.HostConfig.CapAdd}}' $(docker ps -q) 2>/dev/null"
        )
        if result.success and result.output.strip():
            for line in result.output.strip().splitlines():
                for cap in dangerous:
                    if cap in line:
                        name = line.split()[0] if line.split() else "unknown"
                        self.add_finding(
                            title=f"Dangerous capability {cap} on {name}",
                            description=f"Container {name} has {cap} — enables host escape vectors",
                            severity=Severity.HIGH,
                            evidence=line.strip()[:300],
                            remediation=f"Remove {cap} capability; use --cap-drop ALL --cap-add <needed>",
                        )
                        break

    def _check_host_namespaces(self, session: Session) -> None:
        checks = {
            "NetworkMode": ("host", "Host network namespace shared"),
            "PidMode": ("host", "Host PID namespace shared"),
            "IpcMode": ("host", "Host IPC namespace shared"),
        }
        for field, (bad_val, desc) in checks.items():
            result = session.execute(
                f"podman inspect --format '{{{{.Name}}}} {{{{.HostConfig.{field}}}}}' $(podman ps -q) 2>/dev/null || "
                f"docker inspect --format '{{{{.Name}}}} {{{{.HostConfig.{field}}}}}' $(docker ps -q) 2>/dev/null"
            )
            if result.success and result.output.strip():
                for line in result.output.strip().splitlines():
                    if bad_val in line.lower():
                        name = line.split()[0] if line.split() else "unknown"
                        self.add_finding(
                            title=f"{desc}: {name}",
                            description=f"Container {name} shares host {field} — breaks isolation",
                            severity=Severity.HIGH,
                            evidence=line.strip(),
                            remediation=f"Remove --{field.lower().replace('mode', '')}=host from {name}",
                        )

    def _check_host_mounts(self, session: Session) -> None:
        result = session.execute(
            "podman inspect --format '{{.Name}} {{range .Mounts}}{{.Source}}:{{.Destination}} {{end}}' $(podman ps -q) 2>/dev/null || "
            "docker inspect --format '{{.Name}} {{range .Mounts}}{{.Source}}:{{.Destination}} {{end}}' $(docker ps -q) 2>/dev/null"
        )
        if result.success and result.output.strip():
            dangerous_mounts = ["/", "/etc", "/var/run/docker.sock", "/proc", "/sys"]
            for line in result.output.strip().splitlines():
                for mount in dangerous_mounts:
                    if f"{mount}:" in line:
                        name = line.split()[0] if line.split() else "unknown"
                        self.add_finding(
                            title=f"Dangerous host mount {mount} in {name}",
                            description=f"Container mounts {mount} from host — enables escape or data access",
                            severity=Severity.CRITICAL if mount in ("/", "/proc") else Severity.HIGH,
                            evidence=line.strip()[:300],
                            remediation=f"Remove bind mount of {mount}; use named volumes instead",
                        )

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Never run containers with --privileged flag",
            "Use --cap-drop ALL and add only needed capabilities",
            "Avoid sharing host namespaces (--pid=host, --net=host)",
            "Do not mount sensitive host paths into containers",
            "Use SELinux container labels (--security-opt label=type:container_t)",
        ]

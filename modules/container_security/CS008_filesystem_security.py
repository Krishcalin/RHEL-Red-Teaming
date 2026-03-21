"""CS008 — Container Filesystem Security.

Checks read-only filesystem enforcement, tmpfs usage, and
volume mount security on RHEL systems.
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class FilesystemSecurityCheck(BaseModule):
    TECHNIQUE_ID = "CS008"
    TECHNIQUE_NAME = "Container Filesystem Security"
    TACTIC = Tactic.PERSISTENCE
    SEVERITY = Severity.MEDIUM
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        self._check_readonly_rootfs(session)
        self._check_volume_permissions(session)
        self._check_storage_driver(session)

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def _check_readonly_rootfs(self, session: Session) -> None:
        result = session.execute(
            "podman inspect --format '{{.Name}} {{.HostConfig.ReadonlyRootfs}}' $(podman ps -q) 2>/dev/null || "
            "docker inspect --format '{{.Name}} {{.HostConfig.ReadonlyRootfs}}' $(docker ps -q) 2>/dev/null"
        )
        if result.success and result.output.strip():
            for line in result.output.strip().splitlines():
                if "false" in line.lower():
                    name = line.split()[0] if line.split() else "unknown"
                    self.add_finding(
                        title=f"Writable root filesystem: {name}",
                        description=f"{name} has a writable rootfs — malware can persist inside the container",
                        severity=Severity.MEDIUM,
                        evidence=line.strip(),
                        remediation=f"Run with --read-only; use tmpfs for writable paths",
                    )

    def _check_volume_permissions(self, session: Session) -> None:
        result = session.execute(
            "podman inspect --format '{{.Name}} {{range .Mounts}}{{.Source}}:{{.RW}} {{end}}' $(podman ps -q) 2>/dev/null || "
            "docker inspect --format '{{.Name}} {{range .Mounts}}{{.Source}}:{{.RW}} {{end}}' $(docker ps -q) 2>/dev/null"
        )
        if result.success and result.output.strip():
            for line in result.output.strip().splitlines():
                if ":true" in line:
                    name = line.split()[0] if line.split() else "unknown"
                    rw_mounts = [m for m in line.split() if ":true" in m]
                    if rw_mounts:
                        self.add_finding(
                            title=f"Read-write volume mounts on {name}",
                            description=f"{name} has {len(rw_mounts)} writable volume mounts",
                            severity=Severity.LOW,
                            evidence=", ".join(rw_mounts[:5]),
                            remediation="Mount volumes read-only where possible: -v /path:/path:ro",
                        )

    def _check_storage_driver(self, session: Session) -> None:
        result = session.execute("podman info --format '{{.Store.GraphDriverName}}' 2>/dev/null")
        if result.success and result.output.strip():
            driver = result.output.strip()
            if driver == "vfs":
                self.add_finding(
                    title="Container storage using vfs driver",
                    description="vfs driver has no copy-on-write — poor performance and disk waste",
                    severity=Severity.LOW,
                    evidence=f"GraphDriver: {driver}",
                    remediation="Use overlay2 storage driver: configure in /etc/containers/storage.conf",
                )

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Run containers with --read-only flag",
            "Use tmpfs for paths that need to be writable",
            "Mount volumes read-only where possible (-v path:path:ro)",
            "Use overlay2 storage driver for efficiency",
        ]

"""T1611 — Escape to Host.

Checks for container escape vectors (Podman/Docker).
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class EscapeToHostCheck(BaseModule):
    TECHNIQUE_ID = "T1611"
    TECHNIQUE_NAME = "Escape to Host"
    TACTIC = Tactic.PRIVILEGE_ESCALATION
    SEVERITY = Severity.CRITICAL
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        # Detect if we're in a container
        in_container = False
        container_type = "unknown"

        dockerenv = session.execute("test -f /.dockerenv && echo yes")
        containerenv = session.execute("test -f /run/.containerenv && echo yes")
        cgroup = session.execute("cat /proc/1/cgroup 2>/dev/null | head -5")

        if dockerenv.success and dockerenv.output.strip() == "yes":
            in_container = True
            container_type = "Docker"
        elif containerenv.success and containerenv.output.strip() == "yes":
            in_container = True
            container_type = "Podman/OCI"
        elif cgroup.success and ("docker" in cgroup.output or "kubepods" in cgroup.output or "lxc" in cgroup.output):
            in_container = True
            container_type = "Container (cgroup)"

        if not in_container:
            # Not in a container — check host-side container security
            # Docker socket exposure
            docker_sock = session.execute("test -S /var/run/docker.sock && echo exists")
            if docker_sock.success and docker_sock.output.strip() == "exists":
                readable = session.execute("test -r /var/run/docker.sock && echo readable")
                if readable.success and readable.output.strip() == "readable":
                    self.add_finding(
                        title="Docker socket is accessible",
                        description="Access to Docker socket allows container escape to root on host",
                        severity=Severity.CRITICAL,
                        evidence="/var/run/docker.sock is readable",
                        remediation="Restrict Docker socket access; use Podman rootless instead",
                    )

            # Check docker/podman group membership
            groups = session.execute("id -nG 2>/dev/null")
            if groups.success:
                for grp in ["docker", "podman"]:
                    if grp in groups.output.split():
                        self.add_finding(
                            title=f"User in '{grp}' group",
                            description=f"Membership in '{grp}' group grants root-equivalent access",
                            severity=Severity.CRITICAL,
                            evidence=f"Groups: {groups.output.strip()}",
                            remediation=f"Remove user from '{grp}' group; use rootless containers",
                        )

            # Check if Podman is rootless
            podman_info = session.execute("podman info --format '{{.Host.Security.Rootless}}' 2>/dev/null")
            if podman_info.success and podman_info.output.strip() == "false":
                self.add_finding(
                    title="Podman running as root (not rootless)",
                    description="Root Podman containers share the host kernel with full privileges",
                    severity=Severity.MEDIUM,
                    evidence="Podman rootless: false",
                    remediation="Use rootless Podman: podman system migrate",
                )
        else:
            # Inside a container — check escape vectors
            self.add_finding(
                title=f"Running inside container: {container_type}",
                description="System is containerized — checking escape vectors",
                severity=Severity.INFO,
                evidence=f"Container type: {container_type}",
            )

            # Check if privileged
            capeff = session.execute("cat /proc/self/status 2>/dev/null | grep CapEff")
            if capeff.success and capeff.output.strip():
                hex_val = capeff.output.strip().split()[-1]
                try:
                    if int(hex_val, 16) == 0x3fffffffff or int(hex_val, 16) == 0x1ffffffffff:
                        self.add_finding(
                            title="Container running in PRIVILEGED mode!",
                            description="Full capabilities — trivial host escape via mount/chroot",
                            severity=Severity.CRITICAL,
                            evidence=f"CapEff: {hex_val} (all capabilities)",
                            remediation="Never run containers in privileged mode",
                        )
                except ValueError:
                    pass

            # Check mounted host paths
            mounts = session.execute("mount 2>/dev/null | grep -E 'type (ext|xfs|btrfs)' | head -10")
            if mounts.success and mounts.output.strip():
                self.add_finding(
                    title="Host filesystem mounts detected in container",
                    description="Host paths mounted into container — potential escape via write",
                    severity=Severity.HIGH,
                    evidence=mounts.output.strip()[:400],
                    remediation="Minimize host volume mounts; use read-only mounts",
                )

            # Check for Docker socket inside container
            inner_sock = session.execute("test -S /var/run/docker.sock && echo exists")
            if inner_sock.success and inner_sock.output.strip() == "exists":
                self.add_finding(
                    title="Docker socket mounted inside container!",
                    description="Docker-in-Docker pattern — container can control host Docker",
                    severity=Severity.CRITICAL,
                    evidence="Docker socket available inside container",
                    remediation="Never mount Docker socket into containers",
                )

            # Check seccomp profile
            seccomp = session.execute("grep Seccomp /proc/self/status 2>/dev/null")
            if seccomp.success and "0" in seccomp.output:
                self.add_finding(
                    title="No seccomp profile applied to container",
                    description="All system calls available — increases escape surface",
                    severity=Severity.MEDIUM,
                    evidence=seccomp.output.strip(),
                    remediation="Apply a seccomp profile: --security-opt seccomp=default.json",
                )

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Use rootless containers (Podman rootless)",
            "Never run containers in privileged mode",
            "Never mount Docker socket into containers",
            "Apply seccomp profiles to all containers",
            "Minimize host volume mounts; use read-only where possible",
            "Remove users from docker/podman groups",
        ]

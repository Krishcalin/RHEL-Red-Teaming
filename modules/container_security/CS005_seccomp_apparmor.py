"""CS005 — Container Seccomp and SELinux Profiles.

Checks seccomp profiles, SELinux container labels, and AppArmor
enforcement for containers on RHEL systems.
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class SeccompSelinuxCheck(BaseModule):
    TECHNIQUE_ID = "CS005"
    TECHNIQUE_NAME = "Container Seccomp and SELinux"
    TACTIC = Tactic.DEFENSE_EVASION
    SEVERITY = Severity.HIGH
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        self._check_seccomp(session)
        self._check_selinux_labels(session)
        self._check_no_new_privileges(session)

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def _check_seccomp(self, session: Session) -> None:
        result = session.execute(
            "podman inspect --format '{{.Name}} {{.HostConfig.SecurityOpt}}' $(podman ps -q) 2>/dev/null || "
            "docker inspect --format '{{.Name}} {{.HostConfig.SecurityOpt}}' $(docker ps -q) 2>/dev/null"
        )
        if result.success and result.output.strip():
            for line in result.output.strip().splitlines():
                if "unconfined" in line.lower() or "seccomp=unconfined" in line.lower():
                    name = line.split()[0] if line.split() else "unknown"
                    self.add_finding(
                        title=f"Seccomp disabled for container: {name}",
                        description=f"{name} runs with seccomp=unconfined — all syscalls are allowed",
                        severity=Severity.HIGH,
                        evidence=line.strip()[:300],
                        remediation="Remove --security-opt seccomp=unconfined; use default or custom profile",
                    )

    def _check_selinux_labels(self, session: Session) -> None:
        selinux = session.execute("getenforce 2>/dev/null")
        if selinux.success and selinux.output.strip().lower() == "enforcing":
            result = session.execute(
                "podman inspect --format '{{.Name}} {{.ProcessLabel}}' $(podman ps -q) 2>/dev/null"
            )
            if result.success and result.output.strip():
                for line in result.output.strip().splitlines():
                    if "unconfined" in line.lower() or "spc_t" in line.lower():
                        name = line.split()[0] if line.split() else "unknown"
                        self.add_finding(
                            title=f"Container running without SELinux confinement: {name}",
                            description=f"{name} has unconfined or spc_t SELinux label — SELinux protection bypassed",
                            severity=Severity.HIGH,
                            evidence=line.strip(),
                            remediation="Run with proper SELinux label: --security-opt label=type:container_t",
                        )

    def _check_no_new_privileges(self, session: Session) -> None:
        result = session.execute(
            "podman inspect --format '{{.Name}} {{.HostConfig.SecurityOpt}}' $(podman ps -q) 2>/dev/null || "
            "docker inspect --format '{{.Name}} {{.HostConfig.SecurityOpt}}' $(docker ps -q) 2>/dev/null"
        )
        if result.success and result.output.strip():
            for line in result.output.strip().splitlines():
                if "no-new-privileges" not in line.lower():
                    name = line.split()[0] if line.split() else "unknown"
                    # Only flag if containers are running
                    if name and name != "[]":
                        self.add_finding(
                            title=f"no-new-privileges not set: {name}",
                            description=f"{name} can gain new privileges via setuid/setgid binaries",
                            severity=Severity.MEDIUM,
                            evidence=line.strip()[:300],
                            remediation="Add --security-opt no-new-privileges to container run command",
                        )

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Use default seccomp profile (never run with seccomp=unconfined)",
            "Ensure SELinux labels are applied to containers (container_t)",
            "Set no-new-privileges on all containers",
            "Create custom seccomp profiles for sensitive workloads",
        ]

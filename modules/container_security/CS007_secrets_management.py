"""CS007 — Container Secrets Management.

Checks for exposed secrets in container environments, environment
variables, and mounted secret files on RHEL systems.
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class SecretsManagementCheck(BaseModule):
    TECHNIQUE_ID = "CS007"
    TECHNIQUE_NAME = "Container Secrets Management"
    TACTIC = Tactic.CREDENTIAL_ACCESS
    SEVERITY = Severity.HIGH
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    SECRET_KEYWORDS = ["PASSWORD", "SECRET", "API_KEY", "TOKEN", "PRIVATE_KEY",
                       "AWS_SECRET", "DB_PASS", "MYSQL_ROOT_PASSWORD"]

    def check(self, session: Session) -> ModuleResult:
        self._check_env_secrets(session)
        self._check_build_args(session)
        self._check_mounted_secrets(session)

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def _check_env_secrets(self, session: Session) -> None:
        result = session.execute(
            "podman inspect --format '{{.Name}} {{range .Config.Env}}{{.}} {{end}}' $(podman ps -q) 2>/dev/null || "
            "docker inspect --format '{{.Name}} {{range .Config.Env}}{{.}} {{end}}' $(docker ps -q) 2>/dev/null"
        )
        if result.success and result.output.strip():
            for line in result.output.strip().splitlines():
                for kw in self.SECRET_KEYWORDS:
                    if kw in line.upper():
                        name = line.split()[0] if line.split() else "unknown"
                        self.add_finding(
                            title=f"Secret in environment variable: {name}",
                            description=f"Container {name} has {kw}-like env var — secrets visible via inspect",
                            severity=Severity.HIGH,
                            evidence=f"{name}: {kw}=***REDACTED***",
                            remediation="Use Podman secrets (podman secret create) or mount secrets as files",
                        )
                        break

    def _check_build_args(self, session: Session) -> None:
        result = session.execute(
            "podman history --format '{{.CreatedBy}}' $(podman images -q) 2>/dev/null | grep -i 'ARG.*SECRET\\|ARG.*PASSWORD\\|ARG.*TOKEN' | head -5 || "
            "docker history --format '{{.CreatedBy}}' $(docker images -q) 2>/dev/null | grep -i 'ARG.*SECRET\\|ARG.*PASSWORD\\|ARG.*TOKEN' | head -5"
        )
        if result.success and result.output.strip():
            self.add_finding(
                title="Secrets found in image build history",
                description="Build ARGs containing secrets are visible in image layer history",
                severity=Severity.HIGH,
                evidence=result.output.strip()[:300],
                remediation="Use multi-stage builds; never pass secrets via ARG/ENV in Containerfile",
            )

    def _check_mounted_secrets(self, session: Session) -> None:
        result = session.execute(
            "podman inspect --format '{{.Name}} {{range .Mounts}}{{.Source}} {{end}}' $(podman ps -q) 2>/dev/null || "
            "docker inspect --format '{{.Name}} {{range .Mounts}}{{.Source}} {{end}}' $(docker ps -q) 2>/dev/null"
        )
        if result.success and result.output.strip():
            secret_paths = [".env", "credentials", "secret", ".aws", ".ssh"]
            for line in result.output.strip().splitlines():
                for sp in secret_paths:
                    if sp in line.lower():
                        name = line.split()[0] if line.split() else "unknown"
                        self.add_finding(
                            title=f"Secret-like path mounted in {name}",
                            description=f"Container mounts a path containing '{sp}' from host",
                            severity=Severity.MEDIUM,
                            evidence=line.strip()[:300],
                            remediation="Use Podman secrets or Kubernetes secrets instead of bind mounts",
                        )
                        break

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Use Podman secrets (podman secret create) instead of environment variables",
            "Never pass secrets via build ARGs in Containerfile",
            "Use multi-stage builds to prevent secret leakage in layers",
            "Mount secrets as read-only tmpfs, not host bind mounts",
        ]

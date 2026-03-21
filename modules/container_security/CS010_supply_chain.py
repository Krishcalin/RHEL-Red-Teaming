"""CS010 — Container Supply Chain Security.

Checks Containerfile/Dockerfile best practices, base image freshness,
and build security on RHEL systems.
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class ContainerSupplyChainCheck(BaseModule):
    TECHNIQUE_ID = "CS010"
    TECHNIQUE_NAME = "Container Supply Chain Security"
    TACTIC = Tactic.INITIAL_ACCESS
    SEVERITY = Severity.HIGH
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        self._check_old_images(session)
        self._check_cosign(session)
        self._check_containerfile_practices(session)

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def _check_old_images(self, session: Session) -> None:
        result = session.execute(
            "podman images --format '{{.Repository}}:{{.Tag}} {{.Created}}' 2>/dev/null | head -20 || "
            "docker images --format '{{.Repository}}:{{.Tag}} {{.Created}}' 2>/dev/null | head -20"
        )
        if result.success and result.output.strip():
            old_images = []
            for line in result.output.strip().splitlines():
                if "months ago" in line or "years ago" in line:
                    old_images.append(line.split()[0] if line.split() else line)
            if old_images:
                self.add_finding(
                    title=f"{len(old_images)} stale container images (months/years old)",
                    description="Old images likely contain unpatched vulnerabilities",
                    severity=Severity.HIGH,
                    evidence="\n".join(old_images[:10]),
                    remediation="Rebuild images regularly; automate image updates in CI/CD",
                )

    def _check_cosign(self, session: Session) -> None:
        result = session.execute("which cosign 2>/dev/null || which sigstore 2>/dev/null")
        runtime = session.execute("which podman 2>/dev/null || which docker 2>/dev/null")
        if runtime.success and runtime.output.strip():
            if not result.success or not result.output.strip():
                self.add_finding(
                    title="No container signing tool installed (cosign)",
                    description="Cannot verify image signatures without cosign/sigstore",
                    severity=Severity.MEDIUM,
                    evidence="cosign/sigstore not found",
                    remediation="Install cosign for image signature verification",
                )

    def _check_containerfile_practices(self, session: Session) -> None:
        result = session.execute(
            "find /opt /srv /home -maxdepth 4 -name 'Containerfile' -o -name 'Dockerfile' 2>/dev/null | head -10"
        )
        if result.success and result.output.strip():
            for f in result.output.strip().splitlines():
                content = session.execute(f"cat {f.strip()} 2>/dev/null")
                if content.success and content.output.strip():
                    issues = []
                    if "FROM latest" in content.output or ":latest" in content.output.split("FROM")[-1].split("\n")[0]:
                        issues.append("Uses :latest base image")
                    if "curl" in content.output and "| sh" in content.output:
                        issues.append("Pipes curl to shell")
                    if "ADD http" in content.output:
                        issues.append("Uses ADD with URL (unverified download)")
                    if issues:
                        self.add_finding(
                            title=f"Containerfile issues in {f.strip()}",
                            description="; ".join(issues),
                            severity=Severity.MEDIUM,
                            evidence=f"{f.strip()}: {', '.join(issues)}",
                            remediation="Pin base images to digests; avoid piping to shell; use COPY not ADD",
                        )

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Rebuild container images regularly with updated base images",
            "Install cosign for image signature verification",
            "Pin base images to SHA256 digests in Containerfile",
            "Never pipe curl/wget to shell in Containerfile",
            "Use COPY instead of ADD for local files",
        ]

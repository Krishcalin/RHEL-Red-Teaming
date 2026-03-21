"""CS002 — Container Image Security.

Checks container image signing, vulnerability scanning, and
trusted registry enforcement on RHEL systems.
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class ImageSecurityCheck(BaseModule):
    TECHNIQUE_ID = "CS002"
    TECHNIQUE_NAME = "Container Image Security"
    TACTIC = Tactic.DEFENSE_EVASION
    SEVERITY = Severity.HIGH
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        self._check_image_signing(session)
        self._check_vulnerability_scanner(session)
        self._check_untrusted_images(session)
        self._check_latest_tag(session)

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def _check_image_signing(self, session: Session) -> None:
        policy = session.execute("cat /etc/containers/policy.json 2>/dev/null")
        if policy.success and policy.output.strip():
            if '"insecureAcceptAnything"' in policy.output:
                self.add_finding(
                    title="Container policy accepts unsigned images",
                    description="policy.json uses insecureAcceptAnything — unsigned/tampered images are accepted",
                    severity=Severity.HIGH,
                    evidence="insecureAcceptAnything in policy.json",
                    remediation="Configure signature verification in /etc/containers/policy.json",
                )
        else:
            result = session.execute("which podman 2>/dev/null || which docker 2>/dev/null")
            if result.success and result.output.strip():
                self.add_finding(
                    title="No container policy.json found",
                    description="Container image signature policy is missing",
                    severity=Severity.MEDIUM,
                    evidence="Missing /etc/containers/policy.json",
                    remediation="Create policy.json with signature requirements for trusted registries",
                )

    def _check_vulnerability_scanner(self, session: Session) -> None:
        scanners = {"trivy": "Trivy scanner", "grype": "Grype scanner",
                    "clair": "Clair scanner", "skopeo": "Skopeo inspect"}
        installed = []
        for tool, desc in scanners.items():
            result = session.execute(f"which {tool} 2>/dev/null")
            if result.success and result.output.strip():
                installed.append(tool)
        if not installed:
            result = session.execute("which podman 2>/dev/null || which docker 2>/dev/null")
            if result.success and result.output.strip():
                self.add_finding(
                    title="No container vulnerability scanner installed",
                    description="No image scanning tool found — vulnerable images may be deployed",
                    severity=Severity.MEDIUM,
                    evidence="Checked: trivy, grype, clair, skopeo",
                    remediation="Install Trivy: dnf install trivy or download from GitHub",
                )

    def _check_untrusted_images(self, session: Session) -> None:
        result = session.execute(
            "podman images --format '{{.Repository}}:{{.Tag}}' 2>/dev/null || "
            "docker images --format '{{.Repository}}:{{.Tag}}' 2>/dev/null"
        )
        if result.success and result.output.strip():
            untrusted = []
            for line in result.output.strip().splitlines():
                if line and not any(reg in line for reg in [
                    "registry.redhat.io", "registry.access.redhat.com",
                    "quay.io", "localhost", "<none>"
                ]):
                    untrusted.append(line)
            if untrusted:
                self.add_finding(
                    title=f"{len(untrusted)} images from non-Red Hat registries",
                    description="Images from untrusted registries may contain vulnerabilities or malware",
                    severity=Severity.MEDIUM,
                    evidence="\n".join(untrusted[:10]),
                    remediation="Use images from registry.redhat.io or verified sources only",
                )

    def _check_latest_tag(self, session: Session) -> None:
        result = session.execute(
            "podman images --format '{{.Repository}}:{{.Tag}}' 2>/dev/null | grep ':latest$' || "
            "docker images --format '{{.Repository}}:{{.Tag}}' 2>/dev/null | grep ':latest$'"
        )
        if result.success and result.output.strip():
            count = len(result.output.strip().splitlines())
            self.add_finding(
                title=f"{count} images using :latest tag",
                description="Using :latest prevents reproducible builds and hides version changes",
                severity=Severity.LOW,
                evidence=result.output.strip()[:300],
                remediation="Pin images to specific version tags or SHA256 digests",
            )

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Configure image signature verification in policy.json",
            "Install and run container vulnerability scanners (Trivy, Grype)",
            "Use only images from trusted registries (registry.redhat.io)",
            "Pin images to specific versions, not :latest",
        ]

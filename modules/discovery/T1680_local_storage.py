"""T1680 — Local Storage Discovery.

Checks for accessible application data, caches, and local storage.
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule

APP_DATA_PATHS = [
    ("~/.local/share", "XDG local data"),
    ("~/.cache", "User cache directory"),
    ("~/.config", "User configuration"),
    ("~/.gnupg", "GPG keyring"),
    ("~/.ssh", "SSH configuration and keys"),
    ("~/.aws", "AWS credentials"),
    ("~/.azure", "Azure credentials"),
    ("~/.kube", "Kubernetes config"),
    ("~/.docker", "Docker configuration"),
]


class LocalStorageCheck(BaseModule):
    TECHNIQUE_ID = "T1680"
    TECHNIQUE_NAME = "Local Storage Discovery"
    TACTIC = Tactic.DISCOVERY
    SEVERITY = Severity.MEDIUM
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        for path, desc in APP_DATA_PATHS:
            result = session.execute(f"test -d {path} && find {path} -type f 2>/dev/null | wc -l")
            if result.success and result.output.strip().isdigit() and int(result.output.strip()) > 0:
                count = result.output.strip()
                severity = Severity.MEDIUM
                if any(cloud in path for cloud in [".aws", ".azure", ".kube", ".docker", ".gnupg", ".ssh"]):
                    severity = Severity.HIGH

                self.add_finding(
                    title=f"Application data accessible: {desc}",
                    description=f"{desc} ({path}) contains {count} files",
                    severity=severity,
                    evidence=f"{path}: {count} files",
                    remediation=f"Restrict permissions on {path} to 700",
                )

        # Check for cloud credential files specifically
        cred_files = [
            ("~/.aws/credentials", "AWS credentials"),
            ("~/.aws/config", "AWS config"),
            ("~/.azure/accessTokens.json", "Azure access tokens"),
            ("~/.kube/config", "Kubernetes kubeconfig"),
            ("~/.docker/config.json", "Docker registry credentials"),
        ]
        for path, desc in cred_files:
            check = session.execute(f"test -r {path} && echo readable")
            if check.success and check.output.strip() == "readable":
                self.add_finding(
                    title=f"Cloud credential file readable: {desc}",
                    description=f"{path} is accessible — may contain authentication tokens",
                    severity=Severity.HIGH,
                    evidence=path,
                    remediation=f"Set permissions: chmod 600 {path}",
                )

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Set 700 permissions on sensitive dot directories",
            "Set 600 permissions on credential files",
            "Use IAM roles/instance profiles instead of stored credentials",
            "Encrypt home directories at rest",
        ]

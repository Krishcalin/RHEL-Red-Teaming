"""T1567 — Exfiltration Over Web Service.

Checks for cloud storage access, webhook, and pastebin exfiltration
capabilities on RHEL systems.
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class ExfilWebServiceCheck(BaseModule):
    TECHNIQUE_ID = "T1567"
    TECHNIQUE_NAME = "Exfiltration Over Web Service"
    TACTIC = Tactic.EXFILTRATION
    SEVERITY = Severity.HIGH
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        self._check_cloud_tools(session)
        self._check_cloud_credentials(session)
        self._check_web_upload_tools(session)

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def _check_cloud_tools(self, session: Session) -> None:
        tools = {"rclone": "cloud sync", "aws": "AWS CLI", "gsutil": "Google Storage",
                 "az": "Azure CLI", "s3cmd": "S3 client", "mega-cmd": "MEGA cloud"}
        for tool, desc in tools.items():
            result = session.execute(f"which {tool} 2>/dev/null")
            if result.success and result.output.strip():
                self.add_finding(
                    title=f"Cloud storage tool: {tool}",
                    description=f"{tool} ({desc}) can exfiltrate data to cloud storage",
                    severity=Severity.HIGH,
                    evidence=result.output.strip(),
                    remediation=f"Remove {tool} if not needed; restrict with fapolicyd",
                )

    def _check_cloud_credentials(self, session: Session) -> None:
        cred_files = [
            ("~/.aws/credentials", "AWS"),
            ("~/.config/gcloud/", "Google Cloud"),
            ("~/.azure/", "Azure"),
            ("~/.config/rclone/rclone.conf", "rclone"),
        ]
        for path, name in cred_files:
            result = session.execute(f"test -e {path} && echo exists 2>/dev/null")
            if result.success and "exists" in result.output:
                self.add_finding(
                    title=f"{name} credentials found",
                    description=f"{name} credentials at {path} could be used for cloud exfiltration",
                    severity=Severity.HIGH,
                    evidence=f"{path} exists",
                    remediation=f"Restrict {path} permissions; rotate credentials; use IAM roles instead",
                )

    def _check_web_upload_tools(self, session: Session) -> None:
        result = session.execute("which curl 2>/dev/null")
        if result.success and result.output.strip():
            # curl can POST data to any web service
            self.add_finding(
                title="curl available for web uploads",
                description="curl can POST data to pastebins, webhooks, and cloud APIs for exfiltration",
                severity=Severity.LOW,
                evidence=result.output.strip(),
                remediation="Monitor curl usage with auditd; restrict outbound HTTPS destinations",
            )

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Remove cloud storage tools from non-cloud servers",
            "Restrict and rotate cloud credentials; use IAM roles",
            "Block access to common upload services via DNS/firewall",
            "Monitor outbound HTTPS for large data transfers",
        ]

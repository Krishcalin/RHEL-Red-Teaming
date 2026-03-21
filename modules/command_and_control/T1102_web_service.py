"""T1102 — Web Service.

Checks for cloud service C2 feasibility, dead drop resolvers, and
web service abuse on RHEL systems.
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class WebServiceC2Check(BaseModule):
    TECHNIQUE_ID = "T1102"
    TECHNIQUE_NAME = "Web Service"
    TACTIC = Tactic.COMMAND_AND_CONTROL
    SEVERITY = Severity.MEDIUM
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        self._check_cloud_cli_tools(session)
        self._check_web_service_access(session)
        self._check_egress_https(session)

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def _check_cloud_cli_tools(self, session: Session) -> None:
        tools = {"aws": "AWS CLI", "gcloud": "Google Cloud SDK",
                 "az": "Azure CLI", "rclone": "cloud storage sync",
                 "s3cmd": "S3 client"}
        for tool, desc in tools.items():
            result = session.execute(f"which {tool} 2>/dev/null")
            if result.success and result.output.strip():
                self.add_finding(
                    title=f"Cloud CLI tool available: {tool}",
                    description=f"{tool} ({desc}) can communicate with cloud services for C2",
                    severity=Severity.MEDIUM,
                    evidence=result.output.strip(),
                    remediation=f"Remove {tool} if not operationally required",
                )

    def _check_web_service_access(self, session: Session) -> None:
        services = ["pastebin.com", "github.com", "raw.githubusercontent.com",
                     "gist.github.com", "hastebin.com"]
        for svc in services:
            result = session.execute(f"getent hosts {svc} 2>/dev/null")
            if result.success and result.output.strip():
                self.add_finding(
                    title=f"Web service reachable: {svc}",
                    description=f"{svc} is resolvable — can be used as C2 dead drop",
                    severity=Severity.INFO,
                    evidence=result.output.strip()[:200],
                    remediation=f"Block {svc} via DNS or firewall if not needed",
                )

    def _check_egress_https(self, session: Session) -> None:
        result = session.execute("ss -tn 2>/dev/null | grep ':443' | wc -l")
        if result.success and result.output.strip():
            try:
                count = int(result.output.strip())
                if count > 20:
                    self.add_finding(
                        title=f"High HTTPS connection count ({count})",
                        description="Many active HTTPS connections — web service C2 could be hidden in traffic",
                        severity=Severity.INFO,
                        evidence=f"{count} connections to port 443",
                        remediation="Implement TLS inspection and monitor for anomalous HTTPS patterns",
                    )
            except ValueError:
                pass

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Remove unnecessary cloud CLI tools from production systems",
            "Block access to common dead-drop web services via DNS/firewall",
            "Deploy TLS inspection for outbound HTTPS traffic",
            "Monitor for anomalous web service communication patterns",
        ]

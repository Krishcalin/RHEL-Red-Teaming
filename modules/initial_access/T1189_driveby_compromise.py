"""T1189 — Drive-by Compromise.

Audits exposed web services for drive-by vectors on RHEL systems.
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class DrivebyCompromiseCheck(BaseModule):
    TECHNIQUE_ID = "T1189"
    TECHNIQUE_NAME = "Drive-by Compromise"
    TACTIC = Tactic.INITIAL_ACCESS
    SEVERITY = Severity.HIGH
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        self._check_web_server_versions(session)
        self._check_exposed_web_ports(session)
        self._check_directory_listing(session)

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def _check_web_server_versions(self, session: Session) -> None:
        servers = {"httpd": "Apache", "nginx": "Nginx"}
        for pkg, name in servers.items():
            result = session.execute(f"rpm -q {pkg} 2>/dev/null")
            if result.success and "not installed" not in result.output:
                updates = session.execute(f"dnf check-update {pkg} 2>/dev/null | grep -i {pkg}")
                if updates.success and updates.output.strip():
                    self.add_finding(
                        title=f"{name} has pending updates",
                        description=f"{result.output.strip()} has available security updates",
                        severity=Severity.HIGH,
                        evidence=updates.output.strip()[:300],
                        remediation=f"Update: dnf update {pkg}",
                    )

    def _check_exposed_web_ports(self, session: Session) -> None:
        result = session.execute("ss -tuln 2>/dev/null | grep -E ':80 |:443 |:8080 |:8443 '")
        if result.success and result.output.strip():
            for line in result.output.strip().splitlines():
                if "0.0.0.0" in line:
                    port = line.split(":")[1].split()[0] if ":" in line else "unknown"
                    self.add_finding(
                        title=f"Web service exposed on all interfaces (port {port})",
                        description="Web service on 0.0.0.0 is accessible to all networks — drive-by target",
                        severity=Severity.MEDIUM,
                        evidence=line.strip()[:200],
                        remediation="Bind web services to internal interfaces; use reverse proxy",
                    )

    def _check_directory_listing(self, session: Session) -> None:
        apache = session.execute("grep -ri 'Options.*Indexes' /etc/httpd/ 2>/dev/null | grep -v '#'")
        if apache.success and apache.output.strip():
            self.add_finding(
                title="Apache directory listing enabled",
                description="Directory indexing exposes file structure to attackers",
                severity=Severity.MEDIUM,
                evidence=apache.output.strip()[:300],
                remediation="Remove 'Indexes' from Options directive in Apache config",
            )

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Keep web servers updated with latest security patches",
            "Disable directory listing in web server configuration",
            "Restrict web services to internal interfaces where possible",
            "Deploy a WAF for drive-by exploit detection",
        ]

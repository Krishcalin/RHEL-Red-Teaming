"""T1665 — Hide Infrastructure.

Checks CDN/cloud fronting detection capabilities on RHEL systems.
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class HideInfrastructureCheck(BaseModule):
    TECHNIQUE_ID = "T1665"
    TECHNIQUE_NAME = "Hide Infrastructure"
    TACTIC = Tactic.COMMAND_AND_CONTROL
    SEVERITY = Severity.MEDIUM
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        self._check_tls_inspection(session)
        self._check_dns_monitoring(session)
        self._check_cloud_access(session)

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def _check_tls_inspection(self, session: Session) -> None:
        result = session.execute("find /etc/pki/ca-trust/source/anchors/ -name '*.pem' -o -name '*.crt' 2>/dev/null | wc -l")
        if result.success and result.output.strip():
            try:
                count = int(result.output.strip())
                if count == 0:
                    self.add_finding(
                        title="No custom CA certificates for TLS inspection",
                        description="No corporate CA certs installed — TLS inspection is likely not in place",
                        severity=Severity.MEDIUM,
                        evidence=f"Custom CA cert count: {count}",
                        remediation="Deploy corporate CA for TLS inspection to detect domain fronting",
                    )
            except ValueError:
                pass

    def _check_dns_monitoring(self, session: Session) -> None:
        result = session.execute("grep -ri 'log-queries\\|querylog' /etc/named*.conf /etc/unbound/ /etc/systemd/resolved.conf 2>/dev/null")
        if not result.success or not result.output.strip():
            self.add_finding(
                title="No DNS query monitoring detected",
                description="Cannot detect domain fronting or CDN abuse without DNS monitoring",
                severity=Severity.MEDIUM,
                evidence="No DNS logging configuration found",
                remediation="Enable DNS query logging and forward to SIEM",
            )

    def _check_cloud_access(self, session: Session) -> None:
        cloud_domains = ["cloudfront.net", "azureedge.net", "fastly.net", "akamaized.net"]
        result = session.execute("getent hosts " + " ".join(cloud_domains) + " 2>/dev/null")
        if result.success and result.output.strip():
            self.add_finding(
                title="CDN domains are resolvable",
                description="Cloud CDN domains can be reached — domain fronting C2 is feasible",
                severity=Severity.INFO,
                evidence=result.output.strip()[:300],
                remediation="Monitor connections to CDN domains; implement TLS inspection",
            )

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Deploy TLS inspection with corporate CA to detect domain fronting",
            "Monitor DNS queries for CDN/cloud domain patterns",
            "Implement SNI-based filtering for outbound HTTPS",
            "Use network threat intelligence feeds for known C2 infrastructure",
        ]

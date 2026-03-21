"""T1659 — Content Injection (C2).

Checks for man-in-the-middle content injection capabilities and
ARP spoofing tools on RHEL systems.
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class ContentInjectionC2Check(BaseModule):
    TECHNIQUE_ID = "T1659"
    TECHNIQUE_NAME = "Content Injection"
    TACTIC = Tactic.COMMAND_AND_CONTROL
    SEVERITY = Severity.HIGH
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        self._check_mitm_tools(session)
        self._check_ip_forwarding(session)
        self._check_proxy_injection(session)

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def _check_mitm_tools(self, session: Session) -> None:
        tools = {"arpspoof": "ARP spoofing", "ettercap": "network MITM",
                 "bettercap": "MITM framework", "mitmproxy": "HTTP proxy MITM"}
        for tool, desc in tools.items():
            result = session.execute(f"which {tool} 2>/dev/null")
            if result.success and result.output.strip():
                self.add_finding(
                    title=f"MITM tool available: {tool}",
                    description=f"{tool} ({desc}) enables content injection attacks",
                    severity=Severity.HIGH,
                    evidence=result.output.strip(),
                    remediation=f"Remove {tool} if not needed for authorized testing",
                )

    def _check_ip_forwarding(self, session: Session) -> None:
        ipv4 = session.execute("sysctl -n net.ipv4.ip_forward 2>/dev/null")
        if ipv4.success and ipv4.output.strip() == "1":
            self.add_finding(
                title="IPv4 forwarding is enabled",
                description="IP forwarding enables routing traffic through this host for content injection",
                severity=Severity.MEDIUM,
                evidence="net.ipv4.ip_forward = 1",
                remediation="Disable unless needed: sysctl -w net.ipv4.ip_forward=0",
            )

    def _check_proxy_injection(self, session: Session) -> None:
        for var in ["http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY"]:
            result = session.execute(f"echo ${var}")
            if result.success and result.output.strip():
                self.add_finding(
                    title=f"Proxy variable set: {var}",
                    description=f"{var} is configured — traffic passes through a proxy where injection is possible",
                    severity=Severity.LOW,
                    evidence=f"{var}={result.output.strip()[:200]}",
                    remediation="Verify proxy is trusted; use HTTPS to prevent content injection",
                )

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Remove MITM tools from production systems",
            "Disable IP forwarding unless host is a router/gateway",
            "Use HTTPS/TLS for all internal communications",
            "Deploy ARP spoofing detection (arpwatch, dynamic ARP inspection)",
        ]

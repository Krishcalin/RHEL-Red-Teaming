"""T1568 — Dynamic Resolution.

Checks DNS resolution policies, RPZ, and DGA detection capabilities
on RHEL systems.
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class DynamicResolutionCheck(BaseModule):
    TECHNIQUE_ID = "T1568"
    TECHNIQUE_NAME = "Dynamic Resolution"
    TACTIC = Tactic.COMMAND_AND_CONTROL
    SEVERITY = Severity.MEDIUM
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        self._check_dns_policy(session)
        self._check_rpz(session)
        self._check_dns_logging(session)

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def _check_dns_policy(self, session: Session) -> None:
        resolv = session.execute("cat /etc/resolv.conf 2>/dev/null")
        if resolv.success and resolv.output.strip():
            nameservers = [l for l in resolv.output.splitlines() if l.strip().startswith("nameserver")]
            external = [ns for ns in nameservers if "8.8.8.8" in ns or "1.1.1.1" in ns or "9.9.9.9" in ns]
            if external:
                self.add_finding(
                    title="External public DNS resolvers configured",
                    description="Public DNS resolvers bypass internal DNS filtering/monitoring",
                    severity=Severity.MEDIUM,
                    evidence="\n".join(external),
                    remediation="Use internal DNS servers with logging and filtering enabled",
                )

    def _check_rpz(self, session: Session) -> None:
        named = session.execute("pgrep -x named >/dev/null 2>&1; echo $?")
        if named.success and named.output.strip() == "0":
            rpz = session.execute("grep -ri 'response-policy' /etc/named*.conf /etc/named/ 2>/dev/null")
            if not rpz.success or not rpz.output.strip():
                self.add_finding(
                    title="BIND DNS running without Response Policy Zones",
                    description="No RPZ configured — DGA and malicious domain resolution is unfiltered",
                    severity=Severity.MEDIUM,
                    evidence="No response-policy directive in named configuration",
                    remediation="Configure DNS RPZ with threat intelligence feeds for malicious domain blocking",
                )

    def _check_dns_logging(self, session: Session) -> None:
        result = session.execute("grep -ri 'querylog\\|query-log\\|log-queries' /etc/named*.conf /etc/unbound/ 2>/dev/null")
        if not result.success or not result.output.strip():
            systemd_resolved = session.execute("resolvectl status 2>/dev/null | head -5")
            if not systemd_resolved.success or not systemd_resolved.output.strip():
                self.add_finding(
                    title="No DNS query logging detected",
                    description="DNS queries are not logged — DGA/fast-flux domains cannot be detected",
                    severity=Severity.MEDIUM,
                    evidence="No query logging in named/unbound configuration",
                    remediation="Enable DNS query logging in BIND/Unbound or use systemd-resolved with logging",
                )

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Use internal DNS servers instead of public resolvers",
            "Deploy DNS Response Policy Zones (RPZ) with threat feeds",
            "Enable DNS query logging for anomaly detection",
            "Monitor for DGA patterns in DNS query logs",
        ]

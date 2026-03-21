"""T1008 — Fallback Channels.

Checks for alternate outbound communication channels that could serve
as C2 fallbacks on RHEL systems.
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class FallbackChannelsCheck(BaseModule):
    TECHNIQUE_ID = "T1008"
    TECHNIQUE_NAME = "Fallback Channels"
    TACTIC = Tactic.COMMAND_AND_CONTROL
    SEVERITY = Severity.MEDIUM
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        self._check_multiple_interfaces(session)
        self._check_egress_diversity(session)
        self._check_vpn_tunnels(session)

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def _check_multiple_interfaces(self, session: Session) -> None:
        result = session.execute("ip -o link show up 2>/dev/null | grep -cv 'lo:'")
        if result.success and result.output.strip():
            try:
                count = int(result.output.strip())
                if count > 1:
                    ifaces = session.execute("ip -o addr show 2>/dev/null | grep -v 'lo ' | awk '{print $2, $4}'")
                    self.add_finding(
                        title=f"{count} active network interfaces",
                        description="Multiple interfaces provide alternate egress paths for fallback C2",
                        severity=Severity.LOW,
                        evidence=ifaces.output.strip()[:300] if ifaces.success else f"{count} interfaces",
                        remediation="Restrict egress on non-primary interfaces via firewall rules",
                    )
            except ValueError:
                pass

    def _check_egress_diversity(self, session: Session) -> None:
        routes = session.execute("ip route show default 2>/dev/null")
        if routes.success and routes.output.strip():
            defaults = routes.output.strip().splitlines()
            if len(defaults) > 1:
                self.add_finding(
                    title="Multiple default routes configured",
                    description="Multiple default gateways enable fallback egress paths",
                    severity=Severity.MEDIUM,
                    evidence=routes.output.strip()[:300],
                    remediation="Remove unnecessary default routes; enforce single egress path",
                )

    def _check_vpn_tunnels(self, session: Session) -> None:
        result = session.execute("ip link show type tun 2>/dev/null; ip link show type wireguard 2>/dev/null")
        if result.success and result.output.strip():
            self.add_finding(
                title="VPN/tunnel interfaces detected",
                description="Tunnel interfaces provide alternate C2 channels bypassing primary monitoring",
                severity=Severity.MEDIUM,
                evidence=result.output.strip()[:300],
                remediation="Monitor all tunnel interfaces; restrict VPN creation to authorized users",
            )

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Restrict egress traffic to a single monitored gateway",
            "Apply firewall rules on all network interfaces, not just primary",
            "Monitor tunnel interface creation with auditd",
            "Use network segmentation to limit fallback paths",
        ]

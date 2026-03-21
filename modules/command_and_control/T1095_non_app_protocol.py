"""T1095 — Non-Application Layer Protocol.

Checks for raw socket access and ICMP/UDP tunneling capabilities
on RHEL systems.
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class NonAppProtocolCheck(BaseModule):
    TECHNIQUE_ID = "T1095"
    TECHNIQUE_NAME = "Non-Application Layer Protocol"
    TACTIC = Tactic.COMMAND_AND_CONTROL
    SEVERITY = Severity.MEDIUM
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        self._check_raw_socket_tools(session)
        self._check_icmp_access(session)
        self._check_protocol_filtering(session)

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def _check_raw_socket_tools(self, session: Session) -> None:
        tools = {"hping3": "raw packet crafter", "scapy": "packet manipulation",
                 "nping": "packet generator", "nemesis": "packet injection"}
        for tool, desc in tools.items():
            result = session.execute(f"which {tool} 2>/dev/null")
            if result.success and result.output.strip():
                self.add_finding(
                    title=f"Raw socket tool: {tool}",
                    description=f"{tool} ({desc}) enables non-application layer C2",
                    severity=Severity.MEDIUM,
                    evidence=result.output.strip(),
                    remediation=f"Remove {tool} if not needed for authorized testing",
                )

    def _check_icmp_access(self, session: Session) -> None:
        ping = session.execute("which ping 2>/dev/null")
        if ping.success and ping.output.strip():
            caps = session.execute(f"getcap {ping.output.strip()} 2>/dev/null")
            if caps.success and "cap_net_raw" in caps.output:
                self.add_finding(
                    title="ping has cap_net_raw capability",
                    description="ICMP access via capabilities enables ICMP tunneling for C2",
                    severity=Severity.LOW,
                    evidence=caps.output.strip(),
                    remediation="Remove cap_net_raw from ping if ICMP is not needed",
                )

    def _check_protocol_filtering(self, session: Session) -> None:
        result = session.execute("iptables -L OUTPUT -n 2>/dev/null | grep -ic 'icmp\\|udp\\|raw'")
        if result.success and result.output.strip():
            try:
                rules = int(result.output.strip())
                if rules == 0:
                    self.add_finding(
                        title="No outbound protocol filtering rules",
                        description="No iptables rules filter ICMP/UDP/raw protocols — non-app C2 is unblocked",
                        severity=Severity.MEDIUM,
                        evidence="No ICMP/UDP/raw OUTPUT rules in iptables",
                        remediation="Add iptables/nftables rules to restrict outbound ICMP and raw protocols",
                    )
            except ValueError:
                pass

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Remove raw socket tools from production systems",
            "Restrict ICMP and raw socket capabilities",
            "Filter outbound ICMP and non-standard protocols at the firewall",
            "Monitor for anomalous ICMP traffic patterns",
        ]

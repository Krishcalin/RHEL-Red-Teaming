"""T1040 — Network Sniffing.

Checks promiscuous mode, packet capture tools, and sniffing capabilities
on RHEL systems.
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class NetworkSniffingCheck(BaseModule):
    TECHNIQUE_ID = "T1040"
    TECHNIQUE_NAME = "Network Sniffing"
    TACTIC = Tactic.CREDENTIAL_ACCESS
    SEVERITY = Severity.HIGH
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        self._check_capture_tools(session)
        self._check_promiscuous_mode(session)
        self._check_raw_socket_caps(session)

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def _check_capture_tools(self, session: Session) -> None:
        tools = {"tcpdump": "packet capture", "tshark": "Wireshark CLI",
                 "dumpcap": "Wireshark capture", "ngrep": "network grep",
                 "tcpflow": "TCP stream reassembly"}
        for tool, desc in tools.items():
            result = session.execute(f"which {tool} 2>/dev/null")
            if result.success and result.output.strip():
                caps = session.execute(f"getcap {result.output.strip()} 2>/dev/null")
                has_cap = caps.success and "cap_net_raw" in caps.output
                self.add_finding(
                    title=f"Packet capture tool: {tool}" + (" [cap_net_raw]" if has_cap else ""),
                    description=f"{tool} ({desc}) can sniff network credentials" +
                                (" — has cap_net_raw capability" if has_cap else ""),
                    severity=Severity.HIGH if has_cap else Severity.MEDIUM,
                    evidence=result.output.strip() + (" " + caps.output.strip() if has_cap else ""),
                    remediation=f"Remove {tool} or strip capabilities: setcap -r {result.output.strip()}",
                )

    def _check_promiscuous_mode(self, session: Session) -> None:
        result = session.execute("ip link show 2>/dev/null | grep PROMISC")
        if result.success and result.output.strip():
            self.add_finding(
                title="Interface in promiscuous mode",
                description="A network interface is capturing all traffic — active sniffing",
                severity=Severity.CRITICAL,
                evidence=result.output.strip()[:300],
                remediation="Disable: ip link set <iface> promisc off; investigate cause",
            )

    def _check_raw_socket_caps(self, session: Session) -> None:
        result = session.execute("cat /proc/sys/net/ipv4/ping_group_range 2>/dev/null")
        if result.success and result.output.strip():
            parts = result.output.strip().split()
            if len(parts) == 2:
                try:
                    low, high = int(parts[0]), int(parts[1])
                    if high - low > 100:
                        self.add_finding(
                            title=f"Broad raw socket access (groups {low}-{high})",
                            description="Many groups can create raw sockets for network sniffing",
                            severity=Severity.MEDIUM,
                            evidence=f"ping_group_range: {low} {high}",
                            remediation="Restrict: sysctl -w net.ipv4.ping_group_range='1 0'",
                        )
                except ValueError:
                    pass

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Remove packet capture tools from production systems",
            "Strip cap_net_raw capabilities from non-essential binaries",
            "Monitor for interfaces entering promiscuous mode",
            "Restrict raw socket access via ping_group_range",
            "Use encrypted protocols (TLS, SSH) to protect credentials in transit",
        ]

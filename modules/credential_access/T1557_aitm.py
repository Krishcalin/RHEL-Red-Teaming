"""T1557 — Adversary-in-the-Middle.

Checks for ARP spoofing feasibility and DHCP spoofing risk.
Sub-techniques: T1557.002 (ARP Cache Poisoning), T1557.003 (DHCP Spoofing).
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class AiTMCheck(BaseModule):
    TECHNIQUE_ID = "T1557"
    TECHNIQUE_NAME = "Adversary-in-the-Middle"
    TACTIC = Tactic.CREDENTIAL_ACCESS
    SEVERITY = Severity.HIGH
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        # T1557.002 — ARP Cache Poisoning
        # Check for ARP spoofing tools
        arp_tools = ["arpspoof", "ettercap", "bettercap", "mitmproxy"]
        found_tools = []
        for tool in arp_tools:
            check = session.execute(f"which {tool} 2>/dev/null")
            if check.success and check.output.strip():
                found_tools.append(tool)

        if found_tools:
            self.add_finding(
                title=f"MITM tools available: {', '.join(found_tools)}",
                description="ARP spoofing / MITM tools are installed",
                severity=Severity.HIGH,
                evidence=", ".join(found_tools),
                remediation="Remove MITM tools unless authorized for security testing",
            )

        # Check for static ARP entries (protection)
        static_arp = session.execute("ip neigh show | grep -c 'PERMANENT' 2>/dev/null")
        if static_arp.success and static_arp.output.strip() == "0":
            self.add_finding(
                title="No static ARP entries configured",
                description="All ARP entries are dynamic — susceptible to ARP poisoning",
                severity=Severity.LOW,
                evidence="No PERMANENT ARP entries found",
                remediation="Configure static ARP for gateway on critical systems",
            )

        # Check if IP forwarding is enabled
        ip_forward = session.execute("cat /proc/sys/net/ipv4/ip_forward 2>/dev/null")
        if ip_forward.success and ip_forward.output.strip() == "1":
            self.add_finding(
                title="IP forwarding is enabled",
                description="System can route traffic between interfaces — MITM relay capability",
                severity=Severity.MEDIUM,
                evidence="net.ipv4.ip_forward = 1",
                remediation="Disable if not needed: sysctl net.ipv4.ip_forward=0",
            )

        # T1557.003 — DHCP Spoofing
        # Check if DHCP server is running
        dhcp_server = session.execute("systemctl is-active dhcpd 2>/dev/null")
        if dhcp_server.success and dhcp_server.output.strip() == "active":
            self.add_finding(
                title="DHCP server is running",
                description="This system runs a DHCP server — verify it's authorized",
                severity=Severity.MEDIUM,
                evidence="dhcpd service is active",
                remediation="Verify DHCP server is authorized; use DHCP snooping on switches",
            )

        # Check for rogue DHCP detection
        arpwatch = session.execute("systemctl is-active arpwatch 2>/dev/null")
        if not arpwatch.success or arpwatch.output.strip() != "active":
            self.add_finding(
                title="No ARP monitoring (arpwatch) active",
                description="No ARP change detection — spoofing attacks may go unnoticed",
                severity=Severity.LOW,
                remediation="Install and enable arpwatch for ARP change detection",
            )

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Remove MITM tools from production systems",
            "Use static ARP entries for critical gateways",
            "Disable IP forwarding unless required",
            "Deploy arpwatch for ARP monitoring",
            "Enable DHCP snooping on network switches",
            "Use 802.1X port-based authentication",
        ]

"""T1016 — System Network Configuration Discovery.

Checks accessibility of network configuration, routes, and DNS settings.
Sub-techniques: T1016.001 (Internet Connection), T1016.002 (Wi-Fi).
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class NetworkConfigCheck(BaseModule):
    TECHNIQUE_ID = "T1016"
    TECHNIQUE_NAME = "System Network Configuration Discovery"
    TACTIC = Tactic.DISCOVERY
    SEVERITY = Severity.INFO
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        config_items = [
            ("ip addr show", "Network interfaces and addresses"),
            ("ip route show", "Routing table"),
            ("cat /etc/resolv.conf", "DNS resolver configuration"),
            ("ip neigh show", "ARP cache / neighbor table"),
            ("cat /etc/hosts", "Static host mappings"),
            ("cat /etc/hostname", "System hostname"),
        ]

        for cmd, desc in config_items:
            result = session.execute(cmd)
            if result.success and result.output.strip():
                self.add_finding(
                    title=f"Network config accessible: {desc}",
                    description=f"{desc} is readable by the current user",
                    severity=Severity.INFO,
                    evidence=result.output.strip()[:400],
                )

        # Check for multiple network interfaces (potential pivot points)
        iface_result = session.execute("ip -o link show | grep -c 'state UP'")
        if iface_result.success and iface_result.output.strip().isdigit():
            count = int(iface_result.output.strip())
            if count > 2:  # lo + one interface is normal
                self.add_finding(
                    title=f"Multiple active network interfaces: {count}",
                    description="Multiple active interfaces may indicate dual-homing (lateral movement risk)",
                    severity=Severity.MEDIUM,
                    evidence=f"{count} interfaces in UP state",
                    remediation="Review network segmentation; disable unused interfaces",
                )

        # Check default gateway reachability
        gw = session.execute("ip route | grep default | awk '{print $3}' | head -1")
        if gw.success and gw.output.strip():
            self.add_finding(
                title=f"Default gateway: {gw.output.strip()}",
                description="Default gateway is discoverable",
                severity=Severity.INFO,
                evidence=f"Gateway: {gw.output.strip()}",
            )

        # T1016.002 — Wi-Fi Discovery
        wifi = session.execute("iwconfig 2>/dev/null || nmcli dev wifi list 2>/dev/null")
        if wifi.success and wifi.output.strip() and "no wireless" not in wifi.output.lower():
            self.add_finding(
                title="Wireless interfaces detected",
                description="Wi-Fi interfaces are present and discoverable",
                severity=Severity.LOW,
                evidence=wifi.output.strip()[:400],
                remediation="Disable wireless on server systems; restrict nmcli access",
            )

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Disable unused network interfaces",
            "Restrict ip/nmcli command access via SELinux or RBAC",
            "Disable wireless interfaces on server systems",
            "Use separate VLANs/subnets for management and data traffic",
        ]

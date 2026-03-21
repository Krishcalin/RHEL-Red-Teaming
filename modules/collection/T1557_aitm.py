"""T1557 — Adversary-in-the-Middle (Collection).

Checks traffic interception feasibility including ARP spoofing tools,
promiscuous mode, and IP forwarding on RHEL systems.
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class AitmCollectionCheck(BaseModule):
    TECHNIQUE_ID = "T1557"
    TECHNIQUE_NAME = "Adversary-in-the-Middle"
    TACTIC = Tactic.COLLECTION
    SEVERITY = Severity.HIGH
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        self._check_arp_tools(session)
        self._check_promiscuous(session)
        self._check_ip_forwarding(session)

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def _check_arp_tools(self, session: Session) -> None:
        tools = {"arpspoof": "ARP spoofing", "ettercap": "MITM framework",
                 "bettercap": "MITM suite", "tcpdump": "packet capture",
                 "tshark": "Wireshark CLI"}
        for tool, desc in tools.items():
            result = session.execute(f"which {tool} 2>/dev/null")
            if result.success and result.output.strip():
                sev = Severity.HIGH if tool in ("arpspoof", "ettercap", "bettercap") else Severity.MEDIUM
                self.add_finding(
                    title=f"MITM/capture tool: {tool}",
                    description=f"{tool} ({desc}) enables traffic interception",
                    severity=sev,
                    evidence=result.output.strip(),
                    remediation=f"Remove {tool} if not needed for authorized monitoring",
                )

    def _check_promiscuous(self, session: Session) -> None:
        result = session.execute("ip link show 2>/dev/null | grep PROMISC")
        if result.success and result.output.strip():
            self.add_finding(
                title="Interface in promiscuous mode",
                description="A network interface is in promiscuous mode — capturing all traffic",
                severity=Severity.HIGH,
                evidence=result.output.strip()[:300],
                remediation="Disable promiscuous mode: ip link set <iface> promisc off",
            )

    def _check_ip_forwarding(self, session: Session) -> None:
        result = session.execute("sysctl -n net.ipv4.ip_forward 2>/dev/null")
        if result.success and result.output.strip() == "1":
            self.add_finding(
                title="IPv4 forwarding enabled",
                description="IP forwarding allows routing traffic through this host for interception",
                severity=Severity.MEDIUM,
                evidence="net.ipv4.ip_forward = 1",
                remediation="Disable: sysctl -w net.ipv4.ip_forward=0 (unless this is a router)",
            )

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Remove MITM tools from production systems",
            "Monitor for interfaces entering promiscuous mode",
            "Disable IP forwarding on non-router hosts",
            "Deploy dynamic ARP inspection or arpwatch",
        ]

"""T1040 — Network Sniffing.

Checks for network sniffing capability and promiscuous mode.
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class NetworkSniffingCheck(BaseModule):
    TECHNIQUE_ID = "T1040"
    TECHNIQUE_NAME = "Network Sniffing"
    TACTIC = Tactic.DISCOVERY
    SEVERITY = Severity.MEDIUM
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        # Check for promiscuous mode on interfaces
        promisc = session.execute("ip link show 2>/dev/null | grep -i promisc")
        if promisc.success and promisc.output.strip():
            self.add_finding(
                title="Network interface in promiscuous mode",
                description="An interface is in promiscuous mode — may indicate active sniffing",
                severity=Severity.HIGH,
                evidence=promisc.output.strip(),
                remediation="Investigate and disable promiscuous mode: ip link set <iface> promisc off",
            )

        # Check for packet capture tools
        capture_tools = [
            ("tcpdump", "tcpdump packet capture"),
            ("tshark", "Wireshark CLI"),
            ("wireshark", "Wireshark GUI"),
            ("ngrep", "Network grep"),
            ("ettercap", "Ettercap MITM tool"),
            ("bettercap", "Bettercap MITM tool"),
            ("dsniff", "dsniff password sniffer"),
        ]
        found = []
        for tool, desc in capture_tools:
            check = session.execute(f"which {tool} 2>/dev/null")
            if check.success and check.output.strip():
                found.append(f"{tool} ({desc})")

        if found:
            self.add_finding(
                title=f"Packet capture tools available: {len(found)}",
                description="Network sniffing tools are installed",
                severity=Severity.MEDIUM,
                evidence="\n".join(found),
                remediation="Remove packet capture tools unless operationally required",
            )

        # Check if CAP_NET_RAW is available
        cap_check = session.execute("grep -r Cap /proc/self/status 2>/dev/null")
        if cap_check.success and cap_check.output.strip():
            self.add_finding(
                title="Process capabilities",
                description="Current process capability set (check for CAP_NET_RAW)",
                severity=Severity.INFO,
                evidence=cap_check.output.strip()[:300],
            )

        # Check for existing packet captures
        pcap_files = session.execute(
            "find /tmp /var/tmp /home /root -name '*.pcap' -o -name '*.cap' -o -name '*.pcapng' 2>/dev/null | head -10"
        )
        if pcap_files.success and pcap_files.output.strip():
            self.add_finding(
                title="Packet capture files found on disk",
                description="Existing capture files may contain sensitive traffic data",
                severity=Severity.HIGH,
                evidence=pcap_files.output.strip(),
                remediation="Investigate and remove unauthorized capture files",
            )

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Remove packet capture tools from production systems",
            "Monitor for promiscuous mode on interfaces",
            "Restrict CAP_NET_RAW capability via SELinux/seccomp",
            "Use encrypted protocols (TLS, SSH) for all network traffic",
        ]

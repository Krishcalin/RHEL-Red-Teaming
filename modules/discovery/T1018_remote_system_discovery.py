"""T1018 — Remote System Discovery.

Checks ability to discover other hosts on the network.
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class RemoteSystemDiscoveryCheck(BaseModule):
    TECHNIQUE_ID = "T1018"
    TECHNIQUE_NAME = "Remote System Discovery"
    TACTIC = Tactic.DISCOVERY
    SEVERITY = Severity.LOW
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        # ARP cache
        arp = session.execute("ip neigh show 2>/dev/null")
        if arp.success and arp.output.strip():
            entries = [l for l in arp.output.splitlines() if l.strip()]
            self.add_finding(
                title=f"ARP cache entries: {len(entries)} hosts",
                description="Neighboring hosts are discoverable via ARP cache",
                severity=Severity.INFO,
                evidence="\n".join(entries[:15]),
            )

        # /etc/hosts
        hosts = session.execute("cat /etc/hosts 2>/dev/null | grep -v '^#' | grep -v '^$'")
        if hosts.success and hosts.output.strip():
            self.add_finding(
                title="Static host entries in /etc/hosts",
                description="Known hosts are listed in /etc/hosts",
                severity=Severity.INFO,
                evidence=hosts.output.strip()[:400],
            )

        # SSH known_hosts
        known = session.execute("cat ~/.ssh/known_hosts 2>/dev/null | wc -l")
        if known.success and known.output.strip().isdigit() and int(known.output.strip()) > 0:
            self.add_finding(
                title=f"SSH known_hosts entries: {known.output.strip()}",
                description="Previously connected SSH hosts are discoverable",
                severity=Severity.LOW,
                evidence=f"{known.output.strip()} known host entries",
                remediation="Use HashKnownHosts yes in ssh_config to hash hostnames",
            )

        # DNS domain search
        resolv = session.execute("grep search /etc/resolv.conf 2>/dev/null")
        if resolv.success and resolv.output.strip():
            self.add_finding(
                title="DNS search domains configured",
                description="DNS search domains reveal organizational naming conventions",
                severity=Severity.INFO,
                evidence=resolv.output.strip(),
            )

        # Reverse DNS on local subnet
        subnet = session.execute(
            "ip -o -4 addr show | awk '{print $4}' | grep -v '127.0.0' | head -1"
        )
        if subnet.success and subnet.output.strip():
            self.add_finding(
                title=f"Local subnet: {subnet.output.strip()}",
                description="Local network range is discoverable for further scanning",
                severity=Severity.INFO,
                evidence=subnet.output.strip(),
            )

        # Check for network scanning tools
        scan_tools = ["nmap", "masscan", "zmap", "arp-scan", "netdiscover", "nbtscan"]
        found = []
        for tool in scan_tools:
            check = session.execute(f"which {tool} 2>/dev/null")
            if check.success and check.output.strip():
                found.append(tool)

        if found:
            self.add_finding(
                title=f"Network scanning tools available: {', '.join(found)}",
                description="Tools for active network reconnaissance are installed",
                severity=Severity.MEDIUM,
                evidence=", ".join(found),
                remediation="Remove network scanning tools unless operationally required",
            )

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Hash SSH known_hosts: HashKnownHosts yes",
            "Remove network scanning tools from production systems",
            "Segment networks to limit lateral discovery",
            "Use ARP spoofing protection (arpwatch, DHCP snooping)",
        ]

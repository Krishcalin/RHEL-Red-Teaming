"""T1205 — Traffic Signaling.

Checks for persistence via port knocking, socket filters, and other traffic
signaling mechanisms that allow covert activation of backdoors.
Sub-techniques: T1205.001 (Port Knocking), T1205.002 (Socket Filters).
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class TrafficSignalingCheck(BaseModule):
    TECHNIQUE_ID = "T1205"
    TECHNIQUE_NAME = "Traffic Signaling"
    TACTIC = Tactic.PERSISTENCE
    SEVERITY = Severity.HIGH
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        # ---- T1205.001: Port Knocking ----

        # Check for knockd installed
        knockd_installed = session.execute("rpm -q knock-server knock 2>/dev/null; which knockd 2>/dev/null")
        if knockd_installed.success and ("not installed" not in knockd_installed.output or "knockd" in knockd_installed.output):
            self.add_finding(
                title="Port knocking daemon (knockd) is installed",
                description=(
                    "knockd is installed on the system. While it can be used legitimately, "
                    "attackers can deploy port knocking to hide backdoor services."
                ),
                severity=Severity.HIGH,
                evidence=knockd_installed.output.strip(),
                remediation="Remove knockd if not authorized: dnf remove knock-server; audit knockd.conf for port sequences",
            )

            # Check knockd configuration
            knockd_conf = session.execute("cat /etc/knockd.conf 2>/dev/null")
            if knockd_conf.success and knockd_conf.output.strip():
                self.add_finding(
                    title="knockd configuration found",
                    description="Port knocking configuration defines sequences that open ports or execute commands",
                    severity=Severity.HIGH,
                    evidence=knockd_conf.output.strip()[:500],
                    remediation="Review knockd.conf port sequences and command directives; disable if unauthorized",
                )

        # Check if knockd service is running
        knockd_active = session.execute("systemctl is-active knockd 2>/dev/null")
        if knockd_active.success and "active" in knockd_active.output.strip():
            self.add_finding(
                title="knockd service is actively running",
                description="The port knocking daemon is currently active, listening for knock sequences",
                severity=Severity.CRITICAL,
                evidence="knockd.service is active",
                remediation="Stop and disable knockd: systemctl stop knockd; systemctl disable knockd",
            )

        # Check for fwknop (Single Packet Authorization)
        fwknop_installed = session.execute("rpm -q fwknop fwknop-server 2>/dev/null; which fwknopd 2>/dev/null")
        if fwknop_installed.success and ("not installed" not in fwknop_installed.output or "fwknopd" in fwknop_installed.output):
            self.add_finding(
                title="fwknop (Single Packet Authorization) is installed",
                description=(
                    "fwknop provides Single Packet Authorization, a sophisticated form "
                    "of port knocking. Can be used to covertly open firewall ports."
                ),
                severity=Severity.HIGH,
                evidence=fwknop_installed.output.strip(),
                remediation="Audit fwknop configuration; remove if unauthorized: dnf remove fwknop-server",
            )

        # ---- T1205.002: Socket Filters ----

        # Check for BPF filters attached to network interfaces
        bpf_progs = session.execute(
            "bpftool prog list 2>/dev/null | head -30"
        )
        if bpf_progs.success and bpf_progs.output.strip():
            # Look for socket filter type programs
            if "socket_filter" in bpf_progs.output.lower() or "xdp" in bpf_progs.output.lower():
                self.add_finding(
                    title="BPF socket filter or XDP programs detected",
                    description=(
                        "BPF socket filters or XDP programs can intercept and modify network "
                        "traffic, potentially implementing covert signaling mechanisms."
                    ),
                    severity=Severity.HIGH,
                    evidence=bpf_progs.output.strip()[:500],
                    remediation="Audit BPF programs with bpftool; remove unauthorized filters; restrict BPF via sysctl kernel.unprivileged_bpf_disabled=1",
                )

        # Check for raw socket listeners
        raw_sockets = session.execute(
            "ss -nlpw 2>/dev/null | grep -v '^Netid' | head -10"
        )
        if raw_sockets.success and raw_sockets.output.strip():
            self.add_finding(
                title="Raw socket listeners detected",
                description=(
                    "Processes with raw socket listeners can capture all network traffic "
                    "on an interface, enabling traffic signaling or packet sniffing."
                ),
                severity=Severity.HIGH,
                evidence=raw_sockets.output.strip(),
                remediation="Investigate raw socket processes; restrict CAP_NET_RAW capability via setcap and SELinux",
            )

        # Check for iptables rules using the recent module (port knocking via iptables)
        iptables_recent = session.execute(
            "iptables -S 2>/dev/null | grep -i 'recent' | head -10"
        )
        if iptables_recent.success and iptables_recent.output.strip():
            self.add_finding(
                title="iptables rules using 'recent' module detected",
                description=(
                    "The iptables 'recent' module can implement port knocking by tracking "
                    "connection attempts and opening ports after a specific sequence."
                ),
                severity=Severity.HIGH,
                evidence=iptables_recent.output.strip(),
                remediation="Audit iptables rules with 'recent' module; remove unauthorized port knocking rules",
            )

        # Check for unusual nftables rules that could signal
        nft_rules = session.execute(
            "nft list ruleset 2>/dev/null | grep -iE '(meter|set.*timeout|ct count|limit rate)' | head -15"
        )
        if nft_rules.success and nft_rules.output.strip():
            # Look for connection tracking rules that could implement signaling
            self.add_finding(
                title="nftables rules with stateful tracking detected",
                description=(
                    "nftables rules using meters, sets with timeouts, or connection tracking "
                    "could implement traffic signaling or port knocking mechanisms."
                ),
                severity=Severity.MEDIUM,
                evidence=nft_rules.output.strip(),
                remediation="Audit nftables ruleset for unauthorized stateful rules; document legitimate firewall rules",
            )

        # Check for processes listening on unusual ports (above 1024, not well-known services)
        unusual_listeners = session.execute(
            "ss -tlnp 2>/dev/null | awk 'NR>1 {print $4, $6}' | "
            "grep -vE ':(22|80|443|53|25|110|143|993|995|389|636|88|464|3306|5432|8080|8443|111|2049) ' | "
            "head -15"
        )
        if unusual_listeners.success and unusual_listeners.output.strip():
            self.add_finding(
                title="Processes listening on non-standard ports",
                description=(
                    "Services bound to unusual ports may be backdoors or covert communication "
                    "channels waiting for traffic signaling."
                ),
                severity=Severity.MEDIUM,
                evidence=unusual_listeners.output.strip(),
                remediation="Audit all listening services; map to authorized applications; close unauthorized ports via firewalld",
            )

        # Check for PCAP capabilities on non-standard binaries
        pcap_binaries = session.execute(
            "getcap -r / 2>/dev/null | grep -iE '(cap_net_raw|cap_net_admin)' | "
            "grep -vE '(ping|traceroute|arping|tcpdump|dumpcap|wireshark|tshark|nmap)' | head -10"
        )
        if pcap_binaries.success and pcap_binaries.output.strip():
            self.add_finding(
                title="Non-standard binaries with network capture capabilities",
                description=(
                    "Binaries with CAP_NET_RAW or CAP_NET_ADMIN capabilities can capture "
                    "network traffic. Non-standard binaries with these capabilities may be backdoors."
                ),
                severity=Severity.CRITICAL,
                evidence=pcap_binaries.output.strip(),
                remediation="Remove capabilities from unauthorized binaries: setcap -r <binary>; audit with getcap -r /",
            )

        # Check if unprivileged BPF is allowed
        bpf_unprivileged = session.execute(
            "sysctl kernel.unprivileged_bpf_disabled 2>/dev/null"
        )
        if bpf_unprivileged.success and "= 0" in bpf_unprivileged.output:
            self.add_finding(
                title="Unprivileged BPF is enabled",
                description=(
                    "Unprivileged users can load BPF programs, which could be used "
                    "to implement covert traffic signaling without root access."
                ),
                severity=Severity.MEDIUM,
                evidence=bpf_unprivileged.output.strip(),
                remediation="Disable unprivileged BPF: sysctl -w kernel.unprivileged_bpf_disabled=1; persist in /etc/sysctl.d/",
            )

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Remove port knocking tools (knockd, fwknop) unless explicitly authorized and documented",
            "Disable unprivileged BPF: set kernel.unprivileged_bpf_disabled=1 in /etc/sysctl.d/99-security.conf",
            "Audit network capabilities on binaries with getcap -r / and remove CAP_NET_RAW from non-standard binaries",
            "Monitor iptables/nftables rule changes with auditd (-w /etc/sysconfig/iptables -p wa) and restrict firewall management",
            "Use firewalld to enforce a default-deny policy; document all authorized listening services and ports",
        ]

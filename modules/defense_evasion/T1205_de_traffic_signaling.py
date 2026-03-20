"""T1205 — Traffic Signaling (Defense Evasion perspective).

Checks for covert channel indicators in firewall rules, port-knocking
configurations, unexpected VPN tunnels, raw socket listeners that bypass
firewall logging, and BPF programs that could manipulate packet inspection
on RHEL systems.
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class TrafficSignalingEvasionCheck(BaseModule):
    TECHNIQUE_ID = "T1205"
    TECHNIQUE_NAME = "Traffic Signaling"
    TACTIC = Tactic.DEFENSE_EVASION
    SEVERITY = Severity.MEDIUM
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        self._check_covert_firewall_rules(session)
        self._check_port_knocking(session)
        self._check_unexpected_vpn_tunnels(session)
        self._check_raw_socket_listeners(session)
        self._check_bpf_programs(session)

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    # -- Covert channel indicators in firewall rules --------------------------

    def _check_covert_firewall_rules(self, session: Session) -> None:
        # Check iptables for rules matching specific packet patterns (port knocking, magic packets)
        ipt_recent = session.execute("iptables -L -n -v 2>/dev/null | grep -i 'recent\\|string\\|u32\\|mark' || true")
        if ipt_recent.success and ipt_recent.output.strip():
            self.add_finding(
                title="iptables rules with pattern-matching modules detected",
                description=(
                    "Firewall rules use advanced matching modules (recent, string, u32, mark) "
                    "that could implement covert port-knocking or traffic-signaling backdoors"
                ),
                severity=Severity.MEDIUM,
                evidence=ipt_recent.output.strip()[:500],
                remediation="Audit all iptables rules using advanced match modules and remove unauthorized entries",
            )

        # Check nftables for suspicious constructs
        nft_check = session.execute("nft list ruleset 2>/dev/null | grep -i 'ct mark\\|meta mark\\|numgen\\|jhash' || true")
        if nft_check.success and nft_check.output.strip():
            self.add_finding(
                title="nftables rules with mark/hash constructs detected",
                description="nftables rules use connection tracking marks or hash functions that could implement covert signaling",
                severity=Severity.MEDIUM,
                evidence=nft_check.output.strip()[:500],
                remediation="Review nftables rules for unauthorized mark-based or hash-based packet filtering",
            )

        # Check for ICMP-based rules that could be used for signaling
        icmp_rules = session.execute(
            "iptables -L -n 2>/dev/null | grep -i 'icmp.*accept' || true; "
            "nft list ruleset 2>/dev/null | grep -i 'icmp.*accept' || true"
        )
        if icmp_rules.success and icmp_rules.output.strip():
            self.add_finding(
                title="ICMP accept rules detected in firewall",
                description="Explicit ICMP accept rules exist that could be used for covert signaling or tunneling",
                severity=Severity.LOW,
                evidence=icmp_rules.output.strip()[:500],
                remediation="Restrict ICMP types to echo-request and echo-reply only; rate-limit ICMP traffic",
            )

    # -- Port knocking configurations ----------------------------------------

    def _check_port_knocking(self, session: Session) -> None:
        # Check for knockd service
        knockd = session.execute("systemctl is-active knockd 2>/dev/null; rpm -q knockd 2>/dev/null || true")
        if knockd.success and ("active" in knockd.output or "knockd-" in knockd.output):
            self.add_finding(
                title="Port knocking daemon (knockd) detected",
                description=(
                    "knockd is installed or running, which can open firewall ports "
                    "in response to specific packet sequences, creating a hidden access mechanism"
                ),
                severity=Severity.HIGH,
                evidence=knockd.output.strip(),
                remediation="Remove knockd if not explicitly authorized: dnf remove knockd",
            )

        # Check for knockd config
        knockd_conf = session.execute("cat /etc/knockd.conf 2>/dev/null || true")
        if knockd_conf.success and knockd_conf.output.strip():
            self.add_finding(
                title="knockd configuration file found",
                description="Port knocking configuration exists which defines sequences to open firewall ports covertly",
                severity=Severity.HIGH,
                evidence=knockd_conf.output.strip()[:500],
                remediation="Review /etc/knockd.conf and remove if unauthorized; audit opened port rules",
            )

    # -- Unexpected VPN tunnels -----------------------------------------------

    def _check_unexpected_vpn_tunnels(self, session: Session) -> None:
        # Check for WireGuard interfaces
        wg = session.execute("ip link show type wireguard 2>/dev/null || true")
        if wg.success and wg.output.strip():
            self.add_finding(
                title="WireGuard VPN tunnel detected",
                description="A WireGuard interface is active which could provide a covert encrypted channel bypassing network monitoring",
                severity=Severity.MEDIUM,
                evidence=wg.output.strip()[:500],
                remediation="Verify WireGuard tunnel is authorized; check peer configurations with 'wg show'",
            )

        # Check for OpenVPN
        ovpn = session.execute("pgrep -a openvpn 2>/dev/null || true")
        if ovpn.success and ovpn.output.strip():
            self.add_finding(
                title="OpenVPN process detected",
                description="An OpenVPN process is running which could create a covert tunnel bypassing network controls",
                severity=Severity.MEDIUM,
                evidence=ovpn.output.strip()[:500],
                remediation="Verify OpenVPN configuration is authorized and logs traffic appropriately",
            )

        # Check for tun/tap interfaces not matching expected VPN config
        tun = session.execute("ip link show type tun 2>/dev/null || true")
        if tun.success and tun.output.strip():
            self.add_finding(
                title="TUN/TAP interface detected",
                description="A TUN/TAP interface exists that could be used for VPN tunneling or traffic signaling",
                severity=Severity.LOW,
                evidence=tun.output.strip()[:500],
                remediation="Audit all TUN/TAP interfaces and verify they belong to authorized VPN configurations",
            )

    # -- Raw socket listeners bypassing firewall logging ----------------------

    def _check_raw_socket_listeners(self, session: Session) -> None:
        # Check for processes using raw sockets
        raw_sockets = session.execute("ss -w -n -p 2>/dev/null || true")
        if raw_sockets.success and raw_sockets.output.strip():
            lines = raw_sockets.output.strip().splitlines()
            # Filter out header
            data_lines = [l for l in lines if not l.startswith("Netid")]
            if data_lines:
                self.add_finding(
                    title=f"Raw socket listeners detected ({len(data_lines)} found)",
                    description=(
                        "Processes are using raw sockets which bypass normal firewall "
                        "logging and can be used for covert traffic signaling or sniffing"
                    ),
                    severity=Severity.MEDIUM,
                    evidence="\n".join(data_lines[:10]),
                    remediation="Audit processes using raw sockets; restrict CAP_NET_RAW with SELinux or capabilities",
                )

        # Check for PACKET sockets (layer 2)
        packet_sockets = session.execute("ss -0 -n -p 2>/dev/null | grep -v '^Netid' || true")
        if packet_sockets.success and packet_sockets.output.strip():
            self.add_finding(
                title="PACKET (layer 2) socket listeners detected",
                description="Processes have layer-2 packet sockets open, enabling traffic interception below firewall rules",
                severity=Severity.MEDIUM,
                evidence=packet_sockets.output.strip()[:500],
                remediation="Restrict packet socket creation using SELinux policies or drop CAP_NET_RAW capability",
            )

    # -- BPF programs that could manipulate packet inspection -----------------

    def _check_bpf_programs(self, session: Session) -> None:
        # Check for loaded BPF programs
        bpf_progs = session.execute("bpftool prog list 2>/dev/null || true")
        if bpf_progs.success and bpf_progs.output.strip():
            # Look for XDP or TC programs that modify packets
            lines = bpf_progs.output.strip()
            if "xdp" in lines.lower() or "sched_cls" in lines.lower() or "sched_act" in lines.lower():
                self.add_finding(
                    title="BPF programs attached to network interfaces",
                    description=(
                        "BPF programs (XDP/TC) are attached to network interfaces and can "
                        "modify, redirect, or drop packets before they reach the firewall "
                        "or security tools, enabling covert channels"
                    ),
                    severity=Severity.HIGH,
                    evidence=lines[:500],
                    remediation="Audit all loaded BPF programs with 'bpftool prog show' and remove unauthorized ones",
                )

        # Check if unprivileged BPF is allowed
        unpriv_bpf = session.execute("cat /proc/sys/kernel/unprivileged_bpf_disabled 2>/dev/null || true")
        if unpriv_bpf.success and unpriv_bpf.output.strip() == "0":
            self.add_finding(
                title="Unprivileged BPF is enabled",
                description="Non-root users can load BPF programs, which could be used to intercept or manipulate network traffic covertly",
                severity=Severity.HIGH,
                evidence="unprivileged_bpf_disabled=0",
                remediation="Disable unprivileged BPF: sysctl -w kernel.unprivileged_bpf_disabled=1 and persist in /etc/sysctl.d/",
            )

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Disable unprivileged BPF: echo 1 > /proc/sys/kernel/unprivileged_bpf_disabled and persist in sysctl.d",
            "Audit all iptables/nftables rules regularly for unauthorized pattern-matching or port-knocking entries",
            "Restrict raw and packet socket creation via SELinux or by dropping CAP_NET_RAW from non-essential services",
            "Monitor for unauthorized VPN tunnels (WireGuard, OpenVPN, TUN/TAP) with network inventory tools",
            "Use bpftool to audit loaded BPF programs and alert on unauthorized XDP/TC attachments",
        ]

"""T1048 — Exfiltration Over Alternative Protocol.

Checks for tools and channels that enable data exfiltration outside
normal HTTP/S channels:
- T1048.001 Exfiltration over symmetric encrypted non-C2 protocol
- T1048.002 Exfiltration over asymmetric encrypted non-C2 protocol
- T1048.003 Exfiltration over unencrypted non-C2 protocol
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class ExfiltrationAltProtocolCheck(BaseModule):
    TECHNIQUE_ID = "T1048"
    TECHNIQUE_NAME = "Exfiltration Over Alternative Protocol"
    TACTIC = Tactic.EXFILTRATION
    SEVERITY = Severity.HIGH
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        self._check_dns_exfil(session)
        self._check_icmp_exfil(session)
        self._check_ftp_exfil(session)
        self._check_exfil_tools(session)
        self._check_outbound_protocols(session)

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def _check_dns_exfil(self, session: Session) -> None:
        """Check DNS exfiltration capabilities."""
        # DNS tunneling tools
        dns_tunnel_tools = [
            ("iodine", "iodine — IP-over-DNS tunnel"),
            ("dnscat2", "dnscat2 — C2/exfil over DNS"),
            ("dns2tcp", "dns2tcp — TCP over DNS tunnel"),
        ]
        for binary, desc in dns_tunnel_tools:
            result = session.execute(f"which {binary} 2>/dev/null")
            if result.success and result.output.strip():
                self.add_finding(
                    title=f"DNS tunneling tool installed: {binary}",
                    description=f"{desc} enables data exfiltration through DNS queries",
                    severity=Severity.CRITICAL,
                    evidence=result.output.strip(),
                    remediation=f"Remove immediately: dnf remove {binary}",
                )

        # Check if DNS queries can carry large payloads (no response size limit)
        dig_check = session.execute("which dig 2>/dev/null")
        if dig_check.success and dig_check.output.strip():
            # TXT record queries can carry significant data
            self.add_finding(
                title="dig available for DNS-based data exfiltration",
                description="dig can encode data in DNS TXT queries for exfiltration",
                severity=Severity.LOW,
                evidence=dig_check.output.strip(),
            )

    def _check_icmp_exfil(self, session: Session) -> None:
        """Check ICMP exfiltration capabilities."""
        # ping with custom data
        ping_check = session.execute("which ping 2>/dev/null")
        if ping_check.success and ping_check.output.strip():
            # Check if ICMP is unrestricted outbound
            icmp_fw = session.execute(
                "iptables -L OUTPUT -n 2>/dev/null | grep -i icmp"
            )
            if not icmp_fw.success or not icmp_fw.output.strip():
                self.add_finding(
                    title="Outbound ICMP unrestricted",
                    description="ICMP ping can carry data payloads for covert exfiltration",
                    severity=Severity.LOW,
                    evidence="No ICMP output rules in iptables",
                    remediation="Restrict outbound ICMP with rate limiting or firewall rules",
                )

        # ICMP tunneling tools
        for tool in ("ptunnel", "icmpsh", "hans"):
            result = session.execute(f"which {tool} 2>/dev/null")
            if result.success and result.output.strip():
                self.add_finding(
                    title=f"ICMP tunneling tool installed: {tool}",
                    description=f"{tool} enables data exfiltration over ICMP",
                    severity=Severity.CRITICAL,
                    evidence=result.output.strip(),
                    remediation=f"Remove immediately: dnf remove {tool}",
                )

    def _check_ftp_exfil(self, session: Session) -> None:
        """Check FTP-based exfiltration."""
        ftp_tools = session.execute("which ftp 2>/dev/null || which lftp 2>/dev/null")
        if ftp_tools.success and ftp_tools.output.strip():
            self.add_finding(
                title="FTP client available for data exfiltration",
                description="FTP clients can transfer files to attacker-controlled servers",
                severity=Severity.MEDIUM,
                evidence=ftp_tools.output.strip(),
                remediation="Remove FTP clients: dnf remove ftp lftp",
            )

        # TFTP
        tftp_check = session.execute("which tftp 2>/dev/null")
        if tftp_check.success and tftp_check.output.strip():
            self.add_finding(
                title="TFTP client available — unencrypted file transfer",
                description="TFTP can exfiltrate data without authentication",
                severity=Severity.MEDIUM,
                evidence=tftp_check.output.strip(),
                remediation="Remove TFTP: dnf remove tftp",
            )

    def _check_exfil_tools(self, session: Session) -> None:
        """Check for tools commonly used in data exfiltration."""
        # Compression tools that can prepare data for exfil
        compress_tools = []
        for tool in ("tar", "gzip", "bzip2", "xz", "zip", "7z"):
            result = session.execute(f"which {tool} 2>/dev/null")
            if result.success and result.output.strip():
                compress_tools.append(tool)

        if compress_tools:
            self.add_finding(
                title=f"Compression tools available: {', '.join(compress_tools)}",
                description="Compression tools can prepare data for exfiltration",
                severity=Severity.INFO,
                evidence=", ".join(compress_tools),
            )

        # base64 encoding
        b64 = session.execute("which base64 2>/dev/null")
        if b64.success and b64.output.strip():
            self.add_finding(
                title="base64 encoder available",
                description="base64 can encode binary data for exfiltration over text channels",
                severity=Severity.INFO,
                evidence=b64.output.strip(),
            )

        # xxd for hex encoding
        xxd = session.execute("which xxd 2>/dev/null")
        if xxd.success and xxd.output.strip():
            self.add_finding(
                title="xxd hex encoder available",
                description="xxd can encode data for exfiltration via DNS or other text channels",
                severity=Severity.INFO,
                evidence=xxd.output.strip(),
            )

    def _check_outbound_protocols(self, session: Session) -> None:
        """Check for outbound protocol availability beyond HTTP/DNS."""
        # NTP — can carry data
        ntp_client = session.execute("which ntpdate 2>/dev/null || which chronyc 2>/dev/null")
        if ntp_client.success and ntp_client.output.strip():
            ntp_fw = session.execute(
                "iptables -L OUTPUT -n 2>/dev/null | grep ':123 '"
            )
            if not ntp_fw.success or not ntp_fw.output.strip():
                self.add_finding(
                    title="NTP outbound unrestricted",
                    description="NTP protocol can be abused for covert data exfiltration",
                    severity=Severity.LOW,
                    evidence="NTP client available; no specific outbound NTP firewall rules",
                )

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Remove DNS tunneling tools (iodine, dnscat2, dns2tcp)",
            "Remove ICMP tunneling tools (ptunnel, hans, icmpsh)",
            "Remove unnecessary FTP/TFTP clients",
            "Implement egress firewall rules for non-standard protocols",
            "Rate-limit outbound DNS and ICMP traffic",
            "Monitor for unusually large or frequent DNS TXT queries",
            "Deploy DLP solutions to detect data staging and exfiltration",
        ]

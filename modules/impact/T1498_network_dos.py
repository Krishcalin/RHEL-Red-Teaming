"""T1498 — Network Denial of Service.

Checks for network amplification vectors, rate limiting, SYN flood
protection, and DDoS mitigation controls on RHEL systems.
Sub-techniques: Direct Network Flood (T1498.001), Reflection Amplification (T1498.002).
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class NetworkDosCheck(BaseModule):
    TECHNIQUE_ID = "T1498"
    TECHNIQUE_NAME = "Network Denial of Service"
    TACTIC = Tactic.IMPACT
    SEVERITY = Severity.HIGH
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        self._check_syn_cookies(session)
        self._check_icmp_controls(session)
        self._check_rp_filter(session)
        self._check_amplification_services(session)
        self._check_rate_limiting(session)

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def _check_syn_cookies(self, session: Session) -> None:
        result = session.execute("sysctl -n net.ipv4.tcp_syncookies 2>/dev/null")
        if result.success and result.output.strip() == "0":
            self.add_finding(
                title="TCP SYN cookies are disabled",
                description="SYN flood attacks can exhaust connection table without SYN cookies",
                severity=Severity.HIGH,
                evidence="net.ipv4.tcp_syncookies = 0",
                remediation="Enable: sysctl -w net.ipv4.tcp_syncookies=1",
            )

    def _check_icmp_controls(self, session: Session) -> None:
        broadcast = session.execute("sysctl -n net.ipv4.icmp_echo_ignore_broadcasts 2>/dev/null")
        if broadcast.success and broadcast.output.strip() == "0":
            self.add_finding(
                title="ICMP broadcast responses enabled",
                description="System responds to broadcast pings — Smurf amplification vector",
                severity=Severity.MEDIUM,
                evidence="net.ipv4.icmp_echo_ignore_broadcasts = 0",
                remediation="Enable: sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1",
            )

        bogus = session.execute("sysctl -n net.ipv4.icmp_ignore_bogus_error_responses 2>/dev/null")
        if bogus.success and bogus.output.strip() == "0":
            self.add_finding(
                title="Bogus ICMP error responses not ignored",
                description="System processes malformed ICMP errors — potential for resource waste",
                severity=Severity.LOW,
                evidence="net.ipv4.icmp_ignore_bogus_error_responses = 0",
                remediation="Enable: sysctl -w net.ipv4.icmp_ignore_bogus_error_responses=1",
            )

    def _check_rp_filter(self, session: Session) -> None:
        result = session.execute("sysctl -n net.ipv4.conf.all.rp_filter 2>/dev/null")
        if result.success and result.output.strip() == "0":
            self.add_finding(
                title="Reverse path filtering is disabled",
                description="Source address spoofing is possible — enables reflection attacks",
                severity=Severity.HIGH,
                evidence="net.ipv4.conf.all.rp_filter = 0",
                remediation="Enable strict mode: sysctl -w net.ipv4.conf.all.rp_filter=1",
            )

    def _check_amplification_services(self, session: Session) -> None:
        services = {
            "53": ("DNS", "named/bind can be used for DNS amplification"),
            "123": ("NTP", "ntpd monlist can amplify traffic"),
            "161": ("SNMP", "SNMP can be used for amplification"),
            "1900": ("SSDP/UPnP", "SSDP responds to multicast — amplification vector"),
        }
        listening = session.execute("ss -tuln 2>/dev/null")
        if listening.success:
            for port, (name, desc) in services.items():
                if f":{port} " in listening.output or f":{port}\n" in listening.output:
                    self.add_finding(
                        title=f"Amplification-capable service: {name} (port {port})",
                        description=desc,
                        severity=Severity.MEDIUM,
                        evidence=f"Port {port} is listening",
                        remediation=f"Restrict {name} access via firewall rules or disable if not needed",
                    )

    def _check_rate_limiting(self, session: Session) -> None:
        fw_active = session.execute("firewall-cmd --state 2>/dev/null")
        if fw_active.success and "running" in fw_active.output:
            rich_rules = session.execute("firewall-cmd --list-rich-rules 2>/dev/null")
            if rich_rules.success and "limit" not in rich_rules.output.lower():
                self.add_finding(
                    title="No firewall rate-limiting rules detected",
                    description="firewalld has no rich rules with rate limiting",
                    severity=Severity.LOW,
                    evidence="No 'limit' keyword in rich rules",
                    remediation="Add rate limits: firewall-cmd --add-rich-rule='rule ... limit value=10/m'",
                )

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Enable TCP SYN cookies (net.ipv4.tcp_syncookies=1)",
            "Enable reverse path filtering (net.ipv4.conf.all.rp_filter=1)",
            "Ignore ICMP broadcasts to prevent Smurf amplification",
            "Restrict amplification-capable services (DNS, NTP, SNMP) via firewall",
            "Configure firewalld rich rules with rate limiting for exposed services",
        ]

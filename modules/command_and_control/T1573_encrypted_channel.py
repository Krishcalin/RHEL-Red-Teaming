"""T1573 — Encrypted Channel.

Checks for encrypted communication channels that could conceal C2 traffic:
- T1573.001 Symmetric Cryptography
- T1573.002 Asymmetric Cryptography
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class EncryptedChannelCheck(BaseModule):
    TECHNIQUE_ID = "T1573"
    TECHNIQUE_NAME = "Encrypted Channel"
    TACTIC = Tactic.COMMAND_AND_CONTROL
    SEVERITY = Severity.MEDIUM
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        self._check_tls_tools(session)
        self._check_vpn_tunnels(session)
        self._check_ssh_tunnels(session)
        self._check_crypto_libraries(session)

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def _check_tls_tools(self, session: Session) -> None:
        """Check for TLS-capable tools that can create encrypted channels."""
        # stunnel — creates encrypted wrappers around TCP connections
        stunnel = session.execute("which stunnel 2>/dev/null")
        if stunnel.success and stunnel.output.strip():
            self.add_finding(
                title="stunnel installed — encrypted TCP wrapper",
                description="stunnel can wrap arbitrary TCP connections in TLS, hiding C2 traffic",
                severity=Severity.MEDIUM,
                evidence=stunnel.output.strip(),
                remediation="Remove stunnel if not required: dnf remove stunnel",
            )

        # openssl s_client / s_server
        openssl = session.execute("which openssl 2>/dev/null")
        if openssl.success and openssl.output.strip():
            self.add_finding(
                title="OpenSSL available for encrypted communication",
                description="openssl s_client/s_server can establish encrypted channels",
                severity=Severity.INFO,
                evidence=openssl.output.strip(),
            )

        # ncat with SSL
        ncat_ssl = session.execute("ncat --help 2>&1 | grep -i ssl")
        if ncat_ssl.success and ncat_ssl.output.strip():
            self.add_finding(
                title="ncat supports SSL — encrypted netcat",
                description="ncat with --ssl creates encrypted reverse shells and data channels",
                severity=Severity.MEDIUM,
                evidence="ncat has SSL support",
                remediation="Remove ncat if not required",
            )

    def _check_vpn_tunnels(self, session: Session) -> None:
        """Check for VPN/tunnel services that could be C2 channels."""
        vpn_services = [
            ("openvpn", "OpenVPN — full encrypted tunnel"),
            ("wireguard", "WireGuard — kernel-level encrypted tunnel"),
            ("wg-quick", "WireGuard quick interface manager"),
        ]

        for binary, desc in vpn_services:
            result = session.execute(f"which {binary} 2>/dev/null")
            if result.success and result.output.strip():
                # Check if actively running
                active = session.execute(f"systemctl is-active {binary}* 2>/dev/null")
                is_active = active.success and active.output.strip() == "active"

                severity = Severity.MEDIUM if is_active else Severity.LOW
                state = "active" if is_active else "installed but inactive"

                self.add_finding(
                    title=f"VPN tool {state}: {binary}",
                    description=f"{desc} can create encrypted tunnels for C2",
                    severity=severity,
                    evidence=f"{result.output.strip()} ({state})",
                    remediation=f"Remove {binary} if not authorized for this system",
                )

        # Check for tun/tap devices indicating active tunnels
        tun = session.execute("ip link show type tun 2>/dev/null")
        if tun.success and tun.output.strip():
            self.add_finding(
                title="Active TUN/TAP interfaces detected",
                description="TUN interfaces indicate active VPN or tunnel sessions",
                severity=Severity.MEDIUM,
                evidence=tun.output.strip()[:500],
                remediation="Investigate tunnel endpoints; disable unauthorized VPNs",
            )

    def _check_ssh_tunnels(self, session: Session) -> None:
        """Check for SSH tunnel indicators."""
        # SSH processes with port forwarding (-L, -R, -D)
        ssh_tunnels = session.execute(
            "ps aux 2>/dev/null | grep '[s]sh.*-[LRD]'"
        )
        if ssh_tunnels.success and ssh_tunnels.output.strip():
            self.add_finding(
                title="Active SSH tunnels detected",
                description="SSH port forwarding creates encrypted channels usable for C2",
                severity=Severity.MEDIUM,
                evidence=ssh_tunnels.output.strip()[:500],
                remediation="Audit SSH tunnel usage; disable forwarding in sshd_config if not needed",
            )

        # GatewayPorts in sshd_config
        gateway = session.execute(
            "grep -i 'GatewayPorts yes' /etc/ssh/sshd_config 2>/dev/null"
        )
        if gateway.success and gateway.output.strip():
            self.add_finding(
                title="SSH GatewayPorts enabled",
                description="Remote port forwarding is accessible from external hosts",
                severity=Severity.HIGH,
                evidence=gateway.output.strip(),
                remediation="Set 'GatewayPorts no' in /etc/ssh/sshd_config",
            )

    def _check_crypto_libraries(self, session: Session) -> None:
        """Check for crypto libraries that enable custom encrypted C2."""
        # Python cryptography library
        py_crypto = session.execute(
            "python3 -c 'import cryptography; print(cryptography.__version__)' 2>/dev/null"
        )
        if py_crypto.success and py_crypto.output.strip():
            self.add_finding(
                title=f"Python cryptography library: v{py_crypto.output.strip()}",
                description="Python crypto library enables building custom encrypted C2 channels",
                severity=Severity.INFO,
                evidence=f"cryptography {py_crypto.output.strip()}",
            )

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Remove unnecessary encryption tools (stunnel, ncat-ssl)",
            "Disable SSH port forwarding: AllowTcpForwarding no, GatewayPorts no",
            "Remove unauthorized VPN software (OpenVPN, WireGuard)",
            "Monitor for TUN/TAP device creation",
            "Deploy TLS inspection on egress proxy to detect encrypted C2",
            "Use auditd to monitor openssl and stunnel execution",
        ]

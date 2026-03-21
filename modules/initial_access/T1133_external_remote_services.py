"""T1133 — External Remote Services.

Audits SSH, VPN, and other remote service exposure on RHEL systems.
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class ExternalRemoteServicesCheck(BaseModule):
    TECHNIQUE_ID = "T1133"
    TECHNIQUE_NAME = "External Remote Services"
    TACTIC = Tactic.INITIAL_ACCESS
    SEVERITY = Severity.HIGH
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        self._check_ssh_config(session)
        self._check_vpn_services(session)
        self._check_remote_desktop(session)

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def _check_ssh_config(self, session: Session) -> None:
        root_login = session.execute("grep -i '^PermitRootLogin' /etc/ssh/sshd_config 2>/dev/null")
        if root_login.success and root_login.output.strip():
            if "yes" in root_login.output.lower():
                self.add_finding(
                    title="SSH root login is permitted",
                    description="PermitRootLogin yes — direct root access via SSH",
                    severity=Severity.HIGH,
                    evidence=root_login.output.strip(),
                    remediation="Set PermitRootLogin no in /etc/ssh/sshd_config",
                )

        pw_auth = session.execute("grep -i '^PasswordAuthentication' /etc/ssh/sshd_config 2>/dev/null")
        if pw_auth.success and pw_auth.output.strip():
            if "yes" in pw_auth.output.lower():
                self.add_finding(
                    title="SSH password authentication enabled",
                    description="Password auth allows brute force attacks against SSH",
                    severity=Severity.MEDIUM,
                    evidence=pw_auth.output.strip(),
                    remediation="Set PasswordAuthentication no; use key-based auth only",
                )

        port = session.execute("grep -i '^Port' /etc/ssh/sshd_config 2>/dev/null")
        if port.success and port.output.strip():
            if "22" in port.output:
                self.add_finding(
                    title="SSH on default port 22",
                    description="SSH on default port is easily discoverable",
                    severity=Severity.INFO,
                    evidence=port.output.strip(),
                    remediation="Consider changing SSH port or restricting via firewall",
                )

    def _check_vpn_services(self, session: Session) -> None:
        vpns = {"openvpn": "OpenVPN", "wireguard": "WireGuard", "strongswan": "StrongSwan IPSec"}
        for svc, name in vpns.items():
            result = session.execute(f"systemctl is-active {svc} 2>/dev/null || systemctl is-active wg-quick@* 2>/dev/null")
            if result.success and result.output.strip() == "active":
                self.add_finding(
                    title=f"VPN service active: {name}",
                    description=f"{name} provides remote network access — verify configuration",
                    severity=Severity.MEDIUM,
                    evidence=f"{name} is active",
                    remediation=f"Audit {name} configuration; enforce MFA for VPN access",
                )

    def _check_remote_desktop(self, session: Session) -> None:
        for svc, port in [("xrdp", "3389"), ("vncserver", "5900")]:
            result = session.execute(f"ss -tuln 2>/dev/null | grep ':{port} '")
            if result.success and result.output.strip():
                self.add_finding(
                    title=f"Remote desktop service on port {port}",
                    description=f"{svc} is listening — graphical remote access point",
                    severity=Severity.HIGH,
                    evidence=result.output.strip()[:200],
                    remediation=f"Restrict {svc} to internal networks; require SSH tunneling",
                )

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Disable SSH root login and password authentication",
            "Restrict SSH access via firewall/AllowUsers directive",
            "Enforce MFA for VPN connections",
            "Restrict remote desktop to internal networks",
        ]

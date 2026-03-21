"""T1572 — Protocol Tunneling.

Checks for SSH tunneling, socat, chisel, and other tunneling tools
on RHEL systems.
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class ProtocolTunnelingCheck(BaseModule):
    TECHNIQUE_ID = "T1572"
    TECHNIQUE_NAME = "Protocol Tunneling"
    TACTIC = Tactic.COMMAND_AND_CONTROL
    SEVERITY = Severity.HIGH
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        self._check_tunneling_tools(session)
        self._check_ssh_tunneling(session)
        self._check_active_tunnels(session)

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def _check_tunneling_tools(self, session: Session) -> None:
        tools = {"socat": "socket relay", "chisel": "HTTP tunnel",
                 "ngrok": "reverse tunnel", "bore": "TCP tunnel",
                 "rathole": "NAT traversal", "frpc": "fast reverse proxy"}
        for tool, desc in tools.items():
            result = session.execute(f"which {tool} 2>/dev/null || find /tmp /opt /usr/local/bin -name '{tool}' 2>/dev/null | head -1")
            if result.success and result.output.strip():
                self.add_finding(
                    title=f"Tunneling tool: {tool}",
                    description=f"{tool} ({desc}) enables protocol tunneling for C2",
                    severity=Severity.HIGH,
                    evidence=result.output.strip(),
                    remediation=f"Remove {tool}; investigate how it was installed",
                )

    def _check_ssh_tunneling(self, session: Session) -> None:
        result = session.execute("grep -i 'AllowTcpForwarding' /etc/ssh/sshd_config 2>/dev/null")
        if result.success and result.output.strip():
            if "yes" in result.output.lower() or "all" in result.output.lower():
                self.add_finding(
                    title="SSH TCP forwarding is enabled",
                    description="AllowTcpForwarding enables SSH-based protocol tunneling",
                    severity=Severity.MEDIUM,
                    evidence=result.output.strip(),
                    remediation="Set AllowTcpForwarding no in /etc/ssh/sshd_config",
                )
        else:
            self.add_finding(
                title="SSH TCP forwarding not explicitly disabled",
                description="AllowTcpForwarding defaults to yes — SSH tunneling is possible",
                severity=Severity.MEDIUM,
                evidence="AllowTcpForwarding not set (defaults to yes)",
                remediation="Explicitly set AllowTcpForwarding no in /etc/ssh/sshd_config",
            )

    def _check_active_tunnels(self, session: Session) -> None:
        result = session.execute("ss -tnp 2>/dev/null | grep -i 'ssh.*ESTAB' | head -10")
        if result.success and result.output.strip():
            lines = result.output.strip().splitlines()
            if len(lines) > 3:
                self.add_finding(
                    title=f"Multiple active SSH connections ({len(lines)})",
                    description="Many SSH connections may indicate active SSH tunneling",
                    severity=Severity.LOW,
                    evidence=result.output.strip()[:300],
                    remediation="Audit active SSH connections; restrict SSH to authorized users",
                )

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Disable SSH TCP forwarding: AllowTcpForwarding no",
            "Remove unauthorized tunneling tools (socat, chisel, ngrok)",
            "Monitor for unusual SSH connection patterns",
            "Deploy fapolicyd to block unauthorized tunnel executables",
        ]

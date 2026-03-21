"""T1001 — Data Obfuscation.

Checks for protocol impersonation and steganography tools that could
obfuscate C2 communications on RHEL systems.
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class DataObfuscationCheck(BaseModule):
    TECHNIQUE_ID = "T1001"
    TECHNIQUE_NAME = "Data Obfuscation"
    TACTIC = Tactic.COMMAND_AND_CONTROL
    SEVERITY = Severity.MEDIUM
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        self._check_steganography_tools(session)
        self._check_raw_sockets(session)
        self._check_protocol_tools(session)

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def _check_steganography_tools(self, session: Session) -> None:
        tools = {"steghide": "image steganography", "stegsnow": "whitespace stego",
                 "openstego": "digital watermarking", "outguess": "JPEG steganography"}
        for tool, desc in tools.items():
            result = session.execute(f"which {tool} 2>/dev/null")
            if result.success and result.output.strip():
                self.add_finding(
                    title=f"Steganography tool: {tool}",
                    description=f"{tool} ({desc}) can hide C2 data in innocuous files",
                    severity=Severity.HIGH,
                    evidence=result.output.strip(),
                    remediation=f"Remove {tool} if not needed for authorized testing",
                )

    def _check_raw_sockets(self, session: Session) -> None:
        cap = session.execute("grep -r 'cap_net_raw' /etc/security/capability.conf 2>/dev/null")
        result = session.execute("cat /proc/sys/net/ipv4/ping_group_range 2>/dev/null")
        if result.success and result.output.strip():
            parts = result.output.strip().split()
            if len(parts) == 2:
                try:
                    low, high = int(parts[0]), int(parts[1])
                    if high - low > 1000:
                        self.add_finding(
                            title="Broad ping group range (raw socket access)",
                            description="Many groups can create raw sockets for protocol impersonation",
                            severity=Severity.LOW,
                            evidence=f"ping_group_range: {low} {high}",
                            remediation="Restrict: sysctl -w net.ipv4.ping_group_range='1 0'",
                        )
                except ValueError:
                    pass

    def _check_protocol_tools(self, session: Session) -> None:
        tools = {"scapy": "packet crafting", "hping3": "packet generator",
                 "nping": "network packet generation"}
        for tool, desc in tools.items():
            result = session.execute(f"which {tool} 2>/dev/null")
            if result.success and result.output.strip():
                self.add_finding(
                    title=f"Packet crafting tool: {tool}",
                    description=f"{tool} ({desc}) can create custom protocol traffic for C2",
                    severity=Severity.MEDIUM,
                    evidence=result.output.strip(),
                    remediation=f"Remove {tool} from production systems",
                )

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Remove steganography and packet crafting tools from production",
            "Restrict raw socket access via ping_group_range and capabilities",
            "Deploy deep packet inspection to detect obfuscated protocols",
            "Monitor for unusual file types and protocol anomalies",
        ]

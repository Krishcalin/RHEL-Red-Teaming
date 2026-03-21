"""T1011 — Exfiltration Over Other Network Medium.

Checks Bluetooth and other non-standard network media exfiltration
feasibility on RHEL systems.
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class ExfilOtherMediumCheck(BaseModule):
    TECHNIQUE_ID = "T1011"
    TECHNIQUE_NAME = "Exfiltration Over Other Network Medium"
    TACTIC = Tactic.EXFILTRATION
    SEVERITY = Severity.MEDIUM
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        self._check_bluetooth(session)
        self._check_wireless(session)
        self._check_infrared(session)

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def _check_bluetooth(self, session: Session) -> None:
        bt = session.execute("hciconfig 2>/dev/null || bluetoothctl list 2>/dev/null")
        if bt.success and bt.output.strip() and "not found" not in bt.output.lower():
            self.add_finding(
                title="Bluetooth adapter detected",
                description="Bluetooth can be used for short-range data exfiltration",
                severity=Severity.MEDIUM,
                evidence=bt.output.strip()[:300],
                remediation="Disable Bluetooth: systemctl disable --now bluetooth; rfkill block bluetooth",
            )

        tools = {"obexftp": "OBEX file transfer", "hcitool": "Bluetooth control",
                 "bluetoothctl": "Bluetooth management"}
        for tool, desc in tools.items():
            result = session.execute(f"which {tool} 2>/dev/null")
            if result.success and result.output.strip():
                self.add_finding(
                    title=f"Bluetooth tool available: {tool}",
                    description=f"{tool} ({desc}) enables Bluetooth data transfer",
                    severity=Severity.LOW,
                    evidence=result.output.strip(),
                    remediation=f"Remove {tool} if Bluetooth is not needed",
                )

    def _check_wireless(self, session: Session) -> None:
        result = session.execute("iw dev 2>/dev/null | grep Interface")
        if result.success and result.output.strip():
            self.add_finding(
                title="Wireless network interfaces detected",
                description="WiFi interfaces can create ad-hoc networks for exfiltration",
                severity=Severity.MEDIUM,
                evidence=result.output.strip()[:300],
                remediation="Disable WiFi on servers: nmcli radio wifi off; rfkill block wifi",
            )

    def _check_infrared(self, session: Session) -> None:
        result = session.execute("ls /dev/lirc* 2>/dev/null")
        if result.success and result.output.strip():
            self.add_finding(
                title="Infrared devices detected",
                description="IR devices could be used for short-range covert data transfer",
                severity=Severity.LOW,
                evidence=result.output.strip(),
                remediation="Disable IR devices if not needed",
            )

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Disable Bluetooth and WiFi on servers: rfkill block all",
            "Remove Bluetooth and wireless tools from production systems",
            "Monitor for new wireless interface creation",
            "Use physical security to restrict IR/Bluetooth range",
        ]

"""T1669 — Wi-Fi Networks.

Checks wireless interface exposure and WPA configuration on RHEL systems.
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class WifiNetworksCheck(BaseModule):
    TECHNIQUE_ID = "T1669"
    TECHNIQUE_NAME = "Wi-Fi Networks"
    TACTIC = Tactic.INITIAL_ACCESS
    SEVERITY = Severity.MEDIUM
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        self._check_wireless_interfaces(session)
        self._check_wifi_credentials(session)
        self._check_hostapd(session)

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def _check_wireless_interfaces(self, session: Session) -> None:
        result = session.execute("iw dev 2>/dev/null | grep -E 'Interface|ssid|type'")
        if result.success and result.output.strip():
            self.add_finding(
                title="Wireless interfaces detected",
                description="WiFi interfaces present — potential entry point via rogue AP or WPA attacks",
                severity=Severity.MEDIUM,
                evidence=result.output.strip()[:300],
                remediation="Disable WiFi on servers: nmcli radio wifi off; rfkill block wifi",
            )

        nmcli = session.execute("nmcli -t -f DEVICE,TYPE device 2>/dev/null | grep wifi")
        if nmcli.success and nmcli.output.strip():
            self.add_finding(
                title="WiFi managed by NetworkManager",
                description="NetworkManager is managing WiFi interfaces",
                severity=Severity.LOW,
                evidence=nmcli.output.strip()[:200],
                remediation="Disable WiFi via NetworkManager: nmcli radio wifi off",
            )

    def _check_wifi_credentials(self, session: Session) -> None:
        result = session.execute(
            "find /etc/NetworkManager/system-connections /etc/sysconfig/network-scripts "
            "-name '*.nmconnection' -o -name 'ifcfg-*' 2>/dev/null | head -10"
        )
        if result.success and result.output.strip():
            for f in result.output.strip().splitlines():
                psk = session.execute(f"grep -i 'psk\\|password\\|wep-key' {f.strip()} 2>/dev/null")
                if psk.success and psk.output.strip():
                    self.add_finding(
                        title=f"WiFi credentials in {f.strip()}",
                        description="Stored WiFi credentials can be extracted",
                        severity=Severity.HIGH,
                        evidence="Credentials found (content redacted)",
                        remediation=f"Restrict permissions on {f.strip()}; use 802.1X instead of PSK",
                    )

    def _check_hostapd(self, session: Session) -> None:
        result = session.execute("which hostapd 2>/dev/null || systemctl is-active hostapd 2>/dev/null")
        if result.success and result.output.strip() and "inactive" not in result.output:
            self.add_finding(
                title="hostapd detected (access point software)",
                description="hostapd can create rogue access points for initial access",
                severity=Severity.HIGH,
                evidence=result.output.strip(),
                remediation="Remove hostapd if AP functionality is not authorized",
            )

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Disable WiFi on servers: rfkill block wifi",
            "Use 802.1X enterprise authentication instead of PSK",
            "Restrict WiFi credential file permissions",
            "Remove hostapd from non-AP systems",
        ]

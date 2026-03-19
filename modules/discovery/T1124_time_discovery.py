"""T1124 — System Time Discovery.

Checks time synchronization configuration and timezone settings.
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class TimeDiscoveryCheck(BaseModule):
    TECHNIQUE_ID = "T1124"
    TECHNIQUE_NAME = "System Time Discovery"
    TACTIC = Tactic.DISCOVERY
    SEVERITY = Severity.INFO
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        # Current time and timezone
        timedatectl = session.execute("timedatectl 2>/dev/null")
        if timedatectl.success:
            self.add_finding(
                title="System time and timezone accessible",
                description="Time configuration is readable",
                severity=Severity.INFO,
                evidence=timedatectl.output.strip()[:400],
            )

        # NTP synchronization
        chrony = session.execute("chronyc tracking 2>/dev/null")
        if chrony.success and chrony.output.strip():
            self.add_finding(
                title="Chrony NTP status accessible",
                description="Time synchronization details are readable",
                severity=Severity.INFO,
                evidence=chrony.output.strip()[:400],
            )
        else:
            ntp_active = session.execute("systemctl is-active chronyd ntpd 2>/dev/null")
            if not ntp_active.success or "active" not in ntp_active.output:
                self.add_finding(
                    title="No NTP service running",
                    description="System time may drift — impacts log correlation and Kerberos",
                    severity=Severity.MEDIUM,
                    remediation="Enable chronyd: systemctl enable --now chronyd",
                )

        # NTP sources (reveals infrastructure)
        sources = session.execute("chronyc sources 2>/dev/null || ntpq -p 2>/dev/null")
        if sources.success and sources.output.strip():
            self.add_finding(
                title="NTP sources discoverable",
                description="Time server infrastructure is visible",
                severity=Severity.INFO,
                evidence=sources.output.strip()[:400],
            )

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Enable and configure chronyd for time synchronization",
            "Use authenticated NTP (NTS) where possible",
            "Restrict chronyc/ntpq access to administrators",
        ]

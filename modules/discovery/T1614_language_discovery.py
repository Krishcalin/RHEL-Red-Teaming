"""T1614.001 — System Language Discovery.

Checks locale settings and language configuration.
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class LanguageDiscoveryCheck(BaseModule):
    TECHNIQUE_ID = "T1614"
    TECHNIQUE_NAME = "System Language Discovery"
    TACTIC = Tactic.DISCOVERY
    SEVERITY = Severity.INFO
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        locale = session.execute("locale 2>/dev/null")
        if locale.success and locale.output.strip():
            self.add_finding(
                title="System locale accessible",
                description="Locale and language settings are readable (useful for targeted attacks)",
                severity=Severity.INFO,
                evidence=locale.output.strip()[:400],
            )

        localectl = session.execute("localectl status 2>/dev/null")
        if localectl.success and localectl.output.strip():
            self.add_finding(
                title="Keyboard layout and locale details",
                description="System language and keyboard layout configuration exposed",
                severity=Severity.INFO,
                evidence=localectl.output.strip(),
            )

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Locale exposure is generally low risk on servers",
            "Restrict shell access to minimize information leakage",
        ]

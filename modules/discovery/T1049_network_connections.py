"""T1049 — System Network Connections Discovery.

Checks visibility of active network connections and established sessions.
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class NetworkConnectionsCheck(BaseModule):
    TECHNIQUE_ID = "T1049"
    TECHNIQUE_NAME = "System Network Connections Discovery"
    TACTIC = Tactic.DISCOVERY
    SEVERITY = Severity.INFO
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        # Established connections
        established = session.execute("ss -tunp state established 2>/dev/null")
        if established.success and established.output.strip():
            lines = [l for l in established.output.splitlines() if l.strip() and not l.startswith("Netid")]
            if lines:
                self.add_finding(
                    title=f"Established connections visible: {len(lines)}",
                    description="Active network connections are enumerable by the current user",
                    severity=Severity.INFO,
                    evidence="\n".join(lines[:20]),
                    remediation="Use hidepid=2 and restrict ss/netstat access if needed",
                )

        # External connections (non-loopback)
        external = session.execute(
            "ss -tunp state established 2>/dev/null | "
            "grep -v '127.0.0.1' | grep -v '::1' | grep -v 'Netid'"
        )
        if external.success and external.output.strip():
            ext_lines = external.output.strip().splitlines()
            self.add_finding(
                title=f"External connections: {len(ext_lines)}",
                description="Connections to/from external hosts are visible",
                severity=Severity.LOW,
                evidence="\n".join(ext_lines[:15]),
            )

        # Listening on all interfaces
        all_listen = session.execute("ss -tlnp 2>/dev/null | grep '0.0.0.0\\|\\*\\|:::'")
        if all_listen.success and all_listen.output.strip():
            self.add_finding(
                title="Services listening on all interfaces",
                description="Services bound to 0.0.0.0/:: are exposed to all networks",
                severity=Severity.MEDIUM,
                evidence=all_listen.output.strip()[:500],
                remediation="Bind services to specific interfaces where possible",
            )

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Mount /proc with hidepid=2 to restrict connection visibility",
            "Bind services to specific interfaces",
            "Use firewalld zone-based rules to restrict access",
        ]

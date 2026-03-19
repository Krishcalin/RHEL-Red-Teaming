"""T1033 — System Owner/User Discovery.

Checks what user identity and session information is accessible.
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class OwnerDiscoveryCheck(BaseModule):
    TECHNIQUE_ID = "T1033"
    TECHNIQUE_NAME = "System Owner/User Discovery"
    TACTIC = Tactic.DISCOVERY
    SEVERITY = Severity.INFO
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        # Current user identity
        id_result = session.execute("id")
        if id_result.success:
            self.add_finding(
                title="Current user identity",
                description="User identity information is accessible",
                severity=Severity.INFO,
                evidence=id_result.output.strip(),
            )

        # Logged-in users
        who = session.execute("who 2>/dev/null")
        if who.success and who.output.strip():
            users = who.output.strip().splitlines()
            self.add_finding(
                title=f"Logged-in users visible: {len(users)}",
                description="Active user sessions are enumerable",
                severity=Severity.INFO,
                evidence="\n".join(users[:15]),
            )

        # Check w (more detail — idle time, command)
        w_result = session.execute("w -h 2>/dev/null")
        if w_result.success and w_result.output.strip():
            self.add_finding(
                title="User activity visible via 'w' command",
                description="Current commands and idle time of logged-in users are visible",
                severity=Severity.LOW,
                evidence=w_result.output.strip()[:500],
                remediation="Consider restricting 'w' and 'who' access",
            )

        # Recent logins
        lastlog = session.execute("lastlog -t 30 2>/dev/null | grep -v 'Never'")
        if lastlog.success and lastlog.output.strip():
            lines = lastlog.output.strip().splitlines()
            self.add_finding(
                title=f"Recent logins (last 30 days): {len(lines) - 1}",
                description="Login history is accessible",
                severity=Severity.INFO,
                evidence="\n".join(lines[:15]),
            )

        # Home directory enumeration
        homes = session.execute("ls -la /home/ 2>/dev/null")
        if homes.success and homes.output.strip():
            self.add_finding(
                title="Home directories enumerable",
                description="User home directories are listable under /home/",
                severity=Severity.INFO,
                evidence=homes.output.strip()[:500],
                remediation="Restrict /home directory listing permissions if needed",
            )

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Restrict /home directory listing with chmod 711 /home",
            "Limit access to 'w', 'who', 'last' via restricted shells or RBAC",
            "Restrict /var/log/wtmp and /var/log/lastlog permissions",
        ]

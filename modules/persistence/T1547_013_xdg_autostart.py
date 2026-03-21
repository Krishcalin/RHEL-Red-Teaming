"""T1547.013 — XDG Autostart Entries.

Checks for malicious or unauthorized XDG autostart entries that provide
persistence on RHEL systems with graphical desktop environments.
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class XdgAutostartCheck(BaseModule):
    TECHNIQUE_ID = "T1547.013"
    TECHNIQUE_NAME = "XDG Autostart Entries"
    TACTIC = Tactic.PERSISTENCE
    SEVERITY = Severity.MEDIUM
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        self._check_user_autostart(session)
        self._check_system_autostart(session)
        self._check_writable_autostart_dirs(session)

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def _check_user_autostart(self, session: Session) -> None:
        result = session.execute("find /home -path '*/.config/autostart/*.desktop' 2>/dev/null | head -20")
        if result.success and result.output.strip():
            for f in result.output.strip().splitlines():
                exec_line = session.execute(f"grep '^Exec=' {f.strip()} 2>/dev/null")
                if exec_line.success and exec_line.output.strip():
                    self.add_finding(
                        title=f"User XDG autostart: {f.strip()}",
                        description="XDG desktop autostart entry runs at graphical login — persistence vector",
                        severity=Severity.MEDIUM,
                        evidence=exec_line.output.strip()[:300],
                        remediation=f"Audit {f.strip()}; remove if unauthorized",
                    )

    def _check_system_autostart(self, session: Session) -> None:
        result = session.execute("find /etc/xdg/autostart -name '*.desktop' 2>/dev/null | head -20")
        if result.success and result.output.strip():
            for f in result.output.strip().splitlines():
                writable = session.execute(f"test -w {f.strip()} && echo writable")
                if writable.success and "writable" in writable.output:
                    self.add_finding(
                        title=f"Writable system autostart: {f.strip()}",
                        description="System-wide autostart entry is writable — can be modified for persistence",
                        severity=Severity.HIGH,
                        evidence=f"{f.strip()} is writable by current user",
                        remediation=f"Fix permissions: chmod 644 {f.strip()}; chown root:root",
                    )

    def _check_writable_autostart_dirs(self, session: Session) -> None:
        dirs = ["/etc/xdg/autostart"]
        for d in dirs:
            result = session.execute(f"test -d {d} && test -w {d} && echo writable")
            if result.success and "writable" in result.output:
                self.add_finding(
                    title=f"Writable autostart directory: {d}",
                    description=f"{d} is writable — new autostart entries can be planted",
                    severity=Severity.HIGH,
                    evidence=f"{d} is writable",
                    remediation=f"Fix: chmod 755 {d}; chown root:root {d}",
                )

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Restrict /etc/xdg/autostart/ permissions to root only",
            "Audit user autostart entries in ~/.config/autostart/",
            "Monitor autostart directory changes with auditd",
        ]

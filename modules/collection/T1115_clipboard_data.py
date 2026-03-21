"""T1115 — Clipboard Data.

Checks X11/Wayland clipboard access on RHEL systems.
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class ClipboardDataCheck(BaseModule):
    TECHNIQUE_ID = "T1115"
    TECHNIQUE_NAME = "Clipboard Data"
    TACTIC = Tactic.COLLECTION
    SEVERITY = Severity.MEDIUM
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        self._check_clipboard_tools(session)
        self._check_display_access(session)

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def _check_clipboard_tools(self, session: Session) -> None:
        tools = {"xclip": "X11 clipboard", "xsel": "X11 selection",
                 "wl-copy": "Wayland clipboard", "wl-paste": "Wayland paste",
                 "xdotool": "X11 automation"}
        for tool, desc in tools.items():
            result = session.execute(f"which {tool} 2>/dev/null")
            if result.success and result.output.strip():
                self.add_finding(
                    title=f"Clipboard tool: {tool}",
                    description=f"{tool} ({desc}) can capture clipboard contents",
                    severity=Severity.MEDIUM,
                    evidence=result.output.strip(),
                    remediation=f"Remove {tool} from servers without GUI requirements",
                )

    def _check_display_access(self, session: Session) -> None:
        display = session.execute("echo $DISPLAY")
        if display.success and display.output.strip():
            xhost = session.execute("xhost 2>/dev/null")
            if xhost.success and "access control disabled" in xhost.output.lower():
                self.add_finding(
                    title="X11 access control is disabled",
                    description="Any local user can access the X display and capture clipboard data",
                    severity=Severity.HIGH,
                    evidence=xhost.output.strip()[:300],
                    remediation="Enable X11 access control: xhost -",
                )

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Remove clipboard tools from headless servers",
            "Enable X11 access control: xhost -",
            "Use Wayland instead of X11 for better isolation",
        ]

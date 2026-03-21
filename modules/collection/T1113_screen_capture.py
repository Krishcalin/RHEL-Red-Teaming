"""T1113 — Screen Capture.

Checks screenshot tool access and X11/Wayland permissions on RHEL systems.
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class ScreenCaptureCheck(BaseModule):
    TECHNIQUE_ID = "T1113"
    TECHNIQUE_NAME = "Screen Capture"
    TACTIC = Tactic.COLLECTION
    SEVERITY = Severity.MEDIUM
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        self._check_screenshot_tools(session)
        self._check_x11_access(session)
        self._check_framebuffer(session)

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def _check_screenshot_tools(self, session: Session) -> None:
        tools = {"xwd": "X Window dump", "scrot": "screenshot utility",
                 "import": "ImageMagick capture", "gnome-screenshot": "GNOME capture",
                 "spectacle": "KDE capture", "ffmpeg": "screen recording"}
        for tool, desc in tools.items():
            result = session.execute(f"which {tool} 2>/dev/null")
            if result.success and result.output.strip():
                self.add_finding(
                    title=f"Screenshot tool: {tool}",
                    description=f"{tool} ({desc}) can capture screen contents",
                    severity=Severity.MEDIUM,
                    evidence=result.output.strip(),
                    remediation=f"Remove {tool} from headless servers",
                )

    def _check_x11_access(self, session: Session) -> None:
        display = session.execute("echo $DISPLAY")
        if display.success and display.output.strip():
            xauth = session.execute("xauth list 2>/dev/null | wc -l")
            if xauth.success and xauth.output.strip():
                try:
                    count = int(xauth.output.strip())
                    if count > 0:
                        self.add_finding(
                            title="X11 display access available",
                            description="X11 DISPLAY is set with valid xauth — screenshots can be taken",
                            severity=Severity.MEDIUM,
                            evidence=f"DISPLAY={display.output.strip()}, {count} xauth entries",
                            remediation="Restrict X11 access; use Wayland for better isolation",
                        )
                except ValueError:
                    pass

    def _check_framebuffer(self, session: Session) -> None:
        result = session.execute("test -r /dev/fb0 && echo readable 2>/dev/null")
        if result.success and "readable" in result.output:
            self.add_finding(
                title="Framebuffer device is readable",
                description="/dev/fb0 is readable — raw screen content can be captured",
                severity=Severity.MEDIUM,
                evidence="/dev/fb0 is readable",
                remediation="Restrict /dev/fb0 access via udev rules",
            )

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Remove screenshot tools from headless servers",
            "Restrict X11 access; prefer Wayland",
            "Restrict framebuffer device access via udev",
        ]

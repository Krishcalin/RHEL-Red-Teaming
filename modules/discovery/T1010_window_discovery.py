"""T1010 — Application Window Discovery.

Checks for X11/Wayland display access and window enumeration.
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class WindowDiscoveryCheck(BaseModule):
    TECHNIQUE_ID = "T1010"
    TECHNIQUE_NAME = "Application Window Discovery"
    TACTIC = Tactic.DISCOVERY
    SEVERITY = Severity.LOW
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        # Check if X11 is running
        display = session.execute("echo $DISPLAY")
        x11_running = display.success and display.output.strip()

        if x11_running:
            # Try xdotool / wmctrl
            xdotool = session.execute("xdotool search --name '' 2>/dev/null | head -10")
            if xdotool.success and xdotool.output.strip():
                self.add_finding(
                    title="X11 window enumeration possible",
                    description="Application windows can be listed via xdotool",
                    severity=Severity.LOW,
                    evidence=f"DISPLAY={display.output.strip()}",
                    remediation="Restrict X11 access; prefer Wayland",
                )

            # Check xhost access control
            xhost = session.execute("xhost 2>/dev/null")
            if xhost.success and "access control disabled" in xhost.output.lower():
                self.add_finding(
                    title="X11 access control disabled (xhost +)",
                    description="Any user can connect to the X11 display — screen capture/keylogging risk",
                    severity=Severity.HIGH,
                    evidence=xhost.output.strip(),
                    remediation="Enable X11 access control: xhost -",
                )
        else:
            # Check if Wayland
            wayland = session.execute("echo $WAYLAND_DISPLAY")
            if wayland.success and wayland.output.strip():
                self.add_finding(
                    title="Wayland display detected",
                    description="Wayland display is active (more secure than X11 for isolation)",
                    severity=Severity.INFO,
                    evidence=f"WAYLAND_DISPLAY={wayland.output.strip()}",
                )
            else:
                self.add_finding(
                    title="No graphical display detected",
                    description="No X11 or Wayland display — headless server (good for security)",
                    severity=Severity.INFO,
                    evidence="No DISPLAY or WAYLAND_DISPLAY set",
                )

        status = Status.VULNERABLE if any(f.severity.value in ("high", "critical") for f in self._findings) else Status.NOT_VULNERABLE
        return self.make_result(status)

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Use Wayland instead of X11 for better process isolation",
            "Never run xhost + (disable access control)",
            "Run headless on servers — no GUI packages",
        ]

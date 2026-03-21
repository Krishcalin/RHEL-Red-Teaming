"""T1125 — Video Capture.

Checks camera and video device access on RHEL systems.
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class VideoCaptureCheck(BaseModule):
    TECHNIQUE_ID = "T1125"
    TECHNIQUE_NAME = "Video Capture"
    TACTIC = Tactic.COLLECTION
    SEVERITY = Severity.MEDIUM
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        self._check_video_devices(session)
        self._check_video_tools(session)

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def _check_video_devices(self, session: Session) -> None:
        result = session.execute("ls /dev/video* 2>/dev/null")
        if result.success and result.output.strip():
            readable = session.execute("test -r /dev/video0 && echo readable 2>/dev/null")
            if readable.success and "readable" in readable.output:
                self.add_finding(
                    title="Video capture devices accessible",
                    description="/dev/video* devices are accessible — camera capture is possible",
                    severity=Severity.MEDIUM,
                    evidence=result.output.strip()[:300],
                    remediation="Restrict /dev/video* access via udev rules (group video only)",
                )
            else:
                self.add_finding(
                    title="Video devices present but not readable",
                    description="Camera devices exist but are not directly readable by current user",
                    severity=Severity.LOW,
                    evidence=result.output.strip()[:300],
                    remediation="Ensure video device group restrictions are maintained",
                )

    def _check_video_tools(self, session: Session) -> None:
        tools = {"v4l2-ctl": "V4L2 control", "ffmpeg": "multimedia capture",
                 "cheese": "GNOME camera", "guvcview": "webcam viewer"}
        for tool, desc in tools.items():
            result = session.execute(f"which {tool} 2>/dev/null")
            if result.success and result.output.strip():
                self.add_finding(
                    title=f"Video capture tool: {tool}",
                    description=f"{tool} ({desc}) can capture video from cameras",
                    severity=Severity.LOW,
                    evidence=result.output.strip(),
                    remediation=f"Remove {tool} from servers without camera requirements",
                )

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Restrict /dev/video* access via udev rules",
            "Remove video capture tools from headless servers",
            "Disable USB cameras via USBGuard on servers",
        ]

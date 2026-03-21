"""T1123 — Audio Capture.

Checks microphone and audio device access on RHEL systems.
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class AudioCaptureCheck(BaseModule):
    TECHNIQUE_ID = "T1123"
    TECHNIQUE_NAME = "Audio Capture"
    TACTIC = Tactic.COLLECTION
    SEVERITY = Severity.MEDIUM
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        self._check_audio_devices(session)
        self._check_audio_tools(session)
        self._check_pulseaudio(session)

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def _check_audio_devices(self, session: Session) -> None:
        result = session.execute("ls /dev/snd/ 2>/dev/null")
        if result.success and result.output.strip():
            if "pcm" in result.output:
                self.add_finding(
                    title="Audio capture devices available",
                    description="ALSA PCM devices accessible — audio capture is possible",
                    severity=Severity.MEDIUM,
                    evidence=result.output.strip()[:300],
                    remediation="Restrict /dev/snd/ access via udev rules or group permissions",
                )

    def _check_audio_tools(self, session: Session) -> None:
        tools = {"arecord": "ALSA recorder", "parecord": "PulseAudio recorder",
                 "ffmpeg": "multimedia framework", "sox": "sound processing"}
        for tool, desc in tools.items():
            result = session.execute(f"which {tool} 2>/dev/null")
            if result.success and result.output.strip():
                self.add_finding(
                    title=f"Audio capture tool: {tool}",
                    description=f"{tool} ({desc}) can record audio from system microphones",
                    severity=Severity.MEDIUM,
                    evidence=result.output.strip(),
                    remediation=f"Remove {tool} from servers if audio is not needed",
                )

    def _check_pulseaudio(self, session: Session) -> None:
        result = session.execute("pgrep -x pulseaudio >/dev/null 2>&1 || pgrep -x pipewire >/dev/null 2>&1; echo $?")
        if result.success and result.output.strip() == "0":
            self.add_finding(
                title="Audio server running (PulseAudio/PipeWire)",
                description="Audio server is active — microphone access via audio API is possible",
                severity=Severity.LOW,
                evidence="PulseAudio or PipeWire is running",
                remediation="Disable audio server on headless servers",
            )

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Restrict audio device access via udev rules",
            "Remove audio tools from servers",
            "Disable PulseAudio/PipeWire on headless systems",
        ]

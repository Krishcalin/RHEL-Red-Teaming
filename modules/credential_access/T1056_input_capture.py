"""T1056 — Input Capture.

Checks for keylogging feasibility and input device access.
Sub-techniques: T1056.001 (Keylogging), T1056.004 (Credential API Hooking).
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class InputCaptureCheck(BaseModule):
    TECHNIQUE_ID = "T1056"
    TECHNIQUE_NAME = "Input Capture"
    TACTIC = Tactic.CREDENTIAL_ACCESS
    SEVERITY = Severity.MEDIUM
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        # T1056.001 — Keylogging
        # Check /dev/input access
        input_devs = session.execute("ls -la /dev/input/event* 2>/dev/null | head -10")
        if input_devs.success and input_devs.output.strip():
            # Check readability
            readable = session.execute("test -r /dev/input/event0 && echo readable 2>/dev/null")
            if readable.success and readable.output.strip() == "readable":
                self.add_finding(
                    title="Input devices readable",
                    description="/dev/input/event* devices are accessible — keylogging possible",
                    severity=Severity.HIGH,
                    evidence=input_devs.output.strip()[:400],
                    remediation="Restrict /dev/input access via udev rules; use input group",
                )

        # Check for keylogger tools
        keyloggers = ["logkeys", "lkl", "keysniffer", "xinput"]
        found = []
        for tool in keyloggers:
            check = session.execute(f"which {tool} 2>/dev/null")
            if check.success and check.output.strip():
                found.append(tool)

        if found:
            self.add_finding(
                title=f"Keylogging tools available: {', '.join(found)}",
                description="Tools for keyboard input capture are installed",
                severity=Severity.HIGH,
                evidence=", ".join(found),
                remediation="Remove keylogging tools from production systems",
            )

        # Check X11 keylogging feasibility (xinput)
        display = session.execute("echo $DISPLAY")
        if display.success and display.output.strip():
            xinput = session.execute("xinput list 2>/dev/null")
            if xinput.success and xinput.output.strip():
                self.add_finding(
                    title="X11 input device enumeration possible",
                    description="xinput can list input devices — X11 keylogging feasible",
                    severity=Severity.MEDIUM,
                    evidence=xinput.output.strip()[:300],
                    remediation="Use Wayland instead of X11 for input isolation",
                )

        # T1056.004 — Credential API Hooking
        # Check LD_PRELOAD feasibility
        ld_preload = session.execute("echo $LD_PRELOAD")
        if ld_preload.success and ld_preload.output.strip():
            self.add_finding(
                title=f"LD_PRELOAD is set: {ld_preload.output.strip()}",
                description="LD_PRELOAD can intercept library calls including credential functions",
                severity=Severity.HIGH,
                evidence=f"LD_PRELOAD={ld_preload.output.strip()}",
                remediation="Investigate and remove LD_PRELOAD; restrict via /etc/ld.so.preload",
            )

        # Check /etc/ld.so.preload
        preload_file = session.execute("cat /etc/ld.so.preload 2>/dev/null")
        if preload_file.success and preload_file.output.strip():
            self.add_finding(
                title="Libraries in /etc/ld.so.preload",
                description="System-wide library preloading — all processes affected",
                severity=Severity.HIGH,
                evidence=preload_file.output.strip(),
                remediation="Investigate entries in /etc/ld.so.preload; remove unauthorized libs",
            )

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Restrict /dev/input access via udev rules",
            "Use Wayland instead of X11 for input isolation",
            "Remove keylogging tools from production systems",
            "Monitor LD_PRELOAD and /etc/ld.so.preload with auditd",
        ]

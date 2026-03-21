"""T1056 — Input Capture (Collection).

Checks keylogger feasibility and input device access on RHEL systems.
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class InputCaptureCheck(BaseModule):
    TECHNIQUE_ID = "T1056"
    TECHNIQUE_NAME = "Input Capture"
    TACTIC = Tactic.COLLECTION
    SEVERITY = Severity.HIGH
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        self._check_input_devices(session)
        self._check_keylogger_tools(session)
        self._check_strace_capability(session)

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def _check_input_devices(self, session: Session) -> None:
        result = session.execute("ls -la /dev/input/event* 2>/dev/null | head -5")
        if result.success and result.output.strip():
            readable = session.execute("test -r /dev/input/event0 && echo readable 2>/dev/null")
            if readable.success and "readable" in readable.output:
                self.add_finding(
                    title="Input devices are readable",
                    description="/dev/input/ devices are readable — keystrokes can be captured",
                    severity=Severity.HIGH,
                    evidence=result.output.strip()[:300],
                    remediation="Restrict /dev/input/ access via udev rules (group input only)",
                )

    def _check_keylogger_tools(self, session: Session) -> None:
        tools = {"logkeys": "keylogger", "xinput": "X11 input monitor",
                 "showkey": "keyboard event display", "evtest": "input event tester"}
        for tool, desc in tools.items():
            result = session.execute(f"which {tool} 2>/dev/null")
            if result.success and result.output.strip():
                self.add_finding(
                    title=f"Input capture tool: {tool}",
                    description=f"{tool} ({desc}) can capture keystrokes",
                    severity=Severity.HIGH,
                    evidence=result.output.strip(),
                    remediation=f"Remove {tool} if not needed for diagnostics",
                )

    def _check_strace_capability(self, session: Session) -> None:
        ptrace = session.execute("cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null")
        if ptrace.success and ptrace.output.strip() == "0":
            strace = session.execute("which strace 2>/dev/null")
            if strace.success and strace.output.strip():
                self.add_finding(
                    title="strace available with unrestricted ptrace",
                    description="strace can attach to processes to capture input (ptrace_scope=0)",
                    severity=Severity.HIGH,
                    evidence=f"ptrace_scope=0, strace at {strace.output.strip()}",
                    remediation="Set kernel.yama.ptrace_scope=1; remove strace if not needed",
                )

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Restrict /dev/input/ device access via udev rules",
            "Remove keylogger and input capture tools",
            "Set kernel.yama.ptrace_scope=1 to restrict process tracing",
        ]

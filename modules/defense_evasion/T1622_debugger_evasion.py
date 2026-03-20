"""T1622 — Debugger Evasion.

Checks for debugging tool availability, ptrace restrictions, core dump
configuration, TracerPid status, and perf_event_paranoid settings
on RHEL systems.
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class DebuggerEvasionCheck(BaseModule):
    TECHNIQUE_ID = "T1622"
    TECHNIQUE_NAME = "Debugger Evasion"
    TACTIC = Tactic.DEFENSE_EVASION
    SEVERITY = Severity.LOW
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        self._check_debug_tools_installed(session)
        self._check_ptrace_scope(session)
        self._check_core_dumps(session)
        self._check_tracer_pid(session)
        self._check_perf_paranoid(session)

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    # -- Debugging tools installed --------------------------------------------

    def _check_debug_tools_installed(self, session: Session) -> None:
        tools = ["gdb", "strace", "ltrace", "perf", "valgrind", "objdump"]
        found = []
        for tool in tools:
            result = session.execute(f"which {tool} 2>/dev/null")
            if result.success and result.output.strip():
                found.append(f"{tool}: {result.output.strip()}")

        if found:
            self.add_finding(
                title=f"Debugging tools installed ({len(found)} tools)",
                description=(
                    "Debugging tools on production systems can be used to analyze "
                    "and evade security controls or extract sensitive memory contents"
                ),
                severity=Severity.LOW,
                evidence="\n".join(found),
                remediation="Remove unnecessary debugging tools on production systems: yum remove gdb strace ltrace",
            )

    # -- Yama ptrace_scope ----------------------------------------------------

    def _check_ptrace_scope(self, session: Session) -> None:
        result = session.execute("cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null")
        if result.success and result.output.strip():
            value = result.output.strip()
            if value == "0":
                self.add_finding(
                    title="ptrace is unrestricted (yama ptrace_scope=0)",
                    description=(
                        "Any process can ptrace any other process owned by the same user; "
                        "this allows debugger attachment and memory inspection"
                    ),
                    severity=Severity.MEDIUM,
                    evidence=f"kernel.yama.ptrace_scope = {value}",
                    remediation="Set kernel.yama.ptrace_scope=1 or higher in /etc/sysctl.d/ to restrict ptrace",
                )
        else:
            # Yama not available
            self.add_finding(
                title="Yama LSM ptrace protection not available",
                description="Yama security module is not active; ptrace is unrestricted",
                severity=Severity.MEDIUM,
                evidence="yama/ptrace_scope not found in /proc/sys/kernel/",
                remediation="Enable Yama LSM by adding 'lsm=yama' to kernel boot parameters",
            )

    # -- Core dump configuration ----------------------------------------------

    def _check_core_dumps(self, session: Session) -> None:
        # Check ulimit
        result = session.execute("ulimit -c 2>/dev/null")
        if result.success and result.output.strip():
            value = result.output.strip()
            if value != "0":
                self.add_finding(
                    title=f"Core dumps are enabled (ulimit -c = {value})",
                    description="Core dumps can contain sensitive data including credentials and encryption keys",
                    severity=Severity.LOW,
                    evidence=f"ulimit -c: {value}",
                    remediation="Disable core dumps: echo '* hard core 0' >> /etc/security/limits.conf",
                )

        # Check core_pattern
        result = session.execute("cat /proc/sys/kernel/core_pattern 2>/dev/null")
        if result.success and result.output.strip():
            pattern = result.output.strip()
            if "|" in pattern:
                # Piped to a program — check what program
                self.add_finding(
                    title="Core dumps piped to external program",
                    description=f"Core dumps are piped to: {pattern}; verify this is an authorized handler",
                    severity=Severity.LOW,
                    evidence=f"core_pattern: {pattern}",
                    remediation="Verify core dump handler is legitimate; consider disabling core dumps entirely",
                )

    # -- TracerPid in /proc/self/status ---------------------------------------

    def _check_tracer_pid(self, session: Session) -> None:
        result = session.execute("grep TracerPid /proc/self/status 2>/dev/null")
        if result.success and result.output.strip():
            line = result.output.strip()
            try:
                tracer_pid = int(line.split(":")[1].strip())
                if tracer_pid != 0:
                    tracer_info = session.execute(f"ps -p {tracer_pid} -o comm= 2>/dev/null")
                    evidence = f"{line}"
                    if tracer_info.success and tracer_info.output.strip():
                        evidence += f"\nTracer process: {tracer_info.output.strip()}"
                    self.add_finding(
                        title=f"Current process is being traced (TracerPid={tracer_pid})",
                        description="A debugger or tracing tool is attached to the current process",
                        severity=Severity.MEDIUM,
                        evidence=evidence,
                        remediation="Investigate the tracing process; restrict ptrace with yama ptrace_scope",
                    )
            except (ValueError, IndexError):
                pass

    # -- perf_event_paranoid --------------------------------------------------

    def _check_perf_paranoid(self, session: Session) -> None:
        result = session.execute("cat /proc/sys/kernel/perf_event_paranoid 2>/dev/null")
        if result.success and result.output.strip():
            try:
                value = int(result.output.strip())
                if value < 2:
                    self.add_finding(
                        title=f"perf_event_paranoid is permissive (value={value})",
                        description=(
                            "Low perf_event_paranoid allows unprivileged users to use perf "
                            "for CPU profiling and potential side-channel attacks"
                        ),
                        severity=Severity.LOW,
                        evidence=f"kernel.perf_event_paranoid = {value}",
                        remediation="Set kernel.perf_event_paranoid=2 or 3 in /etc/sysctl.d/ to restrict perf events",
                    )
            except ValueError:
                pass

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Remove debugging tools from production systems: yum remove gdb strace ltrace valgrind",
            "Set kernel.yama.ptrace_scope=1 to restrict ptrace to parent processes only",
            "Disable core dumps system-wide via /etc/security/limits.conf and sysctl",
            "Set kernel.perf_event_paranoid=2 or higher to restrict performance monitoring",
            "Use SELinux to confine debugging capabilities to authorized roles only",
        ]

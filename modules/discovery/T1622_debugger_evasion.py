"""T1622 — Debugger Evasion.

Checks for debugging tools and anti-debug protections.
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class DebuggerEvasionCheck(BaseModule):
    TECHNIQUE_ID = "T1622"
    TECHNIQUE_NAME = "Debugger Evasion"
    TACTIC = Tactic.DISCOVERY
    SEVERITY = Severity.LOW
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        # Check ptrace_scope (YAMA LSM)
        ptrace = session.execute("cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null")
        if ptrace.success and ptrace.output.strip():
            scope = ptrace.output.strip()
            if scope == "0":
                self.add_finding(
                    title="ptrace_scope = 0 (unrestricted)",
                    description="Any process can ptrace any other process owned by the same user",
                    severity=Severity.MEDIUM,
                    evidence=f"kernel.yama.ptrace_scope = {scope}",
                    remediation="Set kernel.yama.ptrace_scope = 1 or higher in /etc/sysctl.d/",
                )
            else:
                self.add_finding(
                    title=f"ptrace_scope = {scope} (restricted)",
                    description="Ptrace is restricted by YAMA LSM",
                    severity=Severity.INFO,
                    evidence=f"kernel.yama.ptrace_scope = {scope}",
                )

        # Check debugging tools availability
        debug_tools = ["gdb", "strace", "ltrace", "ptrace", "perf", "systemtap"]
        found = []
        for tool in debug_tools:
            check = session.execute(f"which {tool} 2>/dev/null")
            if check.success and check.output.strip():
                found.append(tool)

        if found:
            self.add_finding(
                title=f"Debugging tools available: {', '.join(found)}",
                description="Debugging tools can be used for process inspection and credential extraction",
                severity=Severity.LOW,
                evidence=", ".join(found),
                remediation="Remove debugging tools from production systems",
            )

        # Check core dump configuration
        core_pattern = session.execute("cat /proc/sys/kernel/core_pattern 2>/dev/null")
        if core_pattern.success and core_pattern.output.strip():
            self.add_finding(
                title="Core dump pattern configured",
                description="Core dumps may contain sensitive data (credentials, keys)",
                severity=Severity.LOW,
                evidence=f"core_pattern: {core_pattern.output.strip()}",
                remediation="Disable core dumps: set fs.suid_dumpable = 0 and ulimit -c 0",
            )

        suid_dumpable = session.execute("cat /proc/sys/fs/suid_dumpable 2>/dev/null")
        if suid_dumpable.success and suid_dumpable.output.strip() != "0":
            self.add_finding(
                title=f"SUID core dumps enabled: suid_dumpable = {suid_dumpable.output.strip()}",
                description="SUID programs can generate core dumps with elevated data",
                severity=Severity.MEDIUM,
                evidence=f"fs.suid_dumpable = {suid_dumpable.output.strip()}",
                remediation="Set fs.suid_dumpable = 0 in /etc/sysctl.d/",
            )

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Set kernel.yama.ptrace_scope = 1 or higher",
            "Remove debugging tools (gdb, strace, ltrace) from production",
            "Disable core dumps: fs.suid_dumpable = 0, ulimit -c 0",
            "Use SELinux to restrict ptrace capabilities",
        ]

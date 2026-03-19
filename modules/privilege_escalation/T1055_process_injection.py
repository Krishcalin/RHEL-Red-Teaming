"""T1055 — Process Injection.

Checks for ptrace, /proc/[pid]/mem, and VDSO hijacking feasibility.
Sub-techniques: T1055.008 (Ptrace), T1055.009 (Proc Memory), T1055.014 (VDSO).
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class ProcessInjectionCheck(BaseModule):
    TECHNIQUE_ID = "T1055"
    TECHNIQUE_NAME = "Process Injection"
    TACTIC = Tactic.PRIVILEGE_ESCALATION
    SEVERITY = Severity.HIGH
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        # T1055.008 — Ptrace System Calls
        ptrace_scope = session.execute("cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null")
        if ptrace_scope.success and ptrace_scope.output.strip():
            scope = ptrace_scope.output.strip()
            descriptions = {
                "0": "unrestricted — any process can ptrace any same-user process",
                "1": "restricted — only parent can ptrace child",
                "2": "admin-only — only CAP_SYS_PTRACE can ptrace",
                "3": "disabled — no ptrace allowed",
            }
            if scope == "0":
                self.add_finding(
                    title="ptrace_scope = 0 (unrestricted)",
                    description="Any process can attach to other same-user processes for injection",
                    severity=Severity.HIGH,
                    evidence=f"kernel.yama.ptrace_scope = {scope} ({descriptions.get(scope, '')})",
                    remediation="Set kernel.yama.ptrace_scope = 1 in /etc/sysctl.d/",
                )
            else:
                self.add_finding(
                    title=f"ptrace_scope = {scope}",
                    description=descriptions.get(scope, ""),
                    severity=Severity.INFO,
                    evidence=f"kernel.yama.ptrace_scope = {scope}",
                )
        else:
            self.add_finding(
                title="YAMA LSM ptrace_scope not available",
                description="YAMA security module may not be enabled — ptrace unrestricted",
                severity=Severity.HIGH,
                remediation="Enable YAMA LSM and set ptrace_scope = 1",
            )

        # Check for CAP_SYS_PTRACE
        cap_check = session.execute("grep -i cap /proc/self/status 2>/dev/null")
        if cap_check.success and cap_check.output.strip():
            # Parse CapEff for SYS_PTRACE (bit 19)
            for line in cap_check.output.splitlines():
                if "CapEff" in line:
                    hex_val = line.split()[-1] if line.split() else ""
                    if hex_val:
                        try:
                            caps = int(hex_val, 16)
                            if caps & (1 << 19):
                                self.add_finding(
                                    title="CAP_SYS_PTRACE capability is set",
                                    description="Current process can ptrace other processes regardless of ptrace_scope",
                                    severity=Severity.HIGH,
                                    evidence=f"CapEff: {hex_val}",
                                    remediation="Remove CAP_SYS_PTRACE from non-essential processes",
                                )
                        except ValueError:
                            pass

        # T1055.009 — Proc Memory
        proc_mem = session.execute("test -r /proc/self/mem && echo readable")
        if proc_mem.success and proc_mem.output.strip() == "readable":
            self.add_finding(
                title="/proc/self/mem is readable",
                description="Process memory can be read via procfs — code injection feasible",
                severity=Severity.LOW,
                evidence="/proc/self/mem accessible (self only is expected)",
            )

        # Check if other processes' maps are readable
        other_maps = session.execute("ls /proc/*/maps 2>/dev/null | head -5")
        if other_maps.success and other_maps.output.strip():
            readable_count = session.execute("cat /proc/*/maps 2>/dev/null | wc -l")
            if readable_count.success and readable_count.output.strip().isdigit():
                if int(readable_count.output.strip()) > 100:
                    self.add_finding(
                        title="Other processes' memory maps readable",
                        description="/proc/[pid]/maps of other users' processes are accessible",
                        severity=Severity.MEDIUM,
                        evidence="Multiple processes' memory maps are readable",
                        remediation="Mount /proc with hidepid=2",
                    )

        # T1055.014 — VDSO Hijacking
        vdso = session.execute("cat /proc/self/maps 2>/dev/null | grep vdso")
        if vdso.success and vdso.output.strip():
            self.add_finding(
                title="VDSO mapping accessible",
                description="Virtual Dynamic Shared Object is mapped — VDSO hijacking possible with ptrace",
                severity=Severity.INFO,
                evidence=vdso.output.strip(),
            )

        # Check seccomp availability
        seccomp = session.execute("grep Seccomp /proc/self/status 2>/dev/null")
        if seccomp.success and seccomp.output.strip():
            mode = seccomp.output.strip().split()[-1] if seccomp.output.split() else "0"
            if mode == "0":
                self.add_finding(
                    title="No seccomp filter on current process",
                    description="Seccomp is not restricting system calls — all syscalls allowed",
                    severity=Severity.LOW,
                    evidence=f"Seccomp mode: {mode}",
                    remediation="Use seccomp profiles for service processes",
                )

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Set kernel.yama.ptrace_scope = 1 (or higher)",
            "Mount /proc with hidepid=2",
            "Remove CAP_SYS_PTRACE from non-essential processes",
            "Use seccomp profiles to restrict system calls",
            "Use SELinux to confine process injection capabilities",
        ]

"""T1055 — Process Injection.

Checks ptrace scope restrictions, /proc/*/mem permissions, vDSO
mapping exposure, process_vm_readv/writev availability, CAP_SYS_PTRACE
on binaries, and SELinux deny_ptrace boolean on RHEL systems.
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class ProcessInjectionCheck(BaseModule):
    TECHNIQUE_ID = "T1055"
    TECHNIQUE_NAME = "Process Injection"
    TACTIC = Tactic.DEFENSE_EVASION
    SEVERITY = Severity.CRITICAL
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        self._check_ptrace_scope(session)
        self._check_proc_mem(session)
        self._check_vdso(session)
        self._check_process_vm_rw(session)
        self._check_cap_sys_ptrace(session)
        self._check_selinux_deny_ptrace(session)

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    # -- T1055.008 Ptrace --------------------------------------------------

    def _check_ptrace_scope(self, session: Session) -> None:
        result = session.execute("cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null")
        if result.success and result.output.strip():
            scope = result.output.strip()
            if scope == "0":
                self.add_finding(
                    title="Ptrace scope is unrestricted (0)",
                    description="Any process can ptrace any other process owned by the same user — enables process injection",
                    severity=Severity.CRITICAL,
                    evidence=f"kernel.yama.ptrace_scope = {scope}",
                    remediation="Set kernel.yama.ptrace_scope = 1 (or higher) in /etc/sysctl.d/99-ptrace.conf",
                )
            elif scope == "1":
                self.add_finding(
                    title="Ptrace restricted to direct children only",
                    description="Ptrace scope is set to 1 — only parent processes can trace children",
                    severity=Severity.INFO,
                    evidence=f"kernel.yama.ptrace_scope = {scope}",
                    remediation="Consider kernel.yama.ptrace_scope = 2 or 3 for stricter environments",
                )
        else:
            # Yama may not be available
            self.add_finding(
                title="Yama LSM ptrace_scope not available",
                description="The Yama security module is not loaded — ptrace is unrestricted",
                severity=Severity.HIGH,
                evidence="Unable to read /proc/sys/kernel/yama/ptrace_scope",
                remediation="Enable the Yama LSM by adding it to the kernel boot parameters",
            )

    # -- T1055.009 Proc Memory ---------------------------------------------

    def _check_proc_mem(self, session: Session) -> None:
        # Check if non-root can read other processes' mem
        result = session.execute(
            "ls -la /proc/1/mem 2>/dev/null"
        )
        if result.success and result.output.strip():
            perms = result.output.strip().split()[0] if result.output.strip().split() else ""
            if len(perms) >= 7 and perms[4] == "r":
                self.add_finding(
                    title="/proc/*/mem is group-readable",
                    description="Process memory files may be readable by non-owner processes",
                    severity=Severity.HIGH,
                    evidence=result.output.strip(),
                    remediation="Ensure kernel.yama.ptrace_scope restricts access; mount /proc with hidepid=2",
                )

        # Re-check ptrace_scope from /proc path
        result = session.execute("sysctl kernel.yama.ptrace_scope 2>/dev/null")
        if result.success and "= 0" in result.output:
            self.add_finding(
                title="kernel.yama.ptrace_scope = 0 (via sysctl)",
                description="/proc/*/mem access is unrestricted — processes can read other processes' memory",
                severity=Severity.CRITICAL,
                evidence=result.output.strip(),
                remediation="Set kernel.yama.ptrace_scope = 1 in /etc/sysctl.d/99-ptrace.conf and reload sysctl",
            )

    # -- T1055.014 VDSO Hijacking ------------------------------------------

    def _check_vdso(self, session: Session) -> None:
        result = session.execute("cat /proc/self/maps 2>/dev/null | grep vdso")
        if result.success and result.output.strip():
            for line in result.output.strip().splitlines():
                if "rwx" in line:
                    self.add_finding(
                        title="vDSO mapping is writable and executable",
                        description="A writable+executable vDSO mapping could be targeted for code injection",
                        severity=Severity.HIGH,
                        evidence=line.strip(),
                        remediation="Ensure kernel is up to date; modern kernels map vDSO as read-only executable",
                    )
                    break

    # -- process_vm_readv/writev availability ------------------------------

    def _check_process_vm_rw(self, session: Session) -> None:
        # Check if the syscall is available and usable
        result = session.execute(
            "grep -c 'process_vm_readv\\|process_vm_writev' /proc/kallsyms 2>/dev/null"
        )
        if result.success and result.output.strip():
            try:
                count = int(result.output.strip())
                if count > 0:
                    # This is expected on modern kernels — flag only if ptrace is unrestricted
                    ptrace = session.execute("cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null")
                    if ptrace.success and ptrace.output.strip() == "0":
                        self.add_finding(
                            title="process_vm_readv/writev available with unrestricted ptrace",
                            description="Cross-process memory access syscalls are available and ptrace is unrestricted",
                            severity=Severity.HIGH,
                            evidence=f"process_vm symbols: {count}, ptrace_scope: 0",
                            remediation="Restrict ptrace_scope to limit cross-process memory access",
                        )
            except ValueError:
                pass

    # -- CAP_SYS_PTRACE on binaries ----------------------------------------

    def _check_cap_sys_ptrace(self, session: Session) -> None:
        result = session.execute("getcap -r / 2>/dev/null | grep cap_sys_ptrace")
        if result.success and result.output.strip():
            for line in result.output.strip().splitlines():
                self.add_finding(
                    title=f"CAP_SYS_PTRACE capability on binary: {line.split()[0]}",
                    description="This binary can attach to and inject into other processes",
                    severity=Severity.CRITICAL,
                    evidence=line.strip(),
                    remediation=f"Remove capability if unnecessary: setcap -r {line.split()[0]}",
                )

    # -- SELinux deny_ptrace boolean ---------------------------------------

    def _check_selinux_deny_ptrace(self, session: Session) -> None:
        result = session.execute("getsebool deny_ptrace 2>/dev/null")
        if result.success and result.output.strip():
            if "off" in result.output.lower():
                self.add_finding(
                    title="SELinux deny_ptrace boolean is off",
                    description="SELinux is not blocking ptrace — processes can attach to other processes",
                    severity=Severity.HIGH,
                    evidence=result.output.strip(),
                    remediation="Enable: setsebool -P deny_ptrace 1",
                )
        else:
            # SELinux may not be available
            getenforce = session.execute("getenforce 2>/dev/null")
            if getenforce.success and getenforce.output.strip().lower() == "disabled":
                self.add_finding(
                    title="SELinux is disabled — deny_ptrace unavailable",
                    description="With SELinux disabled, there is no deny_ptrace protection",
                    severity=Severity.HIGH,
                    evidence="SELinux is disabled",
                    remediation="Enable SELinux in enforcing mode and set deny_ptrace boolean",
                )

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Set kernel.yama.ptrace_scope = 2 or 3 to restrict ptrace to root/CAP_SYS_PTRACE only",
            "Enable SELinux deny_ptrace boolean: setsebool -P deny_ptrace 1",
            "Remove CAP_SYS_PTRACE from all non-essential binaries",
            "Mount /proc with hidepid=2 to restrict process visibility",
            "Keep kernel updated to prevent vDSO and memory-mapping exploits",
        ]

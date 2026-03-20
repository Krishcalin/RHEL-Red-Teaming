"""T1106 — Native API.

Checks kernel-level security controls that restrict access to native Linux
syscalls and debugging interfaces. Covers ptrace, seccomp, eBPF, kptr_restrict,
and dmesg access.
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class NativeAPICheck(BaseModule):
    TECHNIQUE_ID = "T1106"
    TECHNIQUE_NAME = "Native API"
    TACTIC = Tactic.EXECUTION
    SEVERITY = Severity.MEDIUM
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    SYSCTL_CHECKS = [
        {
            "param": "kernel.yama.ptrace_scope",
            "description": "ptrace restriction level",
            "safe_values": ["1", "2", "3"],
            "severity": Severity.HIGH,
            "finding_title": "ptrace is unrestricted",
            "finding_desc": (
                "kernel.yama.ptrace_scope is set to 0, allowing any process to "
                "ptrace any other process owned by the same user. This enables "
                "credential dumping and code injection."
            ),
            "remediation": "Set kernel.yama.ptrace_scope = 2 in /etc/sysctl.d/99-security.conf",
        },
        {
            "param": "kernel.unprivileged_bpf_disabled",
            "description": "Unprivileged eBPF access",
            "safe_values": ["1", "2"],
            "severity": Severity.MEDIUM,
            "finding_title": "Unprivileged eBPF programs allowed",
            "finding_desc": (
                "kernel.unprivileged_bpf_disabled is 0, allowing unprivileged users "
                "to load eBPF programs. This can be used for kernel exploitation "
                "and system monitoring evasion."
            ),
            "remediation": "Set kernel.unprivileged_bpf_disabled = 1 in /etc/sysctl.d/99-security.conf",
        },
        {
            "param": "kernel.kptr_restrict",
            "description": "Kernel pointer exposure",
            "safe_values": ["1", "2"],
            "severity": Severity.MEDIUM,
            "finding_title": "Kernel pointers exposed to unprivileged users",
            "finding_desc": (
                "kernel.kptr_restrict is 0, exposing kernel symbol addresses via "
                "/proc/kallsyms. This aids kernel exploitation."
            ),
            "remediation": "Set kernel.kptr_restrict = 2 in /etc/sysctl.d/99-security.conf",
        },
        {
            "param": "kernel.dmesg_restrict",
            "description": "dmesg access restriction",
            "safe_values": ["1"],
            "severity": Severity.LOW,
            "finding_title": "dmesg accessible to unprivileged users",
            "finding_desc": (
                "kernel.dmesg_restrict is 0, allowing any user to read the kernel "
                "ring buffer. This can leak sensitive system information."
            ),
            "remediation": "Set kernel.dmesg_restrict = 1 in /etc/sysctl.d/99-security.conf",
        },
    ]

    def check(self, session: Session) -> ModuleResult:
        self._check_sysctl_params(session)
        self._check_seccomp(session)
        self._check_process_vm_access(session)

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def _check_sysctl_params(self, session: Session) -> None:
        """Check kernel sysctl parameters for security hardening."""
        for item in self.SYSCTL_CHECKS:
            result = session.execute(f"sysctl -n {item['param']} 2>/dev/null")
            if result.success and result.output.strip():
                value = result.output.strip()
                if value not in item["safe_values"]:
                    self.add_finding(
                        title=item["finding_title"],
                        description=item["finding_desc"],
                        severity=item["severity"],
                        evidence=f"{item['param']} = {value}",
                        remediation=item["remediation"],
                    )
            else:
                # Parameter not found — may not be compiled in
                self.add_finding(
                    title=f"Sysctl parameter not available: {item['param']}",
                    description=f"Could not read {item['param']}. The kernel module may not be loaded.",
                    severity=Severity.INFO,
                    evidence=f"sysctl -n {item['param']} returned no output",
                    remediation=f"Ensure {item['param']} is set in /etc/sysctl.d/99-security.conf",
                )

    def _check_seccomp(self, session: Session) -> None:
        """Check if seccomp is available and in use."""
        # Check kernel support
        seccomp_support = session.execute(
            "grep -c CONFIG_SECCOMP=y /boot/config-$(uname -r) 2>/dev/null"
        )
        if seccomp_support.success and seccomp_support.output.strip() == "0":
            self.add_finding(
                title="Seccomp not enabled in kernel",
                description="The running kernel does not have seccomp compiled in, removing a key syscall filtering layer.",
                severity=Severity.MEDIUM,
                evidence="CONFIG_SECCOMP=y not found in kernel config",
                remediation="Use a RHEL kernel with seccomp support (default in stock RHEL kernels).",
            )

        # Check if any processes use seccomp
        seccomp_procs = session.execute(
            "grep -l Seccomp /proc/*/status 2>/dev/null | head -5"
        )
        if not seccomp_procs.success or not seccomp_procs.output.strip():
            self.add_finding(
                title="No processes appear to use seccomp filtering",
                description="No running processes were found with seccomp filters applied.",
                severity=Severity.INFO,
                evidence="No /proc/*/status files with Seccomp found",
                remediation="Consider using seccomp profiles for critical services (e.g., via systemd SeccompFilter).",
            )

    def _check_process_vm_access(self, session: Session) -> None:
        """Check if process_vm_readv/writev syscalls are accessible."""
        # Check if /proc/sys/kernel/yama exists (Yama LSM)
        yama_check = session.execute("ls /proc/sys/kernel/yama/ 2>/dev/null")
        if not yama_check.success or not yama_check.output.strip():
            self.add_finding(
                title="Yama LSM not loaded",
                description=(
                    "The Yama Linux Security Module is not loaded. Without it, "
                    "process_vm_readv/writev and ptrace are less restricted."
                ),
                severity=Severity.MEDIUM,
                evidence="No /proc/sys/kernel/yama/ directory",
                remediation="Ensure Yama LSM is enabled via kernel boot parameter: security=yama,selinux",
            )

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Set kernel.yama.ptrace_scope = 2 to restrict ptrace to root only.",
            "Set kernel.unprivileged_bpf_disabled = 1 to prevent unprivileged eBPF.",
            "Set kernel.kptr_restrict = 2 and kernel.dmesg_restrict = 1.",
            "Enable Yama LSM and seccomp filters for critical services.",
            "Apply sysctl hardening via /etc/sysctl.d/99-security.conf and run sysctl --system.",
        ]

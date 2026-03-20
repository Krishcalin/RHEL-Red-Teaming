"""T1620 — Reflective Code Loading.

Checks for memfd_create usage, execution from /dev/shm, processes running
from deleted files, memfd_noexec settings, and anonymous executable memory
mappings on RHEL systems.
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class ReflectiveLoadingCheck(BaseModule):
    TECHNIQUE_ID = "T1620"
    TECHNIQUE_NAME = "Reflective Code Loading"
    TACTIC = Tactic.DEFENSE_EVASION
    SEVERITY = Severity.HIGH
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        self._check_memfd_create_usage(session)
        self._check_devshm_execution(session)
        self._check_deleted_exe(session)
        self._check_memfd_noexec(session)
        self._check_anonymous_exec_mappings(session)

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    # -- memfd_create usage via /proc/*/fd ------------------------------------

    def _check_memfd_create_usage(self, session: Session) -> None:
        result = session.execute(
            "ls -la /proc/*/fd 2>/dev/null | grep 'memfd:' | head -20"
        )
        if result.success and result.output.strip():
            entries = result.output.strip().splitlines()
            self.add_finding(
                title=f"Active memfd_create file descriptors detected ({len(entries)} found)",
                description=(
                    "Processes have file descriptors pointing to memfd: objects, "
                    "which can be used for fileless code execution"
                ),
                severity=Severity.HIGH,
                evidence="\n".join(entries[:10]),
                remediation="Investigate processes with memfd file descriptors; audit with auditd for memfd_create syscalls",
            )

    # -- Files executed from /dev/shm -----------------------------------------

    def _check_devshm_execution(self, session: Session) -> None:
        result = session.execute(
            "find /dev/shm -type f -executable 2>/dev/null | head -20"
        )
        if result.success and result.output.strip():
            executables = result.output.strip().splitlines()
            self.add_finding(
                title=f"Executable files in /dev/shm ({len(executables)} found)",
                description="/dev/shm is a tmpfs filesystem; executables here may indicate fileless malware staging",
                severity=Severity.HIGH,
                evidence="\n".join(executables[:10]),
                remediation="Mount /dev/shm with noexec option in /etc/fstab: tmpfs /dev/shm tmpfs defaults,noexec,nosuid,nodev 0 0",
            )

        # Check if /dev/shm is mounted with noexec
        result = session.execute("mount | grep '/dev/shm' | grep -v noexec")
        if result.success and result.output.strip():
            self.add_finding(
                title="/dev/shm mounted without noexec",
                description="/dev/shm allows execution of files, enabling fileless attack staging",
                severity=Severity.MEDIUM,
                evidence=result.output.strip(),
                remediation="Remount /dev/shm with noexec: mount -o remount,noexec /dev/shm",
            )

    # -- Processes running from deleted files ---------------------------------

    def _check_deleted_exe(self, session: Session) -> None:
        result = session.execute(
            "ls -la /proc/*/exe 2>/dev/null | grep '(deleted)' | head -20"
        )
        if result.success and result.output.strip():
            deleted = result.output.strip().splitlines()
            if deleted:
                self.add_finding(
                    title=f"Processes running from deleted executables ({len(deleted)} found)",
                    description=(
                        "Processes whose on-disk binary has been deleted may indicate "
                        "reflective loading or malware that removes its binary after execution"
                    ),
                    severity=Severity.HIGH,
                    evidence="\n".join(deleted[:10]),
                    remediation="Investigate processes running from deleted binaries; capture memory for forensic analysis",
                )

    # -- memfd_noexec sysctl --------------------------------------------------

    def _check_memfd_noexec(self, session: Session) -> None:
        result = session.execute("cat /proc/sys/vm/memfd_noexec 2>/dev/null")
        if result.success and result.output.strip():
            value = result.output.strip()
            if value == "0":
                self.add_finding(
                    title="memfd_noexec is not enabled",
                    description="memfd_create allows creation of executable memory-backed file descriptors",
                    severity=Severity.MEDIUM,
                    evidence=f"vm.memfd_noexec = {value}",
                    remediation="Set vm.memfd_noexec=1 in /etc/sysctl.d/ to restrict executable memfd creation",
                )
        else:
            # Sysctl not available (older kernel)
            result2 = session.execute("uname -r")
            if result2.success:
                self.add_finding(
                    title="memfd_noexec sysctl not available",
                    description="Kernel does not support memfd_noexec; executable memfd objects cannot be restricted",
                    severity=Severity.LOW,
                    evidence=f"Kernel: {result2.output.strip()}",
                    remediation="Upgrade to a kernel version that supports vm.memfd_noexec (6.3+)",
                )

    # -- Anonymous executable memory mappings ---------------------------------

    def _check_anonymous_exec_mappings(self, session: Session) -> None:
        result = session.execute(
            "for pid in $(ls /proc/ 2>/dev/null | grep '^[0-9]' | head -50); do "
            "grep -l 'rwxp.*00000000 00:00 0' /proc/$pid/maps 2>/dev/null && "
            "echo \"PID $pid: $(cat /proc/$pid/comm 2>/dev/null)\"; "
            "done | grep 'PID' | head -20"
        )
        if result.success and result.output.strip():
            procs = result.output.strip().splitlines()
            if procs:
                self.add_finding(
                    title=f"Processes with anonymous executable memory mappings ({len(procs)} found)",
                    description="Anonymous RWX memory regions can host injected or reflectively loaded code",
                    severity=Severity.MEDIUM,
                    evidence="\n".join(procs[:10]),
                    remediation="Investigate processes with anonymous executable mappings; JIT compilers may cause false positives",
                )

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Mount /dev/shm and /tmp with noexec,nosuid,nodev options in /etc/fstab",
            "Enable vm.memfd_noexec sysctl to restrict executable memfd creation",
            "Use auditd to monitor memfd_create and execveat syscalls",
            "Enable SELinux in enforcing mode to restrict anonymous executable memory regions",
            "Deploy RHEL fapolicyd to control execution of untrusted binaries and scripts",
        ]

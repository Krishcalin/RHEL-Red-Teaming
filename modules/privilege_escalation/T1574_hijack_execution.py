"""T1574 — Hijack Execution Flow.

Checks for dynamic linker hijacking and PATH manipulation.
Sub-techniques: T1574.006 (Dynamic Linker), T1574.007 (PATH Variable).
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class HijackExecutionCheck(BaseModule):
    TECHNIQUE_ID = "T1574"
    TECHNIQUE_NAME = "Hijack Execution Flow"
    TACTIC = Tactic.PRIVILEGE_ESCALATION
    SEVERITY = Severity.HIGH
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        # T1574.006 — Dynamic Linker Hijacking
        # Check /etc/ld.so.preload
        preload = session.execute("cat /etc/ld.so.preload 2>/dev/null")
        if preload.success and preload.output.strip():
            self.add_finding(
                title="Libraries in /etc/ld.so.preload",
                description="System-wide library preloading — affects all dynamically linked processes",
                severity=Severity.CRITICAL,
                evidence=preload.output.strip(),
                remediation="Investigate and remove unauthorized entries from /etc/ld.so.preload",
            )

        # Check if /etc/ld.so.preload is writable
        preload_writable = session.execute("test -w /etc/ld.so.preload && echo writable 2>/dev/null")
        if preload_writable.success and preload_writable.output.strip() == "writable":
            self.add_finding(
                title="/etc/ld.so.preload is writable!",
                description="Current user can inject libraries system-wide — trivial root escalation",
                severity=Severity.CRITICAL,
                remediation="chmod 644 /etc/ld.so.preload; chown root:root",
            )

        # Check LD_PRELOAD environment
        ld_preload = session.execute("echo $LD_PRELOAD")
        if ld_preload.success and ld_preload.output.strip():
            self.add_finding(
                title=f"LD_PRELOAD set: {ld_preload.output.strip()}",
                description="LD_PRELOAD injects libraries into all child processes",
                severity=Severity.HIGH,
                evidence=f"LD_PRELOAD={ld_preload.output.strip()}",
                remediation="Investigate and unset LD_PRELOAD",
            )

        # Check LD_LIBRARY_PATH
        ld_lib = session.execute("echo $LD_LIBRARY_PATH")
        if ld_lib.success and ld_lib.output.strip():
            self.add_finding(
                title=f"LD_LIBRARY_PATH set: {ld_lib.output.strip()}",
                description="Custom library search path — library substitution possible",
                severity=Severity.MEDIUM,
                evidence=f"LD_LIBRARY_PATH={ld_lib.output.strip()}",
                remediation="Avoid setting LD_LIBRARY_PATH; use rpath or ldconfig instead",
            )

        # Check for writable directories in ldconfig paths
        ld_conf = session.execute("ldconfig -p 2>/dev/null | head -5; cat /etc/ld.so.conf.d/*.conf 2>/dev/null")
        if ld_conf.success and ld_conf.output.strip():
            for line in ld_conf.output.splitlines():
                line = line.strip()
                if line.startswith("/") and not line.startswith("#"):
                    dir_path = line.split()[0] if line.split() else line
                    writable = session.execute(f"test -w {dir_path} && echo writable 2>/dev/null")
                    if writable.success and writable.output.strip() == "writable":
                        self.add_finding(
                            title=f"Writable library directory in ldconfig: {dir_path}",
                            description="Current user can place malicious shared libraries",
                            severity=Severity.CRITICAL,
                            evidence=f"Writable: {dir_path}",
                            remediation=f"Fix permissions: chmod 755 {dir_path}; chown root:root",
                        )
                        break  # One finding is enough

        # Check RPATH/RUNPATH in SUID binaries
        rpath_check = session.execute(
            "find /usr/bin /usr/sbin -perm -4000 -exec readelf -d {} 2>/dev/null \\; | grep -i 'rpath\\|runpath' | head -5"
        )
        if rpath_check.success and rpath_check.output.strip():
            self.add_finding(
                title="SUID binaries with RPATH/RUNPATH",
                description="SUID binaries use RPATH — may load libraries from writable paths",
                severity=Severity.HIGH,
                evidence=rpath_check.output.strip()[:300],
                remediation="Recompile without RPATH or use only absolute system paths",
            )

        # T1574.007 — PATH Variable
        path = session.execute("echo $PATH")
        if path.success and path.output.strip():
            dirs = path.output.strip().split(":")
            for d in dirs:
                if not d or d == ".":
                    self.add_finding(
                        title="Current directory (.) in PATH",
                        description="Empty or '.' entry in PATH allows binary hijacking",
                        severity=Severity.HIGH,
                        evidence=f"PATH={path.output.strip()}",
                        remediation="Remove '.' and empty entries from PATH",
                    )
                    break

            # Check for writable PATH directories
            for d in dirs:
                if d and d != ".":
                    writable = session.execute(f"test -w {d} && echo writable 2>/dev/null")
                    if writable.success and writable.output.strip() == "writable":
                        if d not in ("/usr/local/bin", "/home"):
                            self.add_finding(
                                title=f"Writable directory in PATH: {d}",
                                description="Current user can place malicious binaries in PATH",
                                severity=Severity.HIGH,
                                evidence=f"Writable PATH directory: {d}",
                                remediation=f"Fix permissions: chmod 755 {d}",
                            )

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Ensure /etc/ld.so.preload is owned by root with 644 permissions",
            "Never set LD_PRELOAD or LD_LIBRARY_PATH in production",
            "Remove '.' from PATH",
            "Ensure all PATH directories are root-owned and not world-writable",
            "Compile SUID binaries without RPATH",
            "Monitor /etc/ld.so.preload changes with auditd",
        ]

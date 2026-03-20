"""T1574 — Hijack Execution Flow.

Checks for persistence via dynamic linker hijacking (ld.so.preload,
LD_PRELOAD) and PATH interception on RHEL systems.
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class HijackExecutionCheck(BaseModule):
    TECHNIQUE_ID = "T1574"
    TECHNIQUE_NAME = "Hijack Execution Flow"
    TACTIC = Tactic.PERSISTENCE
    SEVERITY = Severity.CRITICAL
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        self._check_dynamic_linker_hijacking(session)
        self._check_path_interception(session)

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def _check_dynamic_linker_hijacking(self, session: Session) -> None:
        """T1574.006: Check for dynamic linker hijacking vectors."""
        # Check /etc/ld.so.preload
        ldso_preload = session.execute("cat /etc/ld.so.preload 2>/dev/null")
        if ldso_preload.success and ldso_preload.output.strip():
            self.add_finding(
                title="/etc/ld.so.preload contains entries",
                description="Libraries in /etc/ld.so.preload are loaded into every dynamically linked process — "
                            "a powerful persistence and rootkit mechanism",
                severity=Severity.CRITICAL,
                evidence=ldso_preload.output.strip(),
                remediation="Remove /etc/ld.so.preload unless explicitly required; verify listed libraries with rpm -qf",
            )

        # Check LD_PRELOAD in environment and profile scripts
        ld_preload_env = session.execute(
            "grep -rn 'LD_PRELOAD' /etc/environment /etc/profile /etc/profile.d/ "
            "/etc/bashrc /etc/ld.so.conf /etc/ld.so.conf.d/ "
            "/root/.bashrc /home/*/.bashrc 2>/dev/null | grep -v '^#' | head -10"
        )
        if ld_preload_env.success and ld_preload_env.output.strip():
            self.add_finding(
                title="LD_PRELOAD set in environment/profile files",
                description="LD_PRELOAD forces loading a shared library before all others — used for library injection attacks",
                severity=Severity.CRITICAL,
                evidence=ld_preload_env.output.strip()[:500],
                remediation="Remove LD_PRELOAD from profile scripts; use auditd to monitor: -w /etc/ld.so.preload -p wa",
            )

        # Check for rpath/runpath in SUID binaries
        suid_rpath = session.execute(
            "find /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -perm -4000 -type f 2>/dev/null "
            "| head -20 | while read f; do "
            "readelf -d \"$f\" 2>/dev/null | grep -E 'RPATH|RUNPATH' && echo \"  -> $f\"; "
            "done 2>/dev/null"
        )
        if suid_rpath.success and suid_rpath.output.strip():
            self.add_finding(
                title="SUID binaries with RPATH/RUNPATH set",
                description="SUID binaries with RPATH/RUNPATH can be exploited by placing malicious libraries "
                            "in the specified search paths",
                severity=Severity.CRITICAL,
                evidence=suid_rpath.output.strip()[:500],
                remediation="Recompile SUID binaries without RPATH/RUNPATH or remove SUID bit if unnecessary",
            )

        # Check /etc/ld.so.conf.d/ for suspicious entries
        ldso_conf = session.execute(
            "cat /etc/ld.so.conf.d/*.conf 2>/dev/null"
        )
        if ldso_conf.success and ldso_conf.output.strip():
            suspicious_paths = []
            for line in ldso_conf.output.strip().splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    # Flag paths outside standard lib directories
                    if not line.startswith(("/usr/lib", "/lib", "/usr/local/lib")):
                        suspicious_paths.append(line)
            if suspicious_paths:
                self.add_finding(
                    title="Unusual library search paths in ld.so.conf.d",
                    description="Non-standard library paths may be used to inject malicious shared objects",
                    severity=Severity.HIGH,
                    evidence="\n".join(suspicious_paths),
                    remediation="Remove non-standard paths from /etc/ld.so.conf.d/; run ldconfig after changes",
                )

        # Check for writable library directories in ld.so.conf
        writable_lib_dirs = session.execute(
            "ldconfig -p 2>/dev/null | awk -F'=>' '{print $2}' | xargs -I{} dirname {} 2>/dev/null "
            "| sort -u | while read d; do test -w \"$d\" && echo \"WRITABLE: $d\"; done 2>/dev/null | head -10"
        )
        if writable_lib_dirs.success and writable_lib_dirs.output.strip():
            self.add_finding(
                title="Writable library directories in linker search path",
                description="Writable directories in the dynamic linker search path allow library injection",
                severity=Severity.CRITICAL,
                evidence=writable_lib_dirs.output.strip(),
                remediation="Fix permissions on library directories: chmod 755; chown root:root",
            )

    def _check_path_interception(self, session: Session) -> None:
        """T1574.007: Check for PATH interception vulnerabilities."""
        # Check for writable directories early in PATH
        path_check = session.execute(
            "echo $PATH | tr ':' '\\n' | while read d; do "
            "test -d \"$d\" && test -w \"$d\" && echo \"WRITABLE: $d\"; "
            "done 2>/dev/null"
        )
        if path_check.success and path_check.output.strip():
            self.add_finding(
                title="Writable directories in current user's PATH",
                description="Writable PATH directories allow an attacker to place malicious binaries that shadow legitimate commands",
                severity=Severity.HIGH,
                evidence=path_check.output.strip(),
                remediation="Remove writable directories from PATH or fix permissions: chmod 755",
            )

        # Check if PATH contains "." (current directory) or empty entries
        dot_in_path = session.execute(
            "echo $PATH | tr ':' '\\n' | grep -nE '^\\.$|^$' 2>/dev/null"
        )
        if dot_in_path.success and dot_in_path.output.strip():
            self.add_finding(
                title="PATH contains current directory (.) or empty entries",
                description="Having '.' or empty entries in PATH allows execution of malicious binaries "
                            "from the current working directory",
                severity=Severity.HIGH,
                evidence=f"PATH entries: {dot_in_path.output.strip()}",
                remediation="Remove '.' and empty entries from PATH in profile scripts and /etc/environment",
            )

        # Check for writable directories in root's PATH
        root_path = session.execute(
            "sudo -n grep -E '^(export )?PATH=' /root/.bashrc /root/.bash_profile "
            "/root/.profile 2>/dev/null; "
            "grep -E '^(export )?PATH=' /etc/profile /etc/profile.d/*.sh 2>/dev/null | head -10"
        )
        if root_path.success and root_path.output.strip():
            # Parse PATH values and check writability
            for line in root_path.output.strip().splitlines():
                if "PATH=" in line:
                    path_val = line.split("PATH=", 1)[1].strip().strip('"').strip("'")
                    dirs = path_val.split(":")
                    for d in dirs:
                        d = d.strip()
                        if d in (".", ""):
                            self.add_finding(
                                title=f"Root PATH contains dangerous entry in: {line.split(':')[0]}",
                                description="Root's PATH contains '.' or empty entries — allows privilege escalation",
                                severity=Severity.CRITICAL,
                                evidence=line.strip(),
                                remediation="Remove '.' and empty entries from root's PATH",
                            )
                            break

        # Check PATH in systemd service files
        svc_path = session.execute(
            "grep -rn 'Environment.*PATH' /etc/systemd/system/ /usr/lib/systemd/system/ 2>/dev/null "
            "| head -10"
        )
        if svc_path.success and svc_path.output.strip():
            for line in svc_path.output.strip().splitlines():
                if "PATH=" in line:
                    path_val = line.split("PATH=", 1)[1].strip().strip('"').strip("'")
                    dirs = path_val.split(":")
                    suspicious = [d for d in dirs if d in (".", "") or d.startswith(("/tmp", "/home", "/dev/shm"))]
                    if suspicious:
                        self.add_finding(
                            title="Systemd service with suspicious PATH entries",
                            description="Service PATH contains writable or dangerous directories",
                            severity=Severity.HIGH,
                            evidence=line.strip(),
                            remediation="Remove dangerous entries from service PATH; use absolute paths in ExecStart",
                        )

        # Check for PATH manipulation in profile scripts
        path_append = session.execute(
            "grep -rn 'PATH=' /etc/profile.d/ 2>/dev/null | grep -v '^#' "
            "| grep -E '/tmp|/home|/dev/shm|\\./|::|:$' | head -10"
        )
        if path_append.success and path_append.output.strip():
            self.add_finding(
                title="Suspicious PATH modifications in profile scripts",
                description="Profile scripts add suspicious directories to PATH",
                severity=Severity.HIGH,
                evidence=path_append.output.strip()[:500],
                remediation="Audit PATH settings in /etc/profile.d/; remove references to writable or temporary directories",
            )

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Remove or empty /etc/ld.so.preload; monitor with auditd: -w /etc/ld.so.preload -p wa -k ld_preload",
            "Ensure no LD_PRELOAD is set in /etc/profile.d/, /etc/environment, or user shell profiles",
            "Remove RPATH/RUNPATH from SUID binaries; recompile with -Wl,--disable-new-dtags if needed",
            "Ensure all directories in PATH are owned by root and not world-writable (chmod 755)",
            "Use secure_path in /etc/sudoers to enforce a safe PATH for sudo commands",
        ]

"""T1036 — Masquerading.

Checks for binaries masquerading as legitimate system utilities,
suspicious service names, unpackaged executables in system paths,
and process-tree/argument manipulation on RHEL systems.
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class MasqueradingCheck(BaseModule):
    TECHNIQUE_ID = "T1036"
    TECHNIQUE_NAME = "Masquerading"
    TACTIC = Tactic.DEFENSE_EVASION
    SEVERITY = Severity.HIGH
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    SYSTEM_BINARIES = ["ls", "ps", "netstat", "ss", "top", "cat", "grep", "find", "bash", "sh"]

    def check(self, session: Session) -> ModuleResult:
        self._check_renamed_utilities(session)
        self._check_masquerade_service(session)
        self._check_unpackaged_binaries(session)
        self._check_break_process_trees(session)
        self._check_overwrite_process_args(session)

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    # -- T1036.003 Rename Legitimate Utilities -----------------------------

    def _check_renamed_utilities(self, session: Session) -> None:
        search_dirs = ["/usr/local/bin", "/usr/local/sbin", "/tmp", "/var/tmp", "/dev/shm"]
        for binary in self.SYSTEM_BINARIES:
            dirs_str = " ".join(search_dirs)
            result = session.execute(
                f"find {dirs_str} -name '{binary}' -type f 2>/dev/null"
            )
            if result.success and result.output.strip():
                for path in result.output.strip().splitlines():
                    self.add_finding(
                        title=f"Possible masquerading binary: {path}",
                        description=f"A file named '{binary}' exists in a non-standard location",
                        severity=Severity.HIGH,
                        evidence=path.strip(),
                        remediation=f"Investigate {path} — compare hash with legitimate binary using rpm -Vf",
                    )

        # Also check /home directories
        result = session.execute(
            "find /home -maxdepth 3 -type f \\( "
            + " -o ".join(f"-name '{b}'" for b in self.SYSTEM_BINARIES)
            + " \\) 2>/dev/null | head -20"
        )
        if result.success and result.output.strip():
            for path in result.output.strip().splitlines():
                self.add_finding(
                    title=f"System binary name found in home directory: {path}",
                    description="A file matching a system binary name was found in a user home directory",
                    severity=Severity.MEDIUM,
                    evidence=path.strip(),
                    remediation="Investigate the file origin and purpose; remove if unauthorized",
                )

    # -- T1036.004 Masquerade Task / Service -------------------------------

    def _check_masquerade_service(self, session: Session) -> None:
        # Check for services in non-standard unit file locations
        result = session.execute(
            "find /etc/systemd/system /run/systemd/system -name '*.service' -type f 2>/dev/null"
        )
        if result.success and result.output.strip():
            for svc_path in result.output.strip().splitlines():
                svc_name = svc_path.strip().split("/")[-1]
                # Check if a similarly named service exists in the vendor path
                vendor_check = session.execute(
                    f"ls /usr/lib/systemd/system/{svc_name} 2>/dev/null"
                )
                if vendor_check.success and vendor_check.output.strip():
                    self.add_finding(
                        title=f"Overriding service detected: {svc_name}",
                        description=f"A custom service at {svc_path.strip()} overrides the vendor unit",
                        severity=Severity.MEDIUM,
                        evidence=f"Custom: {svc_path.strip()}, Vendor: /usr/lib/systemd/system/{svc_name}",
                        remediation=f"Review {svc_path.strip()} for unauthorized modifications; use systemd-delta to audit overrides",
                    )

    # -- T1036.005 Match Legitimate Name / Location ------------------------

    def _check_unpackaged_binaries(self, session: Session) -> None:
        for sys_dir in ("/usr/bin", "/usr/sbin"):
            result = session.execute(
                f"find {sys_dir} -maxdepth 1 -type f -executable 2>/dev/null | "
                "while read f; do rpm -qf \"$f\" >/dev/null 2>&1 || echo \"$f\"; done | head -20"
            )
            if result.success and result.output.strip():
                files = result.output.strip().splitlines()
                self.add_finding(
                    title=f"Unpackaged executables in {sys_dir} ({len(files)} found)",
                    description=f"Executables not owned by any RPM package were found in {sys_dir}",
                    severity=Severity.HIGH,
                    evidence="\n".join(files[:10]),
                    remediation="Investigate unpackaged binaries; legitimate files should be tracked via RPM or a configuration management tool",
                )

    # -- T1036.009 Break Process Trees -------------------------------------

    def _check_break_process_trees(self, session: Session) -> None:
        # Check for orphan processes (PPID=1 excluding expected daemons)
        result = session.execute(
            "ps -eo ppid,pid,user,comm --no-headers 2>/dev/null | awk '$1==1' | "
            "grep -vE '(systemd|agetty|sshd|crond|rsyslogd|auditd|dbus|polkit|firewalld|tuned|chronyd)' | head -15"
        )
        if result.success and result.output.strip():
            lines = result.output.strip().splitlines()
            if len(lines) > 5:
                self.add_finding(
                    title=f"Unusual orphan processes detected ({len(lines)})",
                    description="Multiple processes with PPID=1 that are not standard daemons",
                    severity=Severity.MEDIUM,
                    evidence="\n".join(lines[:10]),
                    remediation="Investigate orphan processes; use auditd to track process creation via fork/clone syscalls",
                )

    # -- T1036.011 Overwrite Process Arguments -----------------------------

    def _check_overwrite_process_args(self, session: Session) -> None:
        result = session.execute(
            "ls -1 /proc/*/exe 2>/dev/null | while read exe; do "
            "pid=$(echo $exe | cut -d/ -f3); "
            "real=$(readlink $exe 2>/dev/null); "
            "cmdline=$(cat /proc/$pid/cmdline 2>/dev/null | tr '\\0' ' ' | cut -c1-100); "
            "if [ -n \"$real\" ] && [ -n \"$cmdline\" ]; then "
            "cmd_base=$(echo \"$cmdline\" | awk '{print $1}' | xargs basename 2>/dev/null); "
            "real_base=$(basename \"$real\" 2>/dev/null); "
            "if [ \"$cmd_base\" != \"$real_base\" ] && [ \"$cmd_base\" != \"$real_base (deleted)\" ]; then "
            "echo \"PID=$pid exe=$real cmdline=$cmdline\"; fi; fi; done 2>/dev/null | head -10"
        )
        if result.success and result.output.strip():
            self.add_finding(
                title="Process argument mismatch detected",
                description="Some processes have /proc/*/cmdline that does not match /proc/*/exe",
                severity=Severity.HIGH,
                evidence=result.output.strip()[:500],
                remediation="Investigate mismatched processes; enable auditd execve logging for full command tracking",
            )

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Use AIDE or rpm -Va regularly to detect modified or unpackaged system binaries",
            "Enable SELinux to prevent unauthorized binaries from executing in system paths",
            "Monitor systemd unit file changes with auditd watches on /etc/systemd/system",
            "Deploy fapolicyd to whitelist only trusted executables",
            "Use auditd execve auditing to log all process executions with full arguments",
        ]

"""T1070 — Indicator Removal.

Checks for weaknesses in log protection, command history retention,
secure deletion tool availability, timestomping risks, and persistence
of systemd journal data on RHEL systems.
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class IndicatorRemovalCheck(BaseModule):
    TECHNIQUE_ID = "T1070"
    TECHNIQUE_NAME = "Indicator Removal"
    TACTIC = Tactic.DEFENSE_EVASION
    SEVERITY = Severity.HIGH
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    LOG_FILES = [
        "/var/log/messages",
        "/var/log/secure",
        "/var/log/audit/audit.log",
    ]

    def check(self, session: Session) -> ModuleResult:
        self._check_clear_system_logs(session)
        self._check_clear_command_history(session)
        self._check_file_deletion(session)
        self._check_timestomp(session)
        self._check_clear_persistence(session)
        self._check_relocate_malware(session)

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    # -- T1070.002 Clear System Logs ---------------------------------------

    def _check_clear_system_logs(self, session: Session) -> None:
        for log_path in self.LOG_FILES:
            perms = session.execute(f"stat -c '%a %U %G' {log_path} 2>/dev/null")
            if perms.success and perms.output.strip():
                parts = perms.output.strip().split()
                if len(parts) >= 1:
                    mode = parts[0]
                    if int(mode[-1]) > 0:
                        self.add_finding(
                            title=f"Log file {log_path} is world-accessible",
                            description=f"{log_path} has other-permissions set ({mode})",
                            severity=Severity.HIGH,
                            evidence=perms.output.strip(),
                            remediation=f"Restrict permissions: chmod 600 {log_path}",
                        )

            # Check append-only attribute
            attr = session.execute(f"lsattr {log_path} 2>/dev/null")
            if attr.success and attr.output.strip():
                if "a" not in attr.output.split()[0]:
                    self.add_finding(
                        title=f"Log file {log_path} is not append-only",
                        description="Without the append-only attribute, logs can be truncated or deleted",
                        severity=Severity.MEDIUM,
                        evidence=attr.output.strip(),
                        remediation=f"Set append-only: chattr +a {log_path}",
                    )

        # logrotate config
        logrotate = session.execute("grep -r 'compress' /etc/logrotate.conf /etc/logrotate.d/ 2>/dev/null | head -5")
        if not logrotate.success or not logrotate.output.strip():
            self.add_finding(
                title="Log compression may not be configured in logrotate",
                description="Compressed and rotated logs are harder to tamper with silently",
                severity=Severity.LOW,
                evidence="No compress directive found in logrotate configuration",
                remediation="Ensure compress is set in /etc/logrotate.conf",
            )

    # -- T1070.003 Clear Command History -----------------------------------

    def _check_clear_command_history(self, session: Session) -> None:
        result = session.execute(
            "for d in /root /home/*; do "
            "[ -f \"$d/.bash_history\" ] && echo \"$d: $(ls -la $d/.bash_history 2>/dev/null)\"; "
            "done 2>/dev/null"
        )
        if result.success and result.output.strip():
            for line in result.output.strip().splitlines():
                if "rw" in line:
                    # Check if writable by others
                    parts = line.split()
                    for p in parts:
                        if p.startswith("-") and len(p) >= 10 and p[-1] != "-":
                            self.add_finding(
                                title="Bash history file has broad permissions",
                                description="History file is accessible beyond owner, allowing tampering",
                                severity=Severity.MEDIUM,
                                evidence=line.strip()[:300],
                                remediation="Set permissions: chmod 600 ~/.bash_history for each user",
                            )
                            break

        # Check immutable flag on history files
        immut = session.execute(
            "for d in /root /home/*; do "
            "[ -f \"$d/.bash_history\" ] && lsattr \"$d/.bash_history\" 2>/dev/null; "
            "done"
        )
        if immut.success and immut.output.strip():
            for line in immut.output.strip().splitlines():
                if line and "i" not in line.split()[0]:
                    filepath = line.split()[-1] if len(line.split()) >= 2 else "unknown"
                    self.add_finding(
                        title=f"History file not immutable: {filepath}",
                        description="Without the immutable attribute, history can be cleared by users",
                        severity=Severity.LOW,
                        evidence=line.strip(),
                        remediation=f"Set immutable after session: chattr +i {filepath}",
                    )

    # -- T1070.004 File Deletion -------------------------------------------

    def _check_file_deletion(self, session: Session) -> None:
        for tool in ("shred", "srm", "wipe"):
            result = session.execute(f"which {tool} 2>/dev/null")
            if result.success and result.output.strip():
                self.add_finding(
                    title=f"Secure delete tool available: {tool}",
                    description=f"{tool} is installed and could be used to securely erase evidence",
                    severity=Severity.MEDIUM,
                    evidence=result.output.strip(),
                    remediation=f"Remove {tool} if not required: yum remove $(rpm -qf {result.output.strip()} 2>/dev/null)",
                )

        # Check /tmp cleanup policies
        tmp_clean = session.execute("systemctl is-enabled systemd-tmpfiles-clean.timer 2>/dev/null")
        if tmp_clean.success and "enabled" not in tmp_clean.output.strip():
            self.add_finding(
                title="systemd-tmpfiles-clean timer is not enabled",
                description="Temporary files may persist indefinitely, or cleanup policies are missing",
                severity=Severity.LOW,
                evidence=tmp_clean.output.strip(),
                remediation="Enable systemd-tmpfiles-clean.timer for regular /tmp cleanup",
            )

    # -- T1070.006 Timestomp -----------------------------------------------

    def _check_timestomp(self, session: Session) -> None:
        # Check if touch can modify timestamps on sensitive directories
        for path in ("/etc", "/usr/bin", "/usr/sbin"):
            result = session.execute(f"test -w {path} && echo writable || echo protected")
            if result.success and "writable" in result.output:
                self.add_finding(
                    title=f"Directory {path} is writable by current user",
                    description=f"Timestamps on files in {path} can be modified via touch",
                    severity=Severity.HIGH,
                    evidence=f"{path} is writable",
                    remediation=f"Ensure {path} ownership is root:root with mode 755",
                )

        # Check for files with future timestamps
        future = session.execute(
            "find /tmp /var/tmp /dev/shm -newer /proc/uptime -type f 2>/dev/null | head -20"
        )
        if future.success and future.output.strip():
            self.add_finding(
                title="Files with future timestamps found in temp directories",
                description="Files newer than system uptime may indicate timestomping",
                severity=Severity.MEDIUM,
                evidence=future.output.strip()[:500],
                remediation="Investigate files with anomalous timestamps; enable audit rules for settimeofday/clock_settime",
            )

    # -- T1070.009 Clear Persistence ---------------------------------------

    def _check_clear_persistence(self, session: Session) -> None:
        journal_persist = session.execute("ls -d /var/log/journal 2>/dev/null")
        if not journal_persist.success or not journal_persist.output.strip():
            self.add_finding(
                title="systemd journal is not persistent",
                description="Journal is stored in volatile /run/log/journal and lost on reboot",
                severity=Severity.HIGH,
                evidence="Directory /var/log/journal does not exist",
                remediation="Create /var/log/journal and set Storage=persistent in /etc/systemd/journald.conf",
            )

        journald = session.execute("grep -E '^(SystemMaxUse|MaxRetentionSec)' /etc/systemd/journald.conf 2>/dev/null")
        if journald.success and journald.output.strip():
            for line in journald.output.strip().splitlines():
                if "SystemMaxUse" in line:
                    val = line.split("=")[-1].strip()
                    self.add_finding(
                        title=f"Journal max size limited to {val}",
                        description="A small journal size limit can cause older entries to be discarded quickly",
                        severity=Severity.LOW,
                        evidence=line.strip(),
                        remediation="Ensure SystemMaxUse is adequate for forensic retention (e.g., 2G+)",
                    )

    # -- T1070.010 Relocate Malware ----------------------------------------

    def _check_relocate_malware(self, session: Session) -> None:
        for tmp_dir in ("/tmp", "/dev/shm", "/var/tmp"):
            result = session.execute(
                f"find {tmp_dir} -maxdepth 2 -type f -mmin -60 -executable 2>/dev/null | head -10"
            )
            if result.success and result.output.strip():
                self.add_finding(
                    title=f"Recently modified executables in {tmp_dir}",
                    description="Executable files recently created or moved to a temp directory may indicate malware relocation",
                    severity=Severity.HIGH,
                    evidence=result.output.strip()[:500],
                    remediation=f"Mount {tmp_dir} with noexec,nosuid,nodev options in /etc/fstab",
                )

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Set append-only (chattr +a) on critical log files to prevent truncation",
            "Mount /tmp, /var/tmp, and /dev/shm with noexec,nosuid,nodev options",
            "Forward logs to a remote SIEM so local deletion cannot erase the evidence",
            "Enable persistent systemd journal storage in /etc/systemd/journald.conf",
            "Deploy auditd rules to monitor log deletion and timestamp modification syscalls",
        ]

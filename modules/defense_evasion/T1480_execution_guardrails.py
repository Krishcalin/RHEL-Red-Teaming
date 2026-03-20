"""T1480 — Execution Guardrails.

Checks for environmental keying in scripts, mutual exclusion via lock files,
flock usage in crontabs, environment variable gating, and time-based
execution conditions on RHEL systems.
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class ExecutionGuardrailsCheck(BaseModule):
    TECHNIQUE_ID = "T1480"
    TECHNIQUE_NAME = "Execution Guardrails"
    TACTIC = Tactic.DEFENSE_EVASION
    SEVERITY = Severity.MEDIUM
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        self._check_environmental_keying(session)
        self._check_lock_files(session)
        self._check_flock_crontabs(session)
        self._check_env_var_gating(session)
        self._check_time_based_conditions(session)

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    # -- T1480.001 Environmental keying in scripts ----------------------------

    def _check_environmental_keying(self, session: Session) -> None:
        # Check for scripts that gate execution on hostname or IP
        result = session.execute(
            "grep -rl 'hostname\\|HOSTNAME\\|$(hostname)' /tmp/ /var/tmp/ /dev/shm/ "
            "/usr/local/bin/ /opt/ 2>/dev/null | "
            "while read f; do "
            "grep -lE '(if.*hostname|hostname.*==|hostname.*!=|\\$HOSTNAME)' \"$f\" 2>/dev/null; "
            "done | sort -u | head -10"
        )
        if result.success and result.output.strip():
            scripts = result.output.strip().splitlines()
            self.add_finding(
                title=f"Scripts with hostname-based execution checks ({len(scripts)} found)",
                description=(
                    "Scripts that check hostname before executing may use environmental "
                    "keying to limit execution to specific targets"
                ),
                severity=Severity.MEDIUM,
                evidence="\n".join(scripts[:10]),
                remediation="Review scripts that gate execution on hostname; verify they are authorized",
            )

        # Check for IP-based gating
        result = session.execute(
            "grep -rlE '(ip addr|ifconfig|hostname -I)' /tmp/ /var/tmp/ /dev/shm/ "
            "/usr/local/bin/ 2>/dev/null | "
            "while read f; do "
            "grep -lE '(if.*ip addr|if.*ifconfig|\\$\\(ip addr)' \"$f\" 2>/dev/null; "
            "done | sort -u | head -10"
        )
        if result.success and result.output.strip():
            ip_scripts = result.output.strip().splitlines()
            self.add_finding(
                title=f"Scripts with IP-based execution checks ({len(ip_scripts)} found)",
                description="Scripts that check IP address before execution may target specific network environments",
                severity=Severity.MEDIUM,
                evidence="\n".join(ip_scripts[:10]),
                remediation="Audit scripts with IP address checks; investigate for targeted malicious activity",
            )

    # -- T1480.002 Lock files for mutual exclusion ----------------------------

    def _check_lock_files(self, session: Session) -> None:
        result = session.execute(
            "find /tmp /var/lock /var/run /run -name '*.lock' -o -name '*.pid' -o -name '.lck' 2>/dev/null | "
            "head -20"
        )
        if result.success and result.output.strip():
            locks = result.output.strip().splitlines()
            # Filter out known system lock files
            system_locks = [
                "subsys", "systemd", "yum", "dnf", "rpm",
                "lvm", "multipathd", "NetworkManager",
            ]
            suspicious = [
                lock for lock in locks
                if not any(sys_lock in lock for sys_lock in system_locks)
            ]
            if suspicious:
                self.add_finding(
                    title=f"Non-system lock files found ({len(suspicious)} files)",
                    description=(
                        "Lock files in temp directories may be used for mutual exclusion "
                        "to ensure only one instance of malware runs"
                    ),
                    severity=Severity.LOW,
                    evidence="\n".join(suspicious[:10]),
                    remediation="Investigate non-system lock files in /tmp, /var/lock, and /var/run",
                )

    # -- flock usage in crontabs ----------------------------------------------

    def _check_flock_crontabs(self, session: Session) -> None:
        result = session.execute(
            "grep -r 'flock' /var/spool/cron/ /etc/cron.d/ /etc/crontab 2>/dev/null | "
            "grep -v '^#' | head -10"
        )
        if result.success and result.output.strip():
            entries = result.output.strip().splitlines()
            self.add_finding(
                title=f"Cron jobs using flock for mutual exclusion ({len(entries)} entries)",
                description=(
                    "flock in crontabs ensures single-instance execution; "
                    "may be used by malware to prevent duplicate runs"
                ),
                severity=Severity.LOW,
                evidence="\n".join(entries[:10]),
                remediation="Review cron jobs using flock; verify they are legitimate scheduled tasks",
            )

    # -- Environment variable gating ------------------------------------------

    def _check_env_var_gating(self, session: Session) -> None:
        result = session.execute(
            "grep -rlE '(if.*\\$\\{?[A-Z_]+\\}?.*==|test.*\\$[A-Z_]+|"
            "\\[ -z \"\\$[A-Z_]+\" \\]|\\[ -n \"\\$[A-Z_]+\" \\])' "
            "/tmp/ /dev/shm/ /var/tmp/ 2>/dev/null | head -10"
        )
        if result.success and result.output.strip():
            scripts = result.output.strip().splitlines()
            details = []
            for script in scripts[:5]:
                detail = session.execute(
                    f"grep -nE '(if.*\\$[A-Z_]+|test.*\\$[A-Z_]+)' {script} 2>/dev/null | head -3"
                )
                if detail.success and detail.output.strip():
                    details.append(f"{script}:\n{detail.output.strip()}")

            if details:
                self.add_finding(
                    title=f"Scripts in temp dirs with environment variable checks ({len(scripts)} found)",
                    description=(
                        "Scripts that check environment variables before execution may use "
                        "environmental keying to restrict where they run"
                    ),
                    severity=Severity.MEDIUM,
                    evidence="\n".join(details[:5]),
                    remediation="Investigate scripts with environment variable gates in temporary directories",
                )

    # -- Time-based execution conditions in cron/systemd ----------------------

    def _check_time_based_conditions(self, session: Session) -> None:
        # Check for cron jobs with date checks
        result = session.execute(
            "grep -rE '(date.*\\+|\\$\\(date|if.*date)' "
            "/var/spool/cron/ /etc/cron.d/ /etc/cron.daily/ /etc/cron.hourly/ 2>/dev/null | "
            "grep -v '^#' | head -10"
        )
        if result.success and result.output.strip():
            entries = result.output.strip().splitlines()
            self.add_finding(
                title=f"Cron jobs with date-based execution conditions ({len(entries)} entries)",
                description="Cron jobs that check dates before executing may use time-based guardrails",
                severity=Severity.LOW,
                evidence="\n".join(entries[:10]),
                remediation="Review cron jobs with date conditions; verify time-gated execution is authorized",
            )

        # Check for systemd calendar-based conditions
        result = session.execute(
            "grep -rl 'ConditionFirstBoot\\|ConditionPathExists\\|ConditionHost' "
            "/etc/systemd/system/ 2>/dev/null | head -10"
        )
        if result.success and result.output.strip():
            services = result.output.strip().splitlines()
            details = []
            for svc in services[:5]:
                detail = session.execute(
                    f"grep -E '(Condition|Assert)' {svc} 2>/dev/null | head -5"
                )
                if detail.success and detail.output.strip():
                    details.append(f"{svc}:\n{detail.output.strip()}")

            if details:
                self.add_finding(
                    title=f"Systemd services with execution conditions ({len(services)} files)",
                    description="Systemd Condition/Assert directives can gate service execution on specific criteria",
                    severity=Severity.LOW,
                    evidence="\n".join(details[:5]),
                    remediation="Audit custom systemd services with conditional execution for legitimacy",
                )

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Monitor temporary directories for scripts with execution guardrails using auditd",
            "Use fapolicyd to prevent execution of unauthorized scripts in /tmp, /dev/shm, /var/tmp",
            "Audit cron and systemd configurations for conditional execution patterns regularly",
            "Enable SELinux to restrict script execution from temporary and world-writable directories",
            "Deploy file integrity monitoring (AIDE) on /etc/cron.d/ and /etc/systemd/system/",
        ]

"""T1678 — Delay Execution.

Checks for at jobs with future scheduling, cron jobs with sleep commands,
systemd timers with long delays, sleep usage in init scripts, and systemd
services with restart/startup delays on RHEL systems.
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class DelayExecutionCheck(BaseModule):
    TECHNIQUE_ID = "T1678"
    TECHNIQUE_NAME = "Delay Execution"
    TACTIC = Tactic.DEFENSE_EVASION
    SEVERITY = Severity.LOW
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        self._check_at_jobs_future(session)
        self._check_cron_reboot_sleep(session)
        self._check_systemd_timer_delays(session)
        self._check_scripts_with_sleep(session)
        self._check_systemd_service_delays(session)

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    # -- at jobs scheduled far in the future ----------------------------------

    def _check_at_jobs_future(self, session: Session) -> None:
        result = session.execute("atq 2>/dev/null")
        if result.success and result.output.strip():
            jobs = result.output.strip().splitlines()
            if jobs:
                self.add_finding(
                    title=f"Scheduled at jobs found ({len(jobs)} jobs)",
                    description="at jobs can be used to delay malicious execution; review scheduled tasks",
                    severity=Severity.LOW,
                    evidence="\n".join(jobs[:10]),
                    remediation="Review at jobs with at -c <job_id>; restrict at access via /etc/at.allow",
                )

    # -- Cron @reboot jobs with sleep -----------------------------------------

    def _check_cron_reboot_sleep(self, session: Session) -> None:
        result = session.execute(
            "grep -r '@reboot' /var/spool/cron/ /etc/cron.d/ /etc/crontab 2>/dev/null | "
            "grep -i 'sleep' | head -10"
        )
        if result.success and result.output.strip():
            entries = result.output.strip().splitlines()
            self.add_finding(
                title=f"Cron @reboot jobs with sleep delays ({len(entries)} found)",
                description="@reboot cron jobs with sleep commands delay execution to evade detection at boot time",
                severity=Severity.MEDIUM,
                evidence="\n".join(entries[:10]),
                remediation="Review @reboot cron jobs with sleep; remove unauthorized delayed execution entries",
            )

    # -- Systemd timers with long delays --------------------------------------

    def _check_systemd_timer_delays(self, session: Session) -> None:
        result = session.execute(
            "systemctl list-timers --all --no-pager 2>/dev/null | "
            "grep -v 'NEXT\\|timers listed\\|^$' | head -20"
        )
        if result.success and result.output.strip():
            timers = result.output.strip().splitlines()

            # Check for custom (non-system) timers with long delays
            result2 = session.execute(
                "for timer in $(systemctl list-unit-files '*.timer' --no-pager 2>/dev/null | "
                "awk '/enabled|static/{print $1}'); do "
                "systemctl cat \"$timer\" 2>/dev/null | grep -E '(OnBootSec|OnUnitActiveSec)' | "
                "grep -E '[0-9]+[hd]' && echo \"  -> $timer\"; "
                "done | head -20"
            )
            if result2.success and result2.output.strip():
                delayed = result2.output.strip().splitlines()
                self.add_finding(
                    title=f"Systemd timers with long execution delays found",
                    description="Timers with long OnBootSec or OnUnitActiveSec values may delay malicious execution",
                    severity=Severity.LOW,
                    evidence="\n".join(delayed[:10]),
                    remediation="Audit systemd timers for unauthorized delayed execution: systemctl list-timers --all",
                )

    # -- Sleep commands in cron.d and init.d scripts --------------------------

    def _check_scripts_with_sleep(self, session: Session) -> None:
        result = session.execute(
            "grep -rl 'sleep [0-9]' /etc/cron.d/ /etc/cron.daily/ /etc/cron.hourly/ "
            "/etc/init.d/ 2>/dev/null | head -10"
        )
        if result.success and result.output.strip():
            scripts = result.output.strip().splitlines()
            # Get details on sleep values
            details = []
            for script in scripts[:5]:
                detail = session.execute(f"grep 'sleep [0-9]' {script} 2>/dev/null | head -3")
                if detail.success and detail.output.strip():
                    details.append(f"{script}:\n{detail.output.strip()}")

            if details:
                self.add_finding(
                    title=f"Scripts with sleep commands in cron/init directories ({len(scripts)} files)",
                    description="Sleep commands in scheduled scripts can be used to delay malicious payload execution",
                    severity=Severity.LOW,
                    evidence="\n".join(details[:5]),
                    remediation="Review scripts with sleep commands in cron and init directories for legitimacy",
                )

    # -- Systemd services with RestartSec or ExecStartPre sleep ---------------

    def _check_systemd_service_delays(self, session: Session) -> None:
        result = session.execute(
            "grep -rl 'RestartSec\\|ExecStartPre.*sleep' /etc/systemd/system/ "
            "/usr/lib/systemd/system/ 2>/dev/null | "
            "while read f; do "
            "grep -E '(RestartSec|ExecStartPre.*sleep)' \"$f\" 2>/dev/null | "
            "grep -v '^#' && echo \"  -> $f\"; "
            "done | head -20"
        )
        if result.success and result.output.strip():
            entries = result.output.strip().splitlines()
            # Filter for significant delays (more than 60 seconds)
            significant = [
                line for line in entries
                if any(c.isdigit() for c in line)
            ]
            if significant:
                self.add_finding(
                    title="Systemd services with execution delays",
                    description="Services with RestartSec or ExecStartPre sleep can delay malicious activity after boot",
                    severity=Severity.LOW,
                    evidence="\n".join(significant[:10]),
                    remediation="Review systemd services with delay mechanisms; verify they are legitimate",
                )

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Restrict at command access via /etc/at.allow to authorized users only",
            "Monitor cron and systemd timer changes with auditd watches",
            "Review @reboot cron jobs regularly for unauthorized delayed execution entries",
            "Audit systemd service files for unusual RestartSec or ExecStartPre sleep patterns",
            "Use AIDE or RHEL file integrity monitoring to detect changes to cron and init scripts",
        ]

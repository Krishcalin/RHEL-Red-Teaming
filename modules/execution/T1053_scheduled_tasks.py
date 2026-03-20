"""T1053 — Scheduled Task/Job.

Checks security controls around at, cron, and systemd timers on RHEL systems.
Identifies misconfigured allow/deny lists, writable cron files, and suspicious
scheduled jobs.
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class ScheduledTaskCheck(BaseModule):
    TECHNIQUE_ID = "T1053"
    TECHNIQUE_NAME = "Scheduled Task/Job"
    TACTIC = Tactic.EXECUTION
    SEVERITY = Severity.HIGH
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    CRON_DIRS = [
        "/etc/cron.d",
        "/etc/cron.daily",
        "/etc/cron.hourly",
        "/etc/cron.weekly",
        "/etc/cron.monthly",
    ]

    def check(self, session: Session) -> ModuleResult:
        self._check_at(session)
        self._check_cron(session)
        self._check_systemd_timers(session)

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    # -- T1053.002  at --------------------------------------------------------

    def _check_at(self, session: Session) -> None:
        """Check at daemon status and access controls."""
        # Check if atd is running
        atd = session.execute("systemctl is-active atd 2>/dev/null")
        if atd.success and atd.output.strip() == "active":
            self.add_finding(
                title="atd service is running",
                description="The at daemon is active, allowing users to schedule one-time jobs.",
                severity=Severity.MEDIUM,
                evidence="systemctl is-active atd: active",
                remediation="Disable atd if not required: systemctl disable --now atd",
            )

        # Check at.allow / at.deny
        at_allow = session.execute("cat /etc/at.allow 2>/dev/null")
        at_deny = session.execute("cat /etc/at.deny 2>/dev/null")

        if not at_allow.success or not at_allow.output.strip():
            if not at_deny.success or not at_deny.output.strip():
                self.add_finding(
                    title="Neither /etc/at.allow nor /etc/at.deny is configured",
                    description=(
                        "Without at.allow or at.deny, at job access control depends on "
                        "system defaults. On RHEL, only root can use at if neither file exists, "
                        "but an empty at.deny allows all users."
                    ),
                    severity=Severity.MEDIUM,
                    evidence="at.allow: missing, at.deny: missing or empty",
                    remediation="Create /etc/at.allow with only authorized users listed.",
                )
            else:
                deny_content = at_deny.output.strip()
                if not deny_content:
                    self.add_finding(
                        title="/etc/at.deny is empty — all users can use at",
                        description="An empty at.deny file allows every user to schedule at jobs.",
                        severity=Severity.HIGH,
                        evidence="at.deny exists but is empty",
                        remediation="Create /etc/at.allow listing only authorized users.",
                    )

        # Check pending at jobs
        at_queue = session.execute("atq 2>/dev/null")
        if at_queue.success and at_queue.output.strip():
            self.add_finding(
                title="Pending at jobs found",
                description="There are scheduled at jobs in the queue that should be reviewed.",
                severity=Severity.LOW,
                evidence=at_queue.output[:500],
                remediation="Review pending at jobs and remove unauthorized entries with atrm.",
            )

    # -- T1053.003  Cron ------------------------------------------------------

    def _check_cron(self, session: Session) -> None:
        """Check cron configuration, permissions, and access controls."""
        # Check cron.allow / cron.deny
        cron_allow = session.execute("cat /etc/cron.allow 2>/dev/null")
        cron_deny = session.execute("cat /etc/cron.deny 2>/dev/null")

        if not cron_allow.success or not cron_allow.output.strip():
            if cron_deny.success and not cron_deny.output.strip():
                self.add_finding(
                    title="/etc/cron.deny is empty — all users can use cron",
                    description="An empty cron.deny with no cron.allow means all users can create crontabs.",
                    severity=Severity.HIGH,
                    evidence="cron.allow: missing, cron.deny: empty",
                    remediation="Create /etc/cron.allow with only authorized users.",
                )

        # Check user crontabs
        crontab_dir = session.execute("ls -la /var/spool/cron/ 2>/dev/null")
        if crontab_dir.success and crontab_dir.output.strip():
            lines = [
                l for l in crontab_dir.output.strip().splitlines()
                if not l.startswith("total") and l.strip()
            ]
            if lines:
                self.add_finding(
                    title="User crontabs found",
                    description="One or more users have crontab entries that should be reviewed.",
                    severity=Severity.LOW,
                    evidence=crontab_dir.output[:500],
                    remediation="Audit user crontabs: for u in $(ls /var/spool/cron/); do crontab -l -u $u; done",
                )

        # Check system cron directories for writable files
        for cron_dir in self.CRON_DIRS:
            writable = session.execute(
                f"find {cron_dir} -writable -type f 2>/dev/null"
            )
            if writable.success and writable.output.strip():
                self.add_finding(
                    title=f"Writable cron files found in {cron_dir}",
                    description=f"Files in {cron_dir} are writable by the current user, enabling persistence.",
                    severity=Severity.HIGH,
                    evidence=writable.output[:500],
                    remediation=f"Fix permissions: chmod 644 {cron_dir}/* && chown root:root {cron_dir}/*",
                )

        # Check /etc/crontab permissions
        crontab_perms = session.execute("stat -c '%a %U:%G' /etc/crontab 2>/dev/null")
        if crontab_perms.success and crontab_perms.output.strip():
            parts = crontab_perms.output.strip().split()
            if parts:
                perms = parts[0]
                if int(perms[-1]) > 4:  # world-writable
                    self.add_finding(
                        title="/etc/crontab has excessive permissions",
                        description="The main crontab file is world-writable or has loose permissions.",
                        severity=Severity.HIGH,
                        evidence=crontab_perms.output.strip(),
                        remediation="chmod 600 /etc/crontab && chown root:root /etc/crontab",
                    )

    # -- T1053.006  Systemd Timers --------------------------------------------

    def _check_systemd_timers(self, session: Session) -> None:
        """Check systemd timers for suspicious or user-created entries."""
        timers = session.execute("systemctl list-timers --all --no-pager 2>/dev/null")
        if timers.success and timers.output.strip():
            timer_lines = [
                l for l in timers.output.splitlines()
                if ".timer" in l
            ]

            if timer_lines:
                self.add_finding(
                    title=f"{len(timer_lines)} systemd timer(s) active",
                    description="Systemd timers are active and should be reviewed for unauthorized entries.",
                    severity=Severity.INFO,
                    evidence="\n".join(timer_lines[:20]),
                    remediation="Review all timers: systemctl list-timers --all",
                )

        # Check for user-created timers (non-vendor)
        user_timers = session.execute(
            "find /etc/systemd/system/ /usr/local/lib/systemd/system/ "
            "-name '*.timer' -type f 2>/dev/null"
        )
        if user_timers.success and user_timers.output.strip():
            self.add_finding(
                title="User-created systemd timers found",
                description="Custom systemd timer units exist outside vendor paths and may be used for persistence.",
                severity=Severity.MEDIUM,
                evidence=user_timers.output[:500],
                remediation="Audit custom timers and ensure they are authorized and properly secured.",
            )

        # Check for timers running as root
        root_timers = session.execute(
            "for t in $(systemctl list-timers --no-pager --no-legend 2>/dev/null | awk '{print $NF}'); do "
            "systemctl show \"$t\" --property=User 2>/dev/null | grep -q 'User=$\\|User=root' && echo \"$t\"; "
            "done"
        )
        if root_timers.success and root_timers.output.strip():
            timer_list = root_timers.output.strip().splitlines()
            if timer_list:
                self.add_finding(
                    title=f"{len(timer_list)} systemd timer(s) running as root",
                    description="Timers running as root pose a higher risk if their unit files are tampered with.",
                    severity=Severity.MEDIUM,
                    evidence="\n".join(timer_list[:15]),
                    remediation="Run timers under dedicated service accounts with DynamicUser=yes where possible.",
                )

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Create /etc/cron.allow and /etc/at.allow with only authorized users.",
            "Disable atd if one-time jobs are not required: systemctl disable --now atd.",
            "Ensure cron files are owned by root with 600/644 permissions.",
            "Audit systemd timers regularly and restrict custom timer creation with SELinux.",
            "Use auditd rules to monitor crontab changes: -w /var/spool/cron/ -p wa -k cron_mod.",
        ]

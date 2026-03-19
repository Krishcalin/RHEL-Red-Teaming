"""T1053 — Scheduled Task/Job.

Checks for cron, at, and systemd timer escalation vectors.
Sub-techniques: T1053.002 (At), T1053.003 (Cron), T1053.006 (Systemd Timers).
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class ScheduledTasksCheck(BaseModule):
    TECHNIQUE_ID = "T1053"
    TECHNIQUE_NAME = "Scheduled Task/Job"
    TACTIC = Tactic.PRIVILEGE_ESCALATION
    SEVERITY = Severity.MEDIUM
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        # T1053.003 — Cron
        # System crontabs
        cron_dirs = ["/etc/crontab", "/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly", "/etc/cron.weekly", "/etc/cron.monthly"]
        for cpath in cron_dirs:
            writable = session.execute(f"test -w {cpath} && echo writable 2>/dev/null")
            if writable.success and writable.output.strip() == "writable":
                self.add_finding(
                    title=f"Writable cron path: {cpath}",
                    description="Current user can inject scheduled tasks that run as root",
                    severity=Severity.CRITICAL,
                    evidence=f"Writable: {cpath}",
                    remediation=f"Fix permissions: chmod 644/755 {cpath}; chown root:root",
                )

        # Check for cron jobs running scripts from writable paths
        cron_content = session.execute("cat /etc/crontab /etc/cron.d/* 2>/dev/null | grep -v '^#' | grep -v '^$'")
        if cron_content.success and cron_content.output.strip():
            for line in cron_content.output.splitlines():
                parts = line.split()
                if len(parts) >= 7:
                    script = parts[6]
                    if script.startswith("/"):
                        script_writable = session.execute(f"test -w {script} && echo writable 2>/dev/null")
                        if script_writable.success and script_writable.output.strip() == "writable":
                            self.add_finding(
                                title=f"Cron executes writable script: {script}",
                                description="Root cron job runs a script that the current user can modify",
                                severity=Severity.CRITICAL,
                                evidence=line.strip(),
                                remediation=f"Fix: chmod 755 {script}; chown root:root",
                            )
                            break

        # User crontab access
        user_cron = session.execute("crontab -l 2>/dev/null")
        if user_cron.success and user_cron.output.strip() and "no crontab" not in user_cron.output.lower():
            self.add_finding(
                title="User has a crontab",
                description="Current user's scheduled tasks",
                severity=Severity.INFO,
                evidence=user_cron.output.strip()[:400],
            )

        # Check cron.allow / cron.deny
        cron_allow = session.execute("test -f /etc/cron.allow && echo exists")
        cron_deny = session.execute("test -f /etc/cron.deny && echo exists")
        if not (cron_allow.success and cron_allow.output.strip() == "exists"):
            self.add_finding(
                title="No /etc/cron.allow file",
                description="Without cron.allow, all users can create crontabs (unless in cron.deny)",
                severity=Severity.LOW,
                remediation="Create /etc/cron.allow with only authorized users",
            )

        # T1053.002 — At
        at_allow = session.execute("test -f /etc/at.allow && echo exists")
        at_active = session.execute("systemctl is-active atd 2>/dev/null")
        if at_active.success and at_active.output.strip() == "active":
            if not (at_allow.success and at_allow.output.strip() == "exists"):
                self.add_finding(
                    title="atd running without /etc/at.allow",
                    description="All users can schedule one-time tasks via 'at'",
                    severity=Severity.LOW,
                    remediation="Create /etc/at.allow or disable atd if not needed",
                )

        # T1053.006 — Systemd Timers
        writable_timers = session.execute(
            "find /etc/systemd/system /usr/lib/systemd/system -writable -name '*.timer' 2>/dev/null | head -5"
        )
        if writable_timers.success and writable_timers.output.strip():
            self.add_finding(
                title="Writable systemd timer units",
                description="Timer files can be modified to schedule arbitrary commands",
                severity=Severity.CRITICAL,
                evidence=writable_timers.output.strip(),
                remediation="Fix: chmod 644 on timer files; chown root:root",
            )

        # User timers
        user_timers = session.execute("systemctl --user list-timers --no-pager --no-legend 2>/dev/null")
        if user_timers.success and user_timers.output.strip():
            self.add_finding(
                title=f"User systemd timers active: {len(user_timers.output.strip().splitlines())}",
                description="User-level timers are configured (persistence mechanism)",
                severity=Severity.LOW,
                evidence=user_timers.output.strip()[:300],
            )

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Create /etc/cron.allow and /etc/at.allow with authorized users only",
            "Set cron directories and files to root-owned with 644/755",
            "Ensure scripts called by root cron jobs are not writable by others",
            "Set timer unit files to 644 root:root",
            "Disable atd if not needed",
        ]

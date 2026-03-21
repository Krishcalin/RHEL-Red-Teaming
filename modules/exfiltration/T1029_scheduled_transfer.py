"""T1029 — Scheduled Transfer.

Checks for timed data exfiltration feasibility via cron, at jobs,
and systemd timers on RHEL systems.
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class ScheduledTransferCheck(BaseModule):
    TECHNIQUE_ID = "T1029"
    TECHNIQUE_NAME = "Scheduled Transfer"
    TACTIC = Tactic.EXFILTRATION
    SEVERITY = Severity.MEDIUM
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        self._check_cron_access(session)
        self._check_at_access(session)
        self._check_rsync_cron(session)

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def _check_cron_access(self, session: Session) -> None:
        allow = session.execute("cat /etc/cron.allow 2>/dev/null")
        deny = session.execute("cat /etc/cron.deny 2>/dev/null")
        if not allow.success or not allow.output.strip():
            if not deny.success or not deny.output.strip():
                self.add_finding(
                    title="No cron access restrictions",
                    description="Neither cron.allow nor cron.deny restricts cron — any user can schedule transfers",
                    severity=Severity.MEDIUM,
                    evidence="No /etc/cron.allow or /etc/cron.deny",
                    remediation="Create /etc/cron.allow with only authorized users",
                )

    def _check_at_access(self, session: Session) -> None:
        at_cmd = session.execute("which at 2>/dev/null")
        if at_cmd.success and at_cmd.output.strip():
            allow = session.execute("cat /etc/at.allow 2>/dev/null")
            if not allow.success or not allow.output.strip():
                self.add_finding(
                    title="at command available without restrictions",
                    description="at can schedule one-time transfers; no at.allow file restricts access",
                    severity=Severity.MEDIUM,
                    evidence="at is available; no /etc/at.allow",
                    remediation="Create /etc/at.allow with only authorized users",
                )

    def _check_rsync_cron(self, session: Session) -> None:
        result = session.execute(
            "crontab -l 2>/dev/null | grep -E 'rsync|scp|sftp'; "
            "grep -r 'rsync\\|scp\\|sftp' /etc/cron.d/ /etc/crontab 2>/dev/null"
        )
        if result.success and result.output.strip():
            for line in result.output.strip().splitlines():
                if line.strip() and not line.strip().startswith("#"):
                    self.add_finding(
                        title="Scheduled file transfer in cron",
                        description="A cron job performs file transfers — verify it is authorized",
                        severity=Severity.MEDIUM,
                        evidence=line.strip()[:300],
                        remediation="Audit and remove unauthorized scheduled transfers",
                    )
                    break

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Create /etc/cron.allow with only authorized users",
            "Create /etc/at.allow to restrict at job scheduling",
            "Audit cron jobs for unauthorized file transfers",
            "Monitor scheduled task creation with auditd",
        ]

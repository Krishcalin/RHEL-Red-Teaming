"""T1020 — Automated Exfiltration.

Checks for automated data transfer mechanisms (cron + network tools,
scheduled transfers) on RHEL systems.
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class AutomatedExfilCheck(BaseModule):
    TECHNIQUE_ID = "T1020"
    TECHNIQUE_NAME = "Automated Exfiltration"
    TACTIC = Tactic.EXFILTRATION
    SEVERITY = Severity.HIGH
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        self._check_cron_network_tools(session)
        self._check_systemd_timers(session)
        self._check_inotify_tools(session)

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def _check_cron_network_tools(self, session: Session) -> None:
        result = session.execute(
            "crontab -l 2>/dev/null; cat /etc/crontab 2>/dev/null; "
            "cat /etc/cron.d/* 2>/dev/null"
        )
        if result.success and result.output.strip():
            network_cmds = ["curl", "wget", "scp", "rsync", "ftp", "nc", "ssh"]
            for cmd in network_cmds:
                if cmd in result.output:
                    self.add_finding(
                        title=f"Cron job uses network tool: {cmd}",
                        description=f"A scheduled cron job invokes {cmd} — potential automated exfiltration",
                        severity=Severity.HIGH,
                        evidence=[l for l in result.output.splitlines() if cmd in l][0][:300],
                        remediation=f"Audit cron jobs using {cmd}; ensure they are authorized",
                    )

    def _check_systemd_timers(self, session: Session) -> None:
        result = session.execute("systemctl list-timers --all --no-pager 2>/dev/null | grep -v 'NEXT\\|timers listed'")
        if result.success and result.output.strip():
            lines = [l for l in result.output.strip().splitlines() if l.strip()]
            if len(lines) > 10:
                self.add_finding(
                    title=f"Many systemd timers active ({len(lines)})",
                    description="Numerous scheduled timers may include automated data transfers",
                    severity=Severity.LOW,
                    evidence=f"{len(lines)} active timers",
                    remediation="Audit all systemd timers for unauthorized scheduled transfers",
                )

    def _check_inotify_tools(self, session: Session) -> None:
        for tool in ["inotifywait", "inotifywatch", "fswatch"]:
            result = session.execute(f"which {tool} 2>/dev/null")
            if result.success and result.output.strip():
                self.add_finding(
                    title=f"File watcher available: {tool}",
                    description=f"{tool} can trigger automated exfiltration on file changes",
                    severity=Severity.LOW,
                    evidence=result.output.strip(),
                    remediation=f"Remove {tool} if not needed; monitor its usage with auditd",
                )

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Audit all cron jobs and systemd timers for network tool usage",
            "Restrict cron access via /etc/cron.allow",
            "Monitor file watchers (inotifywait) with auditd",
            "Implement egress filtering to detect automated transfers",
        ]

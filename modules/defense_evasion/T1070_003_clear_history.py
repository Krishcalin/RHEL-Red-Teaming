"""T1070.003 — Clear Command History.

Checks for command history tampering controls and history file
protections on RHEL systems.
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class ClearHistoryCheck(BaseModule):
    TECHNIQUE_ID = "T1070.003"
    TECHNIQUE_NAME = "Clear Command History"
    TACTIC = Tactic.DEFENSE_EVASION
    SEVERITY = Severity.MEDIUM
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        self._check_history_protection(session)
        self._check_history_append(session)
        self._check_syslog_history(session)

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def _check_history_protection(self, session: Session) -> None:
        result = session.execute(
            "find /home /root -name '.bash_history' -exec ls -la {} + 2>/dev/null | head -10"
        )
        if result.success and result.output.strip():
            for line in result.output.strip().splitlines():
                parts = line.split()
                if len(parts) >= 9:
                    perms = parts[0]
                    path = parts[-1]
                    # Check if writable by group/others
                    if perms[5] == "w" or perms[8] == "w":
                        self.add_finding(
                            title=f"History file overly permissive: {path}",
                            description="Other users can modify this history file to clear evidence",
                            severity=Severity.MEDIUM,
                            evidence=line[:300],
                            remediation=f"Fix: chmod 600 {path}",
                        )

        # Check for immutable flag
        immutable = session.execute("lsattr /root/.bash_history 2>/dev/null")
        if immutable.success and immutable.output.strip():
            if "a" not in immutable.output.split()[0]:
                self.add_finding(
                    title="Root history file is not append-only",
                    description="Root's .bash_history can be truncated or deleted",
                    severity=Severity.LOW,
                    evidence=immutable.output.strip(),
                    remediation="Set append-only: chattr +a /root/.bash_history",
                )

    def _check_history_append(self, session: Session) -> None:
        result = session.execute(
            "grep -r 'shopt.*histappend\\|PROMPT_COMMAND.*history' /etc/profile.d/ /etc/bashrc 2>/dev/null"
        )
        if not result.success or not result.output.strip():
            self.add_finding(
                title="History append mode not enforced system-wide",
                description="Without 'shopt -s histappend', history is overwritten on session close",
                severity=Severity.MEDIUM,
                evidence="No histappend in /etc/profile.d/ or /etc/bashrc",
                remediation="Add 'shopt -s histappend' and PROMPT_COMMAND history flush to /etc/profile.d/history.sh",
            )

    def _check_syslog_history(self, session: Session) -> None:
        result = session.execute(
            "grep -r 'PROMPT_COMMAND.*logger\\|PROMPT_COMMAND.*syslog' /etc/profile.d/ /etc/bashrc 2>/dev/null"
        )
        if not result.success or not result.output.strip():
            self.add_finding(
                title="Command history not forwarded to syslog",
                description="Commands are only stored in local history files — easily cleared by attackers",
                severity=Severity.MEDIUM,
                evidence="No syslog/logger in PROMPT_COMMAND",
                remediation="Forward commands to syslog via PROMPT_COMMAND in /etc/profile.d/",
            )

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Set append-only attribute on history files: chattr +a .bash_history",
            "Enforce histappend system-wide via /etc/profile.d/",
            "Forward command history to syslog for tamper-proof logging",
            "Set strict permissions (600) on all history files",
        ]

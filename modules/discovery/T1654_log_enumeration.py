"""T1654 — Log Enumeration.

Checks log file accessibility and audit configuration.
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule

LOG_FILES = [
    ("/var/log/messages", "System messages"),
    ("/var/log/secure", "Authentication logs"),
    ("/var/log/audit/audit.log", "Audit log"),
    ("/var/log/cron", "Cron job logs"),
    ("/var/log/maillog", "Mail logs"),
    ("/var/log/boot.log", "Boot log"),
    ("/var/log/dmesg", "Kernel ring buffer"),
    ("/var/log/yum.log", "Package manager log"),
    ("/var/log/dnf.log", "DNF package log"),
    ("/var/log/httpd/access_log", "Apache access log"),
    ("/var/log/httpd/error_log", "Apache error log"),
    ("/var/log/nginx/access.log", "Nginx access log"),
]


class LogEnumerationCheck(BaseModule):
    TECHNIQUE_ID = "T1654"
    TECHNIQUE_NAME = "Log Enumeration"
    TACTIC = Tactic.DISCOVERY
    SEVERITY = Severity.LOW
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        readable_logs = []
        for path, desc in LOG_FILES:
            result = session.execute(f"test -r {path} && echo readable")
            if result.success and result.output.strip() == "readable":
                readable_logs.append(f"{path} ({desc})")

        if readable_logs:
            self.add_finding(
                title=f"Log files readable: {len(readable_logs)}",
                description="Security-relevant log files are accessible to the current user",
                severity=Severity.LOW,
                evidence="\n".join(readable_logs),
                remediation="Restrict log file permissions to root:adm 640",
            )

        # Check journald access
        journal = session.execute("journalctl -n 5 --no-pager 2>/dev/null")
        if journal.success and journal.output.strip() and "No journal files" not in journal.output:
            self.add_finding(
                title="Journald logs accessible",
                description="Systemd journal is readable by the current user",
                severity=Severity.LOW,
                evidence=journal.output.strip()[:300],
                remediation="Restrict journald access via Storage=persistent and group permissions",
            )

        # Check auditd status
        auditd = session.execute("systemctl is-active auditd 2>/dev/null")
        if not auditd.success or auditd.output.strip() != "active":
            self.add_finding(
                title="auditd is not running",
                description="Linux Audit Daemon is not active — no audit trail",
                severity=Severity.HIGH,
                remediation="Enable auditd: systemctl enable --now auditd",
            )

        # Check if logs are forwarded to remote syslog
        remote_log = session.execute("grep -r '@@\\|@' /etc/rsyslog.conf /etc/rsyslog.d/ 2>/dev/null | grep -v '^#'")
        if not remote_log.success or not remote_log.output.strip():
            self.add_finding(
                title="No remote log forwarding configured",
                description="Logs are only stored locally — can be tampered by an attacker with access",
                severity=Severity.MEDIUM,
                remediation="Configure rsyslog to forward logs to a remote SIEM/syslog server",
            )

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Restrict log file permissions to root:adm 640",
            "Enable and configure auditd with comprehensive rules",
            "Forward logs to a remote SIEM/syslog server",
            "Enable journald persistent storage with restricted access",
        ]

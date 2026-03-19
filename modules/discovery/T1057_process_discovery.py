"""T1057 — Process Discovery.

Checks what process information is visible to the current user.
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule

INTERESTING_PROCESSES = [
    "sshd", "httpd", "nginx", "apache", "mysql", "mariadb", "postgres",
    "docker", "podman", "containerd", "kubelet", "named", "bind",
    "smbd", "nmbd", "winbind", "sssd", "krb5kdc", "kadmind",
    "auditd", "rsyslogd", "firewalld", "NetworkManager",
    "puppet", "chef", "ansible", "salt-minion", "nagios", "zabbix",
]


class ProcessDiscoveryCheck(BaseModule):
    TECHNIQUE_ID = "T1057"
    TECHNIQUE_NAME = "Process Discovery"
    TACTIC = Tactic.DISCOVERY
    SEVERITY = Severity.INFO
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        # Check if all processes are visible
        ps_result = session.execute("ps aux 2>/dev/null")
        if ps_result.success:
            lines = ps_result.output.strip().splitlines()
            total_procs = len(lines) - 1  # minus header
            unique_users = set()
            for line in lines[1:]:
                parts = line.split()
                if parts:
                    unique_users.add(parts[0])

            self.add_finding(
                title=f"Process list visible: {total_procs} processes, {len(unique_users)} users",
                description="Full process list including other users' processes is accessible",
                severity=Severity.INFO,
                evidence=f"Users with running processes: {', '.join(sorted(unique_users)[:15])}",
                remediation="Mount /proc with hidepid=2 to restrict process visibility",
            )

            # Check for interesting/sensitive processes
            found_interesting = []
            for proc in INTERESTING_PROCESSES:
                for line in lines[1:]:
                    if proc in line.lower():
                        found_interesting.append(line.strip()[:120])
                        break

            if found_interesting:
                self.add_finding(
                    title=f"Interesting services discovered: {len(found_interesting)}",
                    description="Security-relevant processes visible to the current user",
                    severity=Severity.LOW,
                    evidence="\n".join(found_interesting[:20]),
                    remediation="Use hidepid=2 on /proc; restrict service info exposure",
                )

        # Check for processes running as root with command-line credentials
        cred_check = session.execute(
            "ps aux 2>/dev/null | grep -iE '(password|passwd|secret|token|key=)' | grep -v grep | head -10"
        )
        if cred_check.success and cred_check.output.strip():
            self.add_finding(
                title="Processes with potential credentials in command line",
                description="Running processes expose credentials in their command-line arguments",
                severity=Severity.HIGH,
                evidence=cred_check.output.strip()[:500],
                remediation="Pass credentials via environment variables or config files, not CLI arguments",
            )

        # Check /proc/[pid]/environ accessibility
        environ_check = session.execute(
            "ls /proc/*/environ 2>/dev/null | head -5 && cat /proc/1/environ 2>/dev/null | tr '\\0' '\\n' | head -3"
        )
        if environ_check.success and environ_check.output.strip():
            self.add_finding(
                title="/proc/[pid]/environ readable for some processes",
                description="Process environment variables (potentially containing secrets) are accessible",
                severity=Severity.MEDIUM,
                evidence="Environment variables of other processes are readable via /proc",
                remediation="Mount /proc with hidepid=2; use SELinux to restrict /proc access",
            )

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Mount /proc with hidepid=2 or hidepid=invisible",
            "Never pass credentials as command-line arguments",
            "Use systemd ProtectProc=invisible for sensitive services",
            "Enable SELinux process isolation",
        ]

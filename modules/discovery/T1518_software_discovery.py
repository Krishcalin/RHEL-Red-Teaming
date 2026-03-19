"""T1518 — Software Discovery.

Enumerates installed software, security tools, and backup agents.
Sub-techniques: T1518.001 (Security Software), T1518.002 (Backup Software).
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule

SECURITY_SOFTWARE = [
    ("aide", "AIDE file integrity checker"),
    ("tripwire", "Tripwire file integrity"),
    ("ossec", "OSSEC HIDS"),
    ("wazuh", "Wazuh security agent"),
    ("falcon-sensor", "CrowdStrike Falcon EDR"),
    ("mdatp", "Microsoft Defender ATP"),
    ("clamd", "ClamAV antivirus"),
    ("freshclam", "ClamAV updater"),
    ("rkhunter", "Rootkit Hunter"),
    ("chkrootkit", "chkrootkit"),
    ("snort", "Snort IDS"),
    ("suricata", "Suricata IDS/IPS"),
    ("auditd", "Linux Audit Daemon"),
    ("rsyslogd", "Rsyslog"),
    ("firewalld", "Firewall daemon"),
    ("fail2ban", "Fail2ban intrusion prevention"),
    ("sshguard", "SSHGuard brute-force protection"),
]

BACKUP_SOFTWARE = [
    ("bacula", "Bacula backup"),
    ("bareos", "Bareos backup"),
    ("borgbackup", "BorgBackup"),
    ("restic", "Restic backup"),
    ("duplicity", "Duplicity backup"),
    ("rdiff-backup", "rdiff-backup"),
    ("amanda", "Amanda backup"),
    ("rear", "ReaR disaster recovery"),
    ("veeam", "Veeam backup agent"),
]


class SoftwareDiscoveryCheck(BaseModule):
    TECHNIQUE_ID = "T1518"
    TECHNIQUE_NAME = "Software Discovery"
    TACTIC = Tactic.DISCOVERY
    SEVERITY = Severity.INFO
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        # Installed packages count
        rpm_count = session.execute("rpm -qa 2>/dev/null | wc -l")
        if rpm_count.success:
            self.add_finding(
                title=f"Installed packages: {rpm_count.output.strip()}",
                description="Package inventory is accessible via rpm",
                severity=Severity.INFO,
                evidence=f"Total RPM packages: {rpm_count.output.strip()}",
            )

        # T1518.001 — Security Software Discovery
        security_found = []
        security_missing = []
        for name, desc in SECURITY_SOFTWARE:
            check = session.execute(f"rpm -q {name} 2>/dev/null || systemctl is-active {name} 2>/dev/null")
            if check.success and "not installed" not in check.output and "inactive" not in check.output:
                security_found.append(f"{name}: {desc}")
            elif name in ("auditd", "firewalld"):
                security_missing.append(f"{name}: {desc}")

        if security_found:
            self.add_finding(
                title=f"Security software detected: {len(security_found)}",
                description="Active security tools on the system",
                severity=Severity.INFO,
                evidence="\n".join(security_found),
            )

        if security_missing:
            self.add_finding(
                title=f"Critical security software missing: {len(security_missing)}",
                description="Expected security tools are not installed or not active",
                severity=Severity.HIGH,
                evidence="\n".join(security_missing),
                remediation="Install and enable missing security software",
            )

        # Check SELinux status
        selinux = session.execute("getenforce 2>/dev/null")
        if selinux.success:
            mode = selinux.output.strip()
            if mode.lower() != "enforcing":
                self.add_finding(
                    title=f"SELinux is {mode}",
                    description="SELinux is not in enforcing mode — reduced security posture",
                    severity=Severity.HIGH,
                    evidence=f"SELinux mode: {mode}",
                    remediation="Set SELinux to enforcing: setenforce 1 and SELINUX=enforcing in /etc/selinux/config",
                )

        # T1518.002 — Backup Software Discovery
        backup_found = []
        for name, desc in BACKUP_SOFTWARE:
            check = session.execute(f"which {name} 2>/dev/null || rpm -q {name} 2>/dev/null")
            if check.success and "not installed" not in check.output and check.output.strip():
                backup_found.append(f"{name}: {desc}")

        if backup_found:
            self.add_finding(
                title=f"Backup software detected: {len(backup_found)}",
                description="Backup tools found — potential target for data access or destruction",
                severity=Severity.INFO,
                evidence="\n".join(backup_found),
                remediation="Protect backup configurations and credentials",
            )

        # Check for development tools that could aid attackers
        dev_tools = ["gcc", "make", "gdb", "strace", "ltrace", "python3", "perl", "curl", "wget"]
        found_tools = []
        for tool in dev_tools:
            check = session.execute(f"which {tool} 2>/dev/null")
            if check.success and check.output.strip():
                found_tools.append(tool)

        if found_tools:
            self.add_finding(
                title=f"Development/utility tools available: {len(found_tools)}",
                description="Tools that could assist post-exploitation are installed",
                severity=Severity.LOW,
                evidence=", ".join(found_tools),
                remediation="Remove unnecessary development tools from production systems",
            )

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Set SELinux to enforcing mode",
            "Install and enable auditd, firewalld, and file integrity monitoring",
            "Remove development tools (gcc, gdb, strace) from production systems",
            "Protect backup tool configurations and credentials",
            "Restrict rpm/yum/dnf access to authorized administrators",
        ]

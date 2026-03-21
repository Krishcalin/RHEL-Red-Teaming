"""T1485 — Data Destruction.

Checks for destructive tool availability, backup status, and file-system
protections that could prevent or detect mass data deletion on RHEL systems.
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class DataDestructionCheck(BaseModule):
    TECHNIQUE_ID = "T1485"
    TECHNIQUE_NAME = "Data Destruction"
    TACTIC = Tactic.IMPACT
    SEVERITY = Severity.CRITICAL
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        self._check_destructive_tools(session)
        self._check_immutable_attrs(session)
        self._check_backup_status(session)
        self._check_trash_cli(session)

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def _check_destructive_tools(self, session: Session) -> None:
        tools = {"shred": "secure file overwrite", "wipe": "secure file wipe",
                 "srm": "secure remove", "dd": "raw disk write"}
        for tool, desc in tools.items():
            result = session.execute(f"which {tool} 2>/dev/null")
            if result.success and result.output.strip():
                self.add_finding(
                    title=f"Destructive tool available: {tool}",
                    description=f"{tool} ({desc}) is available at {result.output.strip()}",
                    severity=Severity.MEDIUM,
                    evidence=result.output.strip(),
                    remediation=f"Restrict access to {tool} via permissions or remove if not needed",
                )

    def _check_immutable_attrs(self, session: Session) -> None:
        critical_dirs = ["/etc", "/var/log"]
        for d in critical_dirs:
            result = session.execute(f"lsattr -R {d} 2>/dev/null | grep -c '\\-i\\-' || echo 0")
            if result.success:
                try:
                    count = int(result.output.strip())
                    if count == 0:
                        self.add_finding(
                            title=f"No immutable files in {d}",
                            description=f"No files in {d} have the immutable attribute set — they can be freely deleted",
                            severity=Severity.LOW,
                            evidence=f"immutable file count in {d}: 0",
                            remediation=f"Set immutable attribute on critical configs: chattr +i <file>",
                        )
                except ValueError:
                    pass

    def _check_backup_status(self, session: Session) -> None:
        backup_tools = ["borgbackup", "restic", "rdiff-backup", "bacula-client", "amanda-client"]
        installed = []
        for pkg in backup_tools:
            result = session.execute(f"rpm -q {pkg} 2>/dev/null")
            if result.success and "not installed" not in result.output:
                installed.append(pkg)

        if not installed:
            self.add_finding(
                title="No backup software detected",
                description="No common backup tools are installed — data destruction may be unrecoverable",
                severity=Severity.HIGH,
                evidence="Checked: " + ", ".join(backup_tools),
                remediation="Install and configure a backup solution (e.g., borgbackup, restic)",
            )

    def _check_trash_cli(self, session: Session) -> None:
        result = session.execute("alias rm 2>/dev/null; grep -r 'alias rm' /etc/profile.d/ 2>/dev/null")
        if not result.success or "trash" not in result.output.lower():
            self.add_finding(
                title="rm is not aliased to trash",
                description="rm directly deletes files without a safety net",
                severity=Severity.INFO,
                evidence="No rm-to-trash alias found",
                remediation="Consider aliasing rm to trash-cli for non-root users",
            )

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Implement regular, tested, off-site backups with versioning",
            "Set immutable attributes on critical configuration files",
            "Restrict access to destructive tools (shred, dd) via file permissions",
            "Use filesystem snapshots (LVM, Btrfs) for rapid recovery",
            "Enable audit rules on unlink/rename syscalls for sensitive paths",
        ]

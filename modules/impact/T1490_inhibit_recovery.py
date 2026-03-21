"""T1490 — Inhibit System Recovery.

Checks backup destruction feasibility, bootloader protection, rescue mode
access, and snapshot/recovery infrastructure on RHEL systems.
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class InhibitRecoveryCheck(BaseModule):
    TECHNIQUE_ID = "T1490"
    TECHNIQUE_NAME = "Inhibit System Recovery"
    TACTIC = Tactic.IMPACT
    SEVERITY = Severity.CRITICAL
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        self._check_grub_protection(session)
        self._check_rescue_mode(session)
        self._check_lvm_snapshots(session)
        self._check_backup_accessibility(session)
        self._check_kdump(session)

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def _check_grub_protection(self, session: Session) -> None:
        grub_pw = session.execute("grep -c 'password_pbkdf2\\|set superusers' /etc/grub2.cfg /boot/grub2/grub.cfg 2>/dev/null")
        if grub_pw.success:
            try:
                count = int(grub_pw.output.strip().split(":")[-1] if ":" in grub_pw.output else grub_pw.output.strip())
            except ValueError:
                count = 0
            if count == 0:
                self.add_finding(
                    title="GRUB bootloader is not password-protected",
                    description="An attacker with console access can modify boot parameters to bypass security controls",
                    severity=Severity.HIGH,
                    evidence="No password_pbkdf2 or superusers in grub.cfg",
                    remediation="Set GRUB password: grub2-setpassword",
                )

    def _check_rescue_mode(self, session: Session) -> None:
        rescue = session.execute("systemctl is-enabled rescue.service 2>/dev/null")
        emergency = session.execute("systemctl is-enabled emergency.service 2>/dev/null")
        for name, result in [("rescue", rescue), ("emergency", emergency)]:
            if result.success and "static" in result.output.strip():
                sulogin = session.execute(f"grep -l 'sulogin' /usr/lib/systemd/system/{name}.service 2>/dev/null")
                if not sulogin.success or not sulogin.output.strip():
                    self.add_finding(
                        title=f"{name.capitalize()} mode may not require authentication",
                        description=f"The {name} service may drop to a root shell without password",
                        severity=Severity.HIGH,
                        evidence=f"{name}.service does not reference sulogin",
                        remediation=f"Ensure {name}.service ExecStart uses sulogin for auth",
                    )

    def _check_lvm_snapshots(self, session: Session) -> None:
        lvm = session.execute("lvs --noheadings -o lv_attr 2>/dev/null")
        if lvm.success and lvm.output.strip():
            snapshots = [l for l in lvm.output.strip().splitlines() if l.strip().startswith("s")]
            if not snapshots:
                self.add_finding(
                    title="No LVM snapshots detected",
                    description="No LVM snapshots exist for rapid filesystem recovery",
                    severity=Severity.MEDIUM,
                    evidence="No snapshot-type LVs found",
                    remediation="Create periodic LVM snapshots of critical volumes",
                )
        else:
            self.add_finding(
                title="LVM not available or no volumes detected",
                description="Cannot verify LVM snapshot recovery capability",
                severity=Severity.LOW,
                evidence="lvs command returned no output",
                remediation="Consider LVM for volume management with snapshot support",
            )

    def _check_backup_accessibility(self, session: Session) -> None:
        backup_dirs = ["/var/backups", "/backup", "/mnt/backup"]
        for d in backup_dirs:
            result = session.execute(f"test -d {d} && find {d} -maxdepth 0 -writable 2>/dev/null")
            if result.success and result.output.strip():
                self.add_finding(
                    title=f"Backup directory writable: {d}",
                    description=f"Current user can write to {d} — backups could be destroyed",
                    severity=Severity.HIGH,
                    evidence=f"{d} is writable",
                    remediation=f"Restrict write access to {d}; use append-only or immutable storage",
                )

    def _check_kdump(self, session: Session) -> None:
        kdump = session.execute("systemctl is-active kdump 2>/dev/null")
        if kdump.success and kdump.output.strip() != "active":
            self.add_finding(
                title="kdump crash recovery is not active",
                description="Kernel crash dumps will not be captured for post-mortem analysis",
                severity=Severity.LOW,
                evidence=f"kdump status: {kdump.output.strip()}",
                remediation="Enable kdump: systemctl enable --now kdump",
            )

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Password-protect the GRUB bootloader with grub2-setpassword",
            "Ensure rescue/emergency modes require root password (sulogin)",
            "Use LVM snapshots and off-site backups for rapid recovery",
            "Make backup storage append-only or immutable",
            "Enable kdump for kernel crash analysis",
        ]

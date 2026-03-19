"""T1547 — Boot or Logon Autostart Execution.

Checks for kernel module and XDG autostart escalation vectors.
Sub-techniques: T1547.006 (Kernel Modules), T1547.013 (XDG Autostart).
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class BootAutostartCheck(BaseModule):
    TECHNIQUE_ID = "T1547"
    TECHNIQUE_NAME = "Boot or Logon Autostart Execution"
    TACTIC = Tactic.PRIVILEGE_ESCALATION
    SEVERITY = Severity.HIGH
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        # T1547.006 — Kernel Modules
        # Check if modules can be loaded
        modules_disabled = session.execute("cat /proc/sys/kernel/modules_disabled 2>/dev/null")
        if modules_disabled.success and modules_disabled.output.strip() == "0":
            self.add_finding(
                title="Kernel module loading enabled",
                description="Kernel modules can be loaded at runtime — rootkit vector",
                severity=Severity.LOW,
                evidence="kernel.modules_disabled = 0",
                remediation="Set kernel.modules_disabled = 1 after boot",
            )

        # Check modprobe.d for blacklisted modules
        blacklist = session.execute("cat /etc/modprobe.d/*.conf 2>/dev/null | grep -c 'install.*bin/true'")
        if blacklist.success and blacklist.output.strip().isdigit():
            count = int(blacklist.output.strip())
            self.add_finding(
                title=f"Blacklisted kernel modules: {count}",
                description="Modules disabled via modprobe.d blacklisting",
                severity=Severity.INFO,
                evidence=f"{count} modules blacklisted",
            )

        # Check for writable module directories
        mod_dirs = session.execute("find /lib/modules /usr/lib/modules -writable -type d 2>/dev/null | head -5")
        if mod_dirs.success and mod_dirs.output.strip():
            self.add_finding(
                title="Writable kernel module directories",
                description="Current user can place kernel modules — rootkit/escalation risk",
                severity=Severity.CRITICAL,
                evidence=mod_dirs.output.strip(),
                remediation="Fix permissions on module directories: chmod 755",
            )

        # T1547.013 — XDG Autostart
        autostart_dirs = [
            "~/.config/autostart",
            "/etc/xdg/autostart",
        ]
        for adir in autostart_dirs:
            check = session.execute(f"ls {adir}/*.desktop 2>/dev/null")
            if check.success and check.output.strip():
                files = check.output.strip().splitlines()
                self.add_finding(
                    title=f"XDG autostart entries: {adir} ({len(files)} files)",
                    description="Desktop autostart entries execute on user login",
                    severity=Severity.LOW,
                    evidence="\n".join(files[:10]),
                    remediation="Audit autostart entries; remove unauthorized desktop files",
                )

        # Check if user autostart dir is writable by others
        user_autostart = session.execute("stat -c '%a' ~/.config/autostart 2>/dev/null")
        if user_autostart.success and user_autostart.output.strip():
            perms = user_autostart.output.strip()
            if perms.endswith("7") or perms.endswith("6"):
                self.add_finding(
                    title="User autostart directory is world-writable",
                    description="Other users can inject autostart entries for privilege escalation",
                    severity=Severity.HIGH,
                    evidence=f"~/.config/autostart permissions: {perms}",
                    remediation="chmod 700 ~/.config/autostart",
                )

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Set kernel.modules_disabled = 1 after boot",
            "Enable kernel module signing enforcement",
            "Restrict module directory permissions",
            "Audit XDG autostart entries regularly",
            "Set ~/.config/autostart to 700",
        ]

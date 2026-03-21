"""T1529 — System Shutdown/Reboot.

Checks whether the current user can shut down or reboot the system,
and evaluates shutdown inhibitor controls on RHEL systems.
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class SystemShutdownCheck(BaseModule):
    TECHNIQUE_ID = "T1529"
    TECHNIQUE_NAME = "System Shutdown/Reboot"
    TACTIC = Tactic.IMPACT
    SEVERITY = Severity.HIGH
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        self._check_shutdown_permissions(session)
        self._check_polkit_reboot(session)
        self._check_ctrl_alt_del(session)
        self._check_inhibitors(session)

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def _check_shutdown_permissions(self, session: Session) -> None:
        cmds = {"shutdown": "shutdown -h now", "reboot": "reboot",
                "poweroff": "poweroff", "init": "init 0"}
        for name, cmd in cmds.items():
            result = session.execute(f"sudo -n {cmd} --dry-run 2>&1 || true")
            if result.success and "password" not in result.output.lower() and "not allowed" not in result.output.lower():
                self.add_finding(
                    title=f"Passwordless sudo access to {name}",
                    description=f"User may execute '{cmd}' without a password via sudo",
                    severity=Severity.HIGH,
                    evidence=result.output.strip()[:300],
                    remediation=f"Remove {name} from NOPASSWD sudo rules",
                )

    def _check_polkit_reboot(self, session: Session) -> None:
        actions = [
            "org.freedesktop.login1.reboot",
            "org.freedesktop.login1.power-off",
            "org.freedesktop.login1.halt",
        ]
        for action in actions:
            result = session.execute(f"pkaction --action-id {action} --verbose 2>/dev/null")
            if result.success and "auth_admin" not in result.output.lower():
                short = action.split(".")[-1]
                self.add_finding(
                    title=f"Polkit allows non-admin {short}",
                    description=f"The polkit action {action} does not require admin auth",
                    severity=Severity.MEDIUM,
                    evidence=result.output.strip()[:500],
                    remediation=f"Configure polkit to require admin auth for {action}",
                )

    def _check_ctrl_alt_del(self, session: Session) -> None:
        result = session.execute("systemctl status ctrl-alt-del.target 2>/dev/null")
        if result.success and "masked" not in result.output.lower():
            self.add_finding(
                title="Ctrl-Alt-Del reboot not masked",
                description="Physical console users can reboot the system via Ctrl-Alt-Del",
                severity=Severity.LOW,
                evidence=result.output.strip()[:300],
                remediation="Mask the target: systemctl mask ctrl-alt-del.target",
            )

    def _check_inhibitors(self, session: Session) -> None:
        result = session.execute("systemd-inhibit --list 2>/dev/null")
        if result.success and result.output.strip():
            lines = [l for l in result.output.strip().splitlines() if l.strip() and not l.startswith("WHO")]
            if len(lines) == 0:
                self.add_finding(
                    title="No shutdown inhibitors active",
                    description="No systemd inhibitor locks are held — shutdown is uninhibited",
                    severity=Severity.INFO,
                    evidence="No inhibitors listed",
                    remediation="Critical services should hold shutdown inhibitor locks",
                )

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Mask ctrl-alt-del.target to prevent console-initiated reboots",
            "Configure polkit to require admin auth for reboot/poweroff actions",
            "Remove shutdown/reboot from NOPASSWD sudo rules",
            "Use systemd inhibitor locks for critical long-running operations",
            "Monitor for unexpected shutdown/reboot events in journal logs",
        ]

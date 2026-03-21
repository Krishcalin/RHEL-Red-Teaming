"""T1489 — Service Stop.

Checks whether critical services can be stopped by the current user,
and evaluates service restart policies on RHEL systems.
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class ServiceStopCheck(BaseModule):
    TECHNIQUE_ID = "T1489"
    TECHNIQUE_NAME = "Service Stop"
    TACTIC = Tactic.IMPACT
    SEVERITY = Severity.HIGH
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    CRITICAL_SERVICES = [
        "sshd", "firewalld", "auditd", "rsyslog", "chronyd",
        "crond", "NetworkManager", "systemd-journald",
    ]

    def check(self, session: Session) -> ModuleResult:
        self._check_service_stop_permissions(session)
        self._check_restart_policies(session)
        self._check_systemctl_access(session)

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def _check_service_stop_permissions(self, session: Session) -> None:
        for svc in self.CRITICAL_SERVICES:
            result = session.execute(
                f"systemctl is-active {svc} 2>/dev/null"
            )
            if result.success and result.output.strip() == "active":
                can_stop = session.execute(
                    f"systemctl show {svc} --property=UnitFileState 2>/dev/null"
                )
                sudo_check = session.execute(
                    f"sudo -n systemctl stop {svc} --dry-run 2>&1 || true"
                )
                if sudo_check.success and "password" not in sudo_check.output.lower():
                    self.add_finding(
                        title=f"May be able to stop {svc} via passwordless sudo",
                        description=f"User can potentially stop critical service {svc} without password",
                        severity=Severity.HIGH,
                        evidence=sudo_check.output.strip()[:300],
                        remediation=f"Restrict sudo access to systemctl stop for {svc}",
                    )

    def _check_restart_policies(self, session: Session) -> None:
        for svc in self.CRITICAL_SERVICES:
            result = session.execute(
                f"systemctl show {svc} --property=Restart 2>/dev/null"
            )
            if result.success and result.output.strip():
                restart_val = result.output.strip().split("=", 1)[-1]
                if restart_val in ("no", ""):
                    self.add_finding(
                        title=f"Service {svc} has no automatic restart policy",
                        description=f"If {svc} is stopped, it will not automatically recover",
                        severity=Severity.MEDIUM,
                        evidence=f"Restart={restart_val}",
                        remediation=f"Set Restart=on-failure in {svc} unit file override",
                    )

    def _check_systemctl_access(self, session: Session) -> None:
        polkit = session.execute(
            "pkaction --action-id org.freedesktop.systemd1.manage-units --verbose 2>/dev/null"
        )
        if polkit.success and "auth_admin" not in polkit.output.lower():
            self.add_finding(
                title="Polkit may allow non-root service management",
                description="The systemd manage-units polkit action may not require admin auth",
                severity=Severity.MEDIUM,
                evidence=polkit.output.strip()[:500],
                remediation="Ensure polkit rules require admin authentication for service management",
            )

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Configure Restart=on-failure for all critical services",
            "Restrict sudo access to systemctl stop/restart commands",
            "Use polkit rules to require admin auth for service management",
            "Deploy watchdog timers for mission-critical daemons",
            "Monitor for unexpected service state changes with auditd",
        ]

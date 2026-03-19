"""T1007 — System Service Discovery.

Enumerates systemd services, their states, and configurations.
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class ServiceDiscoveryCheck(BaseModule):
    TECHNIQUE_ID = "T1007"
    TECHNIQUE_NAME = "System Service Discovery"
    TACTIC = Tactic.DISCOVERY
    SEVERITY = Severity.INFO
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        # List all running services
        running = session.execute("systemctl list-units --type=service --state=running --no-pager --no-legend 2>/dev/null")
        if running.success and running.output.strip():
            services = running.output.strip().splitlines()
            self.add_finding(
                title=f"Running services enumerable: {len(services)}",
                description="All running systemd services are visible to the current user",
                severity=Severity.INFO,
                evidence="\n".join(services[:25]),
            )

        # List enabled services
        enabled = session.execute("systemctl list-unit-files --type=service --state=enabled --no-pager --no-legend 2>/dev/null")
        if enabled.success and enabled.output.strip():
            enabled_list = enabled.output.strip().splitlines()
            self.add_finding(
                title=f"Enabled services: {len(enabled_list)}",
                description="Service boot configuration is enumerable",
                severity=Severity.INFO,
                evidence="\n".join(enabled_list[:25]),
            )

        # Check for failed services (potential misconfigs)
        failed = session.execute("systemctl list-units --type=service --state=failed --no-pager --no-legend 2>/dev/null")
        if failed.success and failed.output.strip():
            failed_list = failed.output.strip().splitlines()
            self.add_finding(
                title=f"Failed services detected: {len(failed_list)}",
                description="Failed services may indicate misconfigurations or security issues",
                severity=Severity.LOW,
                evidence="\n".join(failed_list),
                remediation="Investigate and fix or disable failed services",
            )

        # Check for user-level systemd services
        user_svc = session.execute("systemctl --user list-units --type=service --no-pager --no-legend 2>/dev/null")
        if user_svc.success and user_svc.output.strip():
            user_list = user_svc.output.strip().splitlines()
            self.add_finding(
                title=f"User-level services: {len(user_list)}",
                description="User systemd services are running (potential persistence mechanism)",
                severity=Severity.LOW,
                evidence="\n".join(user_list[:10]),
                remediation="Audit user-level systemd services for unauthorized entries",
            )

        # Check for writable service unit files
        writable = session.execute(
            "find /etc/systemd/system /usr/lib/systemd/system -writable -name '*.service' 2>/dev/null | head -10"
        )
        if writable.success and writable.output.strip():
            self.add_finding(
                title="Writable systemd service files found",
                description="Current user can modify service unit files — privilege escalation risk",
                severity=Severity.CRITICAL,
                evidence=writable.output.strip(),
                remediation="Fix permissions: chown root:root and chmod 644 on service files",
            )

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Restrict systemctl access for non-admin users via polkit",
            "Ensure service unit files are owned by root with 644 permissions",
            "Audit user-level systemd services regularly",
            "Disable and mask unnecessary services",
        ]

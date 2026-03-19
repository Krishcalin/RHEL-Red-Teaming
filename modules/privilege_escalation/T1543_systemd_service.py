"""T1543 — Create or Modify System Process.

Checks for systemd service file escalation vectors.
Sub-technique: T1543.002 (Systemd Service).
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class SystemdServiceCheck(BaseModule):
    TECHNIQUE_ID = "T1543"
    TECHNIQUE_NAME = "Create or Modify System Process"
    TACTIC = Tactic.PRIVILEGE_ESCALATION
    SEVERITY = Severity.HIGH
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        # Check writable system service directories
        svc_dirs = [
            "/etc/systemd/system",
            "/usr/lib/systemd/system",
            "/usr/local/lib/systemd/system",
            "/run/systemd/system",
        ]
        for d in svc_dirs:
            writable = session.execute(f"test -w {d} && echo writable 2>/dev/null")
            if writable.success and writable.output.strip() == "writable":
                self.add_finding(
                    title=f"Writable systemd directory: {d}",
                    description="Current user can create/modify service unit files — root escalation",
                    severity=Severity.CRITICAL,
                    evidence=f"Writable: {d}",
                    remediation=f"Fix permissions: chmod 755 {d}; chown root:root",
                )

        # Check writable service files
        writable_svc = session.execute(
            "find /etc/systemd/system /usr/lib/systemd/system -writable -name '*.service' 2>/dev/null | head -10"
        )
        if writable_svc.success and writable_svc.output.strip():
            self.add_finding(
                title="Writable systemd service files",
                description="Service files can be modified to execute arbitrary commands as root",
                severity=Severity.CRITICAL,
                evidence=writable_svc.output.strip(),
                remediation="Fix: chmod 644 on service files; chown root:root",
            )

        # Check user-level systemd services
        user_svc_dir = session.execute("ls ~/.config/systemd/user/*.service 2>/dev/null")
        if user_svc_dir.success and user_svc_dir.output.strip():
            self.add_finding(
                title="User-level systemd services found",
                description="Persistent user services are configured (may survive logoff)",
                severity=Severity.LOW,
                evidence=user_svc_dir.output.strip()[:300],
                remediation="Audit user systemd services for unauthorized entries",
            )

        # Check for services without hardening
        services_unhardened = session.execute(
            "systemctl show -p ProtectSystem,NoNewPrivileges,PrivateTmp $(systemctl list-units --type=service --state=running --no-pager --no-legend | awk '{print $1}' | head -10) 2>/dev/null | grep -E '=no$|=$' | head -15"
        )
        if services_unhardened.success and services_unhardened.output.strip():
            missing_count = len(services_unhardened.output.strip().splitlines())
            self.add_finding(
                title=f"Services without systemd hardening: {missing_count} missing properties",
                description="Running services lack ProtectSystem, NoNewPrivileges, or PrivateTmp",
                severity=Severity.MEDIUM,
                evidence=services_unhardened.output.strip()[:500],
                remediation="Add ProtectSystem=strict, NoNewPrivileges=yes, PrivateTmp=yes to service units",
            )

        # Check for services running as root that shouldn't
        root_services = session.execute(
            "ps -eo user,pid,comm --no-headers | awk '$1==\"root\" {print $3}' | sort -u | head -30"
        )
        if root_services.success and root_services.output.strip():
            self.add_finding(
                title=f"Processes running as root: {len(root_services.output.strip().splitlines())}",
                description="Review if all root processes require root privileges",
                severity=Severity.INFO,
                evidence=root_services.output.strip()[:500],
                remediation="Use DynamicUser=yes or User= directive for services that don't need root",
            )

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Set systemd directories to 755 root:root",
            "Set service unit files to 644 root:root",
            "Use ProtectSystem=strict, NoNewPrivileges=yes, PrivateTmp=yes",
            "Use DynamicUser=yes for services that don't need a permanent user",
            "Audit user-level systemd services",
        ]

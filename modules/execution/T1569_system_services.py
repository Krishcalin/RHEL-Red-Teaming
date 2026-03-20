"""T1569 — System Services.

Checks for insecure systemd service configurations that could allow
adversaries to execute arbitrary commands through service manipulation
on RHEL systems.
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class SystemServicesCheck(BaseModule):
    TECHNIQUE_ID = "T1569"
    TECHNIQUE_NAME = "System Services"
    TACTIC = Tactic.EXECUTION
    SEVERITY = Severity.MEDIUM
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    SANDBOX_DIRECTIVES = [
        "NoNewPrivileges",
        "ProtectSystem",
        "ProtectHome",
        "PrivateTmp",
        "PrivateDevices",
    ]

    def check(self, session: Session) -> ModuleResult:
        self._check_polkit_service_control(session)
        self._check_services_running_as_root(session)
        self._check_service_sandboxing(session)
        self._check_unit_file_permissions(session)

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    # -- T1569.003  Systemctl --------------------------------------------------

    def _check_polkit_service_control(self, session: Session) -> None:
        """Check if non-root users can manage services via polkit."""
        result = session.execute(
            "pkaction --verbose 2>/dev/null "
            "| grep -A5 'org.freedesktop.systemd1.manage-units' "
            "| grep -i 'implicit any\\|implicit active\\|implicit inactive'"
        )
        if result.success and result.output.strip():
            lines = result.output.strip()
            if "yes" in lines.lower():
                self.add_finding(
                    title="Polkit allows non-root users to manage systemd services",
                    description=(
                        "Polkit policy permits unprivileged users to start, stop, "
                        "or restart systemd services without authentication."
                    ),
                    severity=Severity.HIGH,
                    evidence=lines[:500],
                    remediation=(
                        "Create a polkit rule in /etc/polkit-1/rules.d/ to deny "
                        "org.freedesktop.systemd1.manage-units for non-admin users."
                    ),
                )

        # Also check if 'systemctl' is available to all users
        result = session.execute("ls -la $(which systemctl 2>/dev/null) 2>/dev/null")
        if result.success and result.output.strip():
            perms = result.output.strip()
            if "x" in perms.split()[0][-3:]:  # world-executable
                self.add_finding(
                    title="systemctl is world-executable",
                    description=(
                        "The systemctl binary is executable by all users, "
                        "allowing any user to attempt service operations."
                    ),
                    severity=Severity.LOW,
                    evidence=perms,
                    remediation=(
                        "Restrict systemctl access via SELinux policy or "
                        "remove world-execute permission if not needed."
                    ),
                )

    def _check_services_running_as_root(self, session: Session) -> None:
        """Check for services running as root that may not need to."""
        result = session.execute(
            "systemctl list-units --type=service --state=running --no-pager --no-legend 2>/dev/null "
            "| awk '{print $1}'"
        )
        if not result.success or not result.output.strip():
            return

        services = result.output.strip().splitlines()
        root_services = []

        for svc in services[:30]:  # Limit to avoid excessive commands
            svc = svc.strip()
            if not svc:
                continue
            pid_result = session.execute(
                f"systemctl show -p MainPID -p User {svc} 2>/dev/null"
            )
            if pid_result.success and pid_result.output.strip():
                props = pid_result.output.strip()
                # Services without User= directive run as root
                if "User=" not in props or "User=root" in props:
                    main_pid_line = [
                        l for l in props.splitlines() if l.startswith("MainPID=")
                    ]
                    if main_pid_line:
                        pid = main_pid_line[0].split("=", 1)[1]
                        if pid and pid != "0":
                            root_services.append(svc)

        if root_services:
            self.add_finding(
                title="Services running as root without explicit User= directive",
                description=(
                    f"{len(root_services)} running service(s) execute as root. "
                    "Some may not require root privileges."
                ),
                severity=Severity.MEDIUM,
                evidence="\n".join(root_services[:15]),
                remediation=(
                    "Add User= and Group= directives to service unit files "
                    "to run services with least-privilege accounts."
                ),
            )

    def _check_service_sandboxing(self, session: Session) -> None:
        """Check for services without proper sandboxing directives."""
        result = session.execute(
            "systemctl list-units --type=service --state=running --no-pager --no-legend 2>/dev/null "
            "| awk '{print $1}' | head -20"
        )
        if not result.success or not result.output.strip():
            return

        unsandboxed = []
        for svc in result.output.strip().splitlines():
            svc = svc.strip()
            if not svc:
                continue
            props_result = session.execute(
                f"systemctl show {svc} -p NoNewPrivileges -p ProtectSystem "
                f"-p ProtectHome -p PrivateTmp -p PrivateDevices 2>/dev/null"
            )
            if props_result.success and props_result.output.strip():
                props = props_result.output.strip()
                missing = []
                for directive in self.SANDBOX_DIRECTIVES:
                    if f"{directive}=no" in props or f"{directive}=" not in props:
                        missing.append(directive)
                if len(missing) >= 3:
                    unsandboxed.append(f"{svc}: missing {', '.join(missing)}")

        if unsandboxed:
            self.add_finding(
                title="Services running without proper sandboxing",
                description=(
                    f"{len(unsandboxed)} service(s) lack systemd sandboxing directives "
                    "(NoNewPrivileges, ProtectSystem, PrivateTmp, etc.)."
                ),
                severity=Severity.MEDIUM,
                evidence="\n".join(unsandboxed[:10]),
                remediation=(
                    "Add sandboxing directives to service unit files: "
                    "NoNewPrivileges=yes, ProtectSystem=strict, ProtectHome=yes, "
                    "PrivateTmp=yes, PrivateDevices=yes."
                ),
            )

    def _check_unit_file_permissions(self, session: Session) -> None:
        """Check if systemd unit files are modifiable by non-root users."""
        dirs = [
            "/etc/systemd/system",
            "/usr/lib/systemd/system",
            "/usr/local/lib/systemd/system",
        ]
        writable_files = []
        for d in dirs:
            result = session.execute(
                f"find {d} -type f -name '*.service' "
                f"\\( -perm -o+w -o -perm -g+w \\) 2>/dev/null"
            )
            if result.success and result.output.strip():
                writable_files.extend(result.output.strip().splitlines())

        if writable_files:
            self.add_finding(
                title="Systemd unit files writable by non-root users",
                description=(
                    "Service unit files with group-writable or world-writable "
                    "permissions can be modified to execute arbitrary commands."
                ),
                severity=Severity.HIGH,
                evidence="\n".join(writable_files[:10]),
                remediation=(
                    "Set unit file permissions to 644 owned by root:root. "
                    "Run: chmod 644 <unit-file> && chown root:root <unit-file>"
                ),
            )

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Configure polkit rules to restrict systemctl access to authorized administrators only.",
            "Add User= and Group= directives to all service unit files to enforce least privilege.",
            "Enable systemd sandboxing directives (NoNewPrivileges, ProtectSystem, PrivateTmp) on all services.",
            "Ensure all unit files under /etc/systemd/system and /usr/lib/systemd/system are owned by root with 644 permissions.",
            "Use 'systemd-analyze security <service>' to audit service hardening scores.",
        ]

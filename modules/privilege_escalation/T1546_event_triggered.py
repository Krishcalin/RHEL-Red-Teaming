"""T1546 — Event Triggered Execution.

Checks for shell config, trap, udev rule, and Python startup hook escalation.
Sub-techniques: T1546.004 (Shell Config), T1546.005 (Trap), T1546.017 (Udev), T1546.018 (Python).
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class EventTriggeredCheck(BaseModule):
    TECHNIQUE_ID = "T1546"
    TECHNIQUE_NAME = "Event Triggered Execution"
    TACTIC = Tactic.PRIVILEGE_ESCALATION
    SEVERITY = Severity.MEDIUM
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        # T1546.004 — Shell Config Modification
        shell_files = [
            "/etc/profile", "/etc/profile.d/", "/etc/bashrc",
            "~/.bashrc", "~/.bash_profile", "~/.profile", "~/.bash_login",
        ]
        for sf in shell_files:
            writable = session.execute(f"test -w {sf} && echo writable 2>/dev/null")
            if writable.success and writable.output.strip() == "writable":
                if sf.startswith("/etc"):
                    self.add_finding(
                        title=f"System shell profile writable: {sf}",
                        description="Current user can inject commands into system-wide shell profiles",
                        severity=Severity.CRITICAL,
                        evidence=f"Writable: {sf}",
                        remediation=f"Fix permissions: chmod 644 {sf}; chown root:root",
                    )

        # Check /etc/profile.d for writable scripts
        profiled_writable = session.execute("find /etc/profile.d -writable -name '*.sh' 2>/dev/null")
        if profiled_writable.success and profiled_writable.output.strip():
            self.add_finding(
                title="Writable scripts in /etc/profile.d",
                description="Commands injected here execute for all users on login",
                severity=Severity.CRITICAL,
                evidence=profiled_writable.output.strip(),
                remediation="Fix: chmod 644 /etc/profile.d/*.sh; chown root:root",
            )

        # T1546.005 — Trap
        # Check for trap commands in profiles
        trap_check = session.execute("grep -rn 'trap ' /etc/profile /etc/profile.d/ /etc/bashrc 2>/dev/null | grep -v '^#'")
        if trap_check.success and trap_check.output.strip():
            self.add_finding(
                title="Trap commands in system profiles",
                description="Shell trap handlers in system profiles — may intercept signals",
                severity=Severity.LOW,
                evidence=trap_check.output.strip()[:400],
            )

        # T1546.017 — Udev Rules
        # Check for writable udev rules
        udev_writable = session.execute("find /etc/udev/rules.d /usr/lib/udev/rules.d -writable 2>/dev/null")
        if udev_writable.success and udev_writable.output.strip():
            self.add_finding(
                title="Writable udev rules",
                description="Current user can create udev rules that execute as root on device events",
                severity=Severity.CRITICAL,
                evidence=udev_writable.output.strip(),
                remediation="Fix permissions: chmod 644 on udev rules; chown root:root",
            )

        # Check for udev rules that run programs
        udev_run = session.execute(
            "grep -rn 'RUN+=' /etc/udev/rules.d/ 2>/dev/null | head -10"
        )
        if udev_run.success and udev_run.output.strip():
            self.add_finding(
                title="Udev rules with RUN directives",
                description="Udev rules execute programs on device events (as root)",
                severity=Severity.INFO,
                evidence=udev_run.output.strip()[:400],
            )

        # T1546.018 — Python Startup Hooks
        pythonstartup = session.execute("echo $PYTHONSTARTUP")
        if pythonstartup.success and pythonstartup.output.strip():
            self.add_finding(
                title=f"PYTHONSTARTUP set: {pythonstartup.output.strip()}",
                description="Python startup script executes on every Python interpreter launch",
                severity=Severity.MEDIUM,
                evidence=f"PYTHONSTARTUP={pythonstartup.output.strip()}",
                remediation="Investigate and unset PYTHONSTARTUP if not needed",
            )

        # Check sitecustomize.py
        site_customize = session.execute(
            "python3 -c 'import site; print(site.ENABLE_USER_SITE)' 2>/dev/null"
        )
        if site_customize.success and site_customize.output.strip() == "True":
            user_site = session.execute("python3 -m site --user-site 2>/dev/null")
            if user_site.success and user_site.output.strip():
                site_path = user_site.output.strip()
                customize = session.execute(f"test -f {site_path}/sitecustomize.py && echo exists")
                if customize.success and customize.output.strip() == "exists":
                    self.add_finding(
                        title="User sitecustomize.py exists",
                        description="Custom Python code runs on every interpreter launch",
                        severity=Severity.MEDIUM,
                        evidence=f"User site: {site_path}/sitecustomize.py",
                        remediation="Audit sitecustomize.py; restrict user site-packages",
                    )

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Set /etc/profile, /etc/bashrc, /etc/profile.d/ to 644 root:root",
            "Restrict udev rules to 644 root:root",
            "Audit udev RUN directives",
            "Monitor PYTHONSTARTUP and sitecustomize.py",
            "Use auditd to watch shell profile modifications",
        ]

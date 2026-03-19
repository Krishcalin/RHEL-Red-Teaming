"""T1037 — Boot or Logon Initialization Scripts.

Checks for RC script and init script escalation vectors.
Sub-technique: T1037.004 (RC Scripts).
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class InitScriptsCheck(BaseModule):
    TECHNIQUE_ID = "T1037"
    TECHNIQUE_NAME = "Boot or Logon Initialization Scripts"
    TACTIC = Tactic.PRIVILEGE_ESCALATION
    SEVERITY = Severity.MEDIUM
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        # Check rc.local
        rc_local = session.execute("cat /etc/rc.local 2>/dev/null || cat /etc/rc.d/rc.local 2>/dev/null")
        if rc_local.success and rc_local.output.strip():
            content = rc_local.output.strip()
            non_comment = [l for l in content.splitlines() if l.strip() and not l.strip().startswith("#")]
            if non_comment:
                self.add_finding(
                    title=f"rc.local contains commands: {len(non_comment)} lines",
                    description="Commands in rc.local execute as root at boot",
                    severity=Severity.MEDIUM,
                    evidence="\n".join(non_comment[:10]),
                    remediation="Migrate rc.local commands to systemd service units",
                )

            # Check if writable
            writable = session.execute("test -w /etc/rc.local && echo writable 2>/dev/null")
            if not writable.success:
                writable = session.execute("test -w /etc/rc.d/rc.local && echo writable 2>/dev/null")
            if writable.success and writable.output.strip() == "writable":
                self.add_finding(
                    title="rc.local is writable!",
                    description="Current user can inject boot-time commands that run as root",
                    severity=Severity.CRITICAL,
                    remediation="chmod 644 /etc/rc.local; chown root:root",
                )

        # Check init.d scripts
        initd_writable = session.execute("find /etc/init.d -writable -type f 2>/dev/null | head -10")
        if initd_writable.success and initd_writable.output.strip():
            self.add_finding(
                title="Writable init.d scripts",
                description="Legacy init scripts can be modified to execute as root",
                severity=Severity.HIGH,
                evidence=initd_writable.output.strip(),
                remediation="Fix: chmod 755 /etc/init.d/*; chown root:root",
            )

        # Check /etc/environment
        env_writable = session.execute("test -w /etc/environment && echo writable 2>/dev/null")
        if env_writable.success and env_writable.output.strip() == "writable":
            self.add_finding(
                title="/etc/environment is writable",
                description="Current user can inject environment variables for all users",
                severity=Severity.HIGH,
                remediation="chmod 644 /etc/environment; chown root:root",
            )

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Migrate rc.local commands to systemd units",
            "Set rc.local and init.d scripts to 644/755 root:root",
            "Set /etc/environment to 644 root:root",
            "Monitor boot script modifications with auditd",
        ]

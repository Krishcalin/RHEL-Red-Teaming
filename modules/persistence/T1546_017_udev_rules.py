"""T1546.017 — Event Triggered Execution: Udev Rules.

Checks for writable udev rules and device-triggered persistence
on RHEL systems.
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class UdevRulesCheck(BaseModule):
    TECHNIQUE_ID = "T1546.017"
    TECHNIQUE_NAME = "Udev Rules"
    TACTIC = Tactic.PERSISTENCE
    SEVERITY = Severity.HIGH
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        self._check_writable_rules_dirs(session)
        self._check_run_commands(session)
        self._check_custom_rules(session)

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def _check_writable_rules_dirs(self, session: Session) -> None:
        dirs = ["/etc/udev/rules.d", "/usr/lib/udev/rules.d", "/run/udev/rules.d"]
        for d in dirs:
            result = session.execute(f"test -d {d} && test -w {d} && echo writable 2>/dev/null")
            if result.success and "writable" in result.output:
                self.add_finding(
                    title=f"Writable udev rules directory: {d}",
                    description=f"{d} is writable — malicious udev rules can be planted for persistence",
                    severity=Severity.HIGH,
                    evidence=f"{d} is writable by current user",
                    remediation=f"Fix: chmod 755 {d}; chown root:root {d}",
                )

    def _check_run_commands(self, session: Session) -> None:
        result = session.execute("grep -rn 'RUN+=' /etc/udev/rules.d/ 2>/dev/null")
        if result.success and result.output.strip():
            for line in result.output.strip().splitlines():
                if "/bin/" in line or "/usr/" in line or "/tmp/" in line:
                    self.add_finding(
                        title="Udev rule executes command on device event",
                        description="RUN+= directive triggers command execution when devices are connected",
                        severity=Severity.MEDIUM,
                        evidence=line.strip()[:300],
                        remediation="Audit RUN+= directives; ensure only authorized commands are executed",
                    )

    def _check_custom_rules(self, session: Session) -> None:
        result = session.execute("find /etc/udev/rules.d/ -name '*.rules' -writable 2>/dev/null | head -10")
        if result.success and result.output.strip():
            count = len(result.output.strip().splitlines())
            self.add_finding(
                title=f"{count} writable udev rule files",
                description="Writable udev rule files can be modified to add persistence triggers",
                severity=Severity.HIGH,
                evidence=result.output.strip()[:500],
                remediation="Set all udev rule files to 644 root:root",
            )

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Restrict udev rules directories to root write only",
            "Audit RUN+= directives in udev rules",
            "Monitor udev rule file changes with auditd",
            "Set all rule files to 644 owned by root",
        ]

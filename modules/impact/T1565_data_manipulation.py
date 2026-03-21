"""T1565 — Data Manipulation.

Checks data integrity monitoring (AIDE/Tripwire), file permission hygiene,
and runtime data manipulation risks on RHEL systems.
Sub-techniques: Stored Data (T1565.001), Transmitted Data (T1565.002),
Runtime Data (T1565.003).
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class DataManipulationCheck(BaseModule):
    TECHNIQUE_ID = "T1565"
    TECHNIQUE_NAME = "Data Manipulation"
    TACTIC = Tactic.IMPACT
    SEVERITY = Severity.HIGH
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        self._check_integrity_monitoring(session)
        self._check_writable_configs(session)
        self._check_tls_enforcement(session)
        self._check_ptrace_scope(session)

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def _check_integrity_monitoring(self, session: Session) -> None:
        aide = session.execute("rpm -q aide 2>/dev/null")
        tripwire = session.execute("rpm -q tripwire 2>/dev/null")
        aide_ok = aide.success and "not installed" not in aide.output
        tripwire_ok = tripwire.success and "not installed" not in tripwire.output
        if not aide_ok and not tripwire_ok:
            self.add_finding(
                title="No file integrity monitoring installed",
                description="Neither AIDE nor Tripwire is installed — file tampering may go undetected",
                severity=Severity.HIGH,
                evidence="aide and tripwire both not installed",
                remediation="Install and initialise AIDE: dnf install aide && aide --init",
            )
        elif aide_ok:
            db = session.execute("test -f /var/lib/aide/aide.db.gz && echo exists")
            if not db.success or "exists" not in db.output:
                self.add_finding(
                    title="AIDE installed but database not initialised",
                    description="AIDE cannot detect changes without a baseline database",
                    severity=Severity.MEDIUM,
                    evidence="AIDE db not found at /var/lib/aide/aide.db.gz",
                    remediation="Initialise AIDE: aide --init && mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz",
                )

    def _check_writable_configs(self, session: Session) -> None:
        configs = ["/etc/passwd", "/etc/shadow", "/etc/hosts",
                   "/etc/resolv.conf", "/etc/sudoers"]
        for cfg in configs:
            result = session.execute(f"test -f {cfg} && find {cfg} -writable 2>/dev/null")
            if result.success and result.output.strip():
                self.add_finding(
                    title=f"Critical config writable: {cfg}",
                    description=f"Current user can modify {cfg} — stored data manipulation risk",
                    severity=Severity.CRITICAL,
                    evidence=f"{cfg} is writable by current user",
                    remediation=f"Fix permissions: chmod 644 {cfg} (or 640 for sensitive files)",
                )

    def _check_tls_enforcement(self, session: Session) -> None:
        crypto_policy = session.execute("update-crypto-policies --show 2>/dev/null")
        if crypto_policy.success and crypto_policy.output.strip():
            policy = crypto_policy.output.strip()
            weak = ["LEGACY", "DEFAULT"]
            if policy in weak:
                self.add_finding(
                    title=f"Crypto policy is {policy}",
                    description=f"The {policy} crypto policy may allow weak algorithms enabling data-in-transit manipulation",
                    severity=Severity.MEDIUM,
                    evidence=f"crypto-policy: {policy}",
                    remediation="Strengthen: update-crypto-policies --set FUTURE",
                )

    def _check_ptrace_scope(self, session: Session) -> None:
        result = session.execute("cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null")
        if result.success and result.output.strip():
            try:
                scope = int(result.output.strip())
                if scope == 0:
                    self.add_finding(
                        title="ptrace_scope is 0 (unrestricted)",
                        description="Any process can ptrace any other — runtime data manipulation is trivial",
                        severity=Severity.HIGH,
                        evidence=f"kernel.yama.ptrace_scope = {scope}",
                        remediation="Set kernel.yama.ptrace_scope=1 in /etc/sysctl.d/",
                    )
            except ValueError:
                pass

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Deploy AIDE or Tripwire with daily integrity checks and alerting",
            "Enforce strong crypto policies (FUTURE) to protect data in transit",
            "Set kernel.yama.ptrace_scope=1 to restrict runtime process inspection",
            "Use immutable attributes on critical configuration files",
            "Implement TLS mutual authentication for internal services",
        ]

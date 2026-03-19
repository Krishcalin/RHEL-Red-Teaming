"""T1110 — Brute Force.

Audits brute-force protection: account lockout, rate limiting, password policy.
Sub-techniques: T1110.001-004 (Guessing, Cracking, Spraying, Stuffing).
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class BruteForceCheck(BaseModule):
    TECHNIQUE_ID = "T1110"
    TECHNIQUE_NAME = "Brute Force"
    TACTIC = Tactic.CREDENTIAL_ACCESS
    SEVERITY = Severity.HIGH
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        # Check PAM faillock configuration
        faillock = session.execute("grep -r 'pam_faillock' /etc/pam.d/ 2>/dev/null")
        if faillock.success and faillock.output.strip():
            self.add_finding(
                title="pam_faillock configured",
                description="Account lockout via pam_faillock is in place",
                severity=Severity.INFO,
                evidence=faillock.output.strip()[:500],
            )

            # Check deny count
            faillock_conf = session.execute("cat /etc/security/faillock.conf 2>/dev/null | grep -v '^#' | grep -v '^$'")
            if faillock_conf.success and faillock_conf.output.strip():
                conf = faillock_conf.output.lower()
                if "deny" in conf:
                    for line in conf.splitlines():
                        if "deny" in line and "=" in line:
                            val = line.split("=")[-1].strip()
                            if val.isdigit() and int(val) > 10:
                                self.add_finding(
                                    title=f"High faillock deny threshold: {val}",
                                    description="Account lockout threshold is too high for effective brute-force protection",
                                    severity=Severity.MEDIUM,
                                    evidence=line.strip(),
                                    remediation="Set deny = 5 in /etc/security/faillock.conf",
                                )
                if "unlock_time" in conf:
                    for line in conf.splitlines():
                        if "unlock_time" in line and "=" in line:
                            val = line.split("=")[-1].strip()
                            if val.isdigit() and int(val) < 600 and int(val) != 0:
                                self.add_finding(
                                    title=f"Short lockout duration: {val}s",
                                    description="Account unlock time is too short",
                                    severity=Severity.MEDIUM,
                                    evidence=line.strip(),
                                    remediation="Set unlock_time = 900 (15 minutes) or 0 (manual unlock)",
                                )
        else:
            # Check for pam_tally2 (older RHEL)
            tally2 = session.execute("grep -r 'pam_tally2' /etc/pam.d/ 2>/dev/null")
            if tally2.success and tally2.output.strip():
                self.add_finding(
                    title="Legacy pam_tally2 in use",
                    description="pam_tally2 is deprecated — migrate to pam_faillock",
                    severity=Severity.MEDIUM,
                    evidence=tally2.output.strip()[:300],
                    remediation="Replace pam_tally2 with pam_faillock",
                )
            else:
                self.add_finding(
                    title="No account lockout configured",
                    description="Neither pam_faillock nor pam_tally2 is configured — unlimited login attempts allowed",
                    severity=Severity.HIGH,
                    remediation="Configure pam_faillock with deny=5, unlock_time=900",
                )

        # Check SSH MaxAuthTries
        ssh_config = session.execute("grep -i 'MaxAuthTries' /etc/ssh/sshd_config 2>/dev/null | grep -v '^#'")
        if ssh_config.success and ssh_config.output.strip():
            val = ssh_config.output.strip().split()[-1]
            if val.isdigit() and int(val) > 6:
                self.add_finding(
                    title=f"SSH MaxAuthTries too high: {val}",
                    description="SSH allows too many authentication attempts per connection",
                    severity=Severity.MEDIUM,
                    evidence=ssh_config.output.strip(),
                    remediation="Set MaxAuthTries 3 in /etc/ssh/sshd_config",
                )
        else:
            self.add_finding(
                title="SSH MaxAuthTries not explicitly set",
                description="Default MaxAuthTries (6) may allow excessive login attempts",
                severity=Severity.LOW,
                evidence="MaxAuthTries not found in sshd_config",
                remediation="Set MaxAuthTries 3 in /etc/ssh/sshd_config",
            )

        # Check for fail2ban
        f2b = session.execute("systemctl is-active fail2ban 2>/dev/null")
        if f2b.success and f2b.output.strip() == "active":
            self.add_finding(
                title="fail2ban is active",
                description="fail2ban provides IP-based brute-force protection",
                severity=Severity.INFO,
                evidence="fail2ban service is running",
            )
        else:
            self.add_finding(
                title="fail2ban not running",
                description="No IP-based brute-force protection (fail2ban) detected",
                severity=Severity.LOW,
                evidence="fail2ban is not active",
                remediation="Install and configure fail2ban for SSH and other services",
            )

        # Check login delay (pam_faildelay)
        faildelay = session.execute("grep -r 'pam_faildelay' /etc/pam.d/ 2>/dev/null")
        if not faildelay.success or not faildelay.output.strip():
            self.add_finding(
                title="No login delay configured",
                description="pam_faildelay not set — rapid brute-force attempts possible",
                severity=Severity.LOW,
                remediation="Add pam_faildelay with delay=4000000 (4 seconds)",
            )

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Configure pam_faillock: deny=5, unlock_time=900",
            "Set SSH MaxAuthTries to 3",
            "Install and enable fail2ban",
            "Configure pam_faildelay for login delays",
            "Use SSH key-only authentication where possible",
        ]

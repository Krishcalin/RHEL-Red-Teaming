"""T1556 — Modify Authentication Process.

Checks PAM integrity and MFA configuration.
Sub-techniques: T1556.003 (PAM), T1556.006 (MFA).
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule

EXPECTED_PAM_MODULES = [
    "pam_unix.so", "pam_permit.so", "pam_deny.so", "pam_env.so",
    "pam_faillock.so", "pam_succeed_if.so", "pam_pwquality.so",
    "pam_sss.so", "pam_systemd.so", "pam_selinux.so",
    "pam_namespace.so", "pam_keyinit.so", "pam_limits.so",
    "pam_lastlog.so", "pam_motd.so", "pam_nologin.so",
    "pam_faildelay.so", "pam_sepermit.so", "pam_access.so",
    "pam_tally2.so", "pam_wheel.so", "pam_google_authenticator.so",
    "pam_oath.so", "pam_yubico.so",
]


class ModifyAuthCheck(BaseModule):
    TECHNIQUE_ID = "T1556"
    TECHNIQUE_NAME = "Modify Authentication Process"
    TACTIC = Tactic.CREDENTIAL_ACCESS
    SEVERITY = Severity.CRITICAL
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        # T1556.003 — PAM Module Integrity
        # Check for unknown PAM modules
        pam_modules = session.execute(
            "grep -rh 'pam_.*\\.so' /etc/pam.d/ 2>/dev/null | "
            "grep -oP 'pam_\\w+\\.so' | sort -u"
        )
        if pam_modules.success and pam_modules.output.strip():
            modules = pam_modules.output.strip().splitlines()
            unknown = [m for m in modules if m not in EXPECTED_PAM_MODULES]
            if unknown:
                self.add_finding(
                    title=f"Non-standard PAM modules detected: {len(unknown)}",
                    description="PAM modules not in the expected baseline — possible backdoor",
                    severity=Severity.HIGH,
                    evidence="\n".join(unknown),
                    remediation="Investigate unknown PAM modules; verify with rpm -Vf",
                )

        # Check for pam_permit.so in auth stack (bypasses auth)
        permit = session.execute("grep -rn 'auth.*sufficient.*pam_permit' /etc/pam.d/ 2>/dev/null")
        if permit.success and permit.output.strip():
            self.add_finding(
                title="pam_permit.so in auth stack (auth bypass!)",
                description="pam_permit always succeeds — any password accepted",
                severity=Severity.CRITICAL,
                evidence=permit.output.strip(),
                remediation="Remove pam_permit.so from auth stack in PAM configuration",
            )

        # Check PAM file permissions
        pam_writable = session.execute("find /etc/pam.d -writable 2>/dev/null")
        if pam_writable.success and pam_writable.output.strip():
            self.add_finding(
                title="Writable PAM configuration files",
                description="Current user can modify PAM config — authentication backdoor possible",
                severity=Severity.CRITICAL,
                evidence=pam_writable.output.strip(),
                remediation="Set PAM files to 644 owned by root:root",
            )

        # Check PAM file integrity via RPM
        pam_verify = session.execute("rpm -V pam 2>/dev/null | head -20")
        if pam_verify.success and pam_verify.output.strip():
            self.add_finding(
                title="PAM package integrity check failed",
                description="PAM files have been modified from their RPM-installed state",
                severity=Severity.HIGH,
                evidence=pam_verify.output.strip(),
                remediation="Investigate modifications; reinstall: dnf reinstall pam",
            )

        # Check for passwordless sudo/su
        su_noauth = session.execute("grep -rn 'auth.*sufficient.*pam_rootok' /etc/pam.d/su 2>/dev/null")
        if su_noauth.success and su_noauth.output.strip():
            # This is normal, but check if pam_wheel is enforced
            wheel_check = session.execute("grep -n 'pam_wheel' /etc/pam.d/su 2>/dev/null | grep -v '^#'")
            if not wheel_check.success or not wheel_check.output.strip():
                self.add_finding(
                    title="su does not restrict to wheel group",
                    description="Any user can attempt su — pam_wheel is not enforced",
                    severity=Severity.MEDIUM,
                    evidence="pam_wheel.so not enabled in /etc/pam.d/su",
                    remediation="Uncomment pam_wheel.so in /etc/pam.d/su",
                )

        # T1556.006 — MFA
        mfa_modules = ["pam_google_authenticator.so", "pam_oath.so", "pam_yubico.so", "pam_duo.so"]
        mfa_found = False
        if pam_modules.success:
            for mod in mfa_modules:
                if mod in pam_modules.output:
                    mfa_found = True
                    self.add_finding(
                        title=f"MFA module configured: {mod}",
                        description="Multi-factor authentication is in the PAM stack",
                        severity=Severity.INFO,
                        evidence=mod,
                    )

        if not mfa_found:
            self.add_finding(
                title="No MFA module detected in PAM",
                description="Multi-factor authentication is not configured",
                severity=Severity.MEDIUM,
                remediation="Configure TOTP (pam_google_authenticator) or hardware tokens (pam_yubico)",
            )

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Verify PAM file integrity with rpm -V pam",
            "Remove pam_permit.so from auth stacks",
            "Set PAM config file permissions to 644 root:root",
            "Enable pam_wheel.so for su access restriction",
            "Deploy MFA (TOTP, hardware tokens) via PAM",
            "Monitor PAM config changes with auditd",
        ]

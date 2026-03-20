"""T1556 — Modify Authentication Process.

Checks for tampering with PAM configuration, MFA bypass, and authentication
mechanism modifications on RHEL systems.
Sub-techniques: T1556.003 (Pluggable Authentication Modules), T1556.006 (MFA).
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class ModifyAuthCheck(BaseModule):
    TECHNIQUE_ID = "T1556"
    TECHNIQUE_NAME = "Modify Authentication Process"
    TACTIC = Tactic.PERSISTENCE
    SEVERITY = Severity.CRITICAL
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = True
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        # --- T1556.003: PAM Checks ---

        # Check for unusual PAM modules in /etc/pam.d/
        unusual_pam = session.execute(
            "grep -rh 'auth\\|session\\|account\\|password' /etc/pam.d/ 2>/dev/null "
            "| grep -v '^#' | awk '{print $NF}' | sort -u "
            "| while read mod; do rpm -qf /usr/lib64/security/${mod}.so 2>/dev/null "
            "|| echo \"UNPACKAGED: $mod\"; done | grep '^UNPACKAGED' | head -10"
        )
        if unusual_pam.success and unusual_pam.output.strip():
            self.add_finding(
                title="Unusual PAM modules detected",
                description="PAM modules not tracked by RPM may have been injected for credential harvesting or auth bypass",
                severity=Severity.CRITICAL,
                evidence=unusual_pam.output.strip(),
                remediation="Audit all PAM modules; remove any not provided by known RPM packages",
            )

        # Check for pam_exec.so entries (can run arbitrary commands during auth)
        pam_exec = session.execute(
            "grep -rn 'pam_exec.so' /etc/pam.d/ 2>/dev/null | grep -v '^#'"
        )
        if pam_exec.success and pam_exec.output.strip():
            self.add_finding(
                title="pam_exec.so entries found in PAM configuration",
                description="pam_exec.so executes arbitrary commands during authentication and can be used to backdoor login",
                severity=Severity.CRITICAL,
                evidence=pam_exec.output.strip(),
                remediation="Remove pam_exec.so entries unless explicitly required; audit the scripts they execute",
            )

        # Check for pam_permit.so (allows auth without password)
        pam_permit = session.execute(
            "grep -rn 'pam_permit.so' /etc/pam.d/ 2>/dev/null | grep -v '^#' "
            "| grep -v 'pam.d/fingerprint-auth\\|pam.d/smartcard-auth' | head -10"
        )
        if pam_permit.success and pam_permit.output.strip():
            self.add_finding(
                title="pam_permit.so allows authentication without password",
                description="pam_permit.so unconditionally permits access; presence in auth stacks is a critical backdoor",
                severity=Severity.CRITICAL,
                evidence=pam_permit.output.strip(),
                remediation="Remove pam_permit.so from all PAM stacks except where explicitly documented",
            )

        # Check for modified pam_unix.so
        pam_unix_verify = session.execute(
            "rpm -Vf /usr/lib64/security/pam_unix.so 2>/dev/null | grep -v '^$'"
        )
        if pam_unix_verify.success and pam_unix_verify.output.strip():
            self.add_finding(
                title="pam_unix.so has been modified from RPM original",
                description="A modified pam_unix.so may contain a hardcoded backdoor password or credential logger",
                severity=Severity.CRITICAL,
                evidence=pam_unix_verify.output.strip(),
                remediation="Reinstall the pam package: dnf reinstall pam; verify with rpm -V pam",
            )

        # Check PAM file permissions and ownership
        pam_perms = session.execute(
            "find /etc/pam.d/ -type f \\( ! -user root -o ! -group root -o -perm /o+w \\) 2>/dev/null | head -10"
        )
        if pam_perms.success and pam_perms.output.strip():
            self.add_finding(
                title="PAM configuration files with insecure permissions",
                description="PAM files not owned by root or world-writable allow unprivileged modification of auth",
                severity=Severity.CRITICAL,
                evidence=pam_perms.output.strip(),
                remediation="Fix permissions: chown root:root /etc/pam.d/*; chmod 644 /etc/pam.d/*",
            )

        # --- T1556.006: MFA Checks ---

        # Check if MFA modules are configured
        mfa_configured = session.execute(
            "grep -rl 'pam_google_authenticator\\|pam_duo\\|pam_u2f\\|pam_yubico' /etc/pam.d/ 2>/dev/null"
        )
        if not (mfa_configured.success and mfa_configured.output.strip()):
            self.add_finding(
                title="No MFA modules detected in PAM configuration",
                description="Multi-factor authentication is not configured, increasing risk of credential-based attacks",
                severity=Severity.HIGH,
                evidence="No pam_google_authenticator, pam_duo, pam_u2f, or pam_yubico found in /etc/pam.d/",
                remediation="Implement MFA for SSH and privileged access using pam_google_authenticator or pam_duo",
            )
        else:
            # Check if MFA can be bypassed (sufficient vs required)
            mfa_bypass = session.execute(
                "grep -rn 'pam_google_authenticator\\|pam_duo\\|pam_u2f' /etc/pam.d/ 2>/dev/null "
                "| grep -i 'sufficient' | head -10"
            )
            if mfa_bypass.success and mfa_bypass.output.strip():
                self.add_finding(
                    title="MFA module configured as 'sufficient' — bypass possible",
                    description="When MFA is 'sufficient' rather than 'required', earlier auth methods can bypass it",
                    severity=Severity.HIGH,
                    evidence=mfa_bypass.output.strip(),
                    remediation="Change MFA PAM entries from 'sufficient' to 'required' to enforce MFA",
                )

        # Check TOTP seed file permissions
        totp_files = session.execute(
            "find /home /root -name '.google_authenticator' -o -name '.duo_credentials' 2>/dev/null "
            "| while read f; do ls -la \"$f\"; done | head -10"
        )
        if totp_files.success and totp_files.output.strip():
            totp_insecure = session.execute(
                "find /home /root -name '.google_authenticator' -o -name '.duo_credentials' 2>/dev/null "
                "| while read f; do stat -c '%a %U %n' \"$f\"; done "
                "| grep -v '^400\\|^600' | head -10"
            )
            if totp_insecure.success and totp_insecure.output.strip():
                self.add_finding(
                    title="TOTP seed files have insecure permissions",
                    description="TOTP seed files readable by others allow MFA token cloning",
                    severity=Severity.HIGH,
                    evidence=totp_insecure.output.strip(),
                    remediation="Set TOTP seed files to 400 or 600 owned by the user: chmod 600 ~/.google_authenticator",
                )

        # Check /etc/security/ files for tampering
        security_files = session.execute(
            "rpm -V pam 2>/dev/null | grep '/etc/security/' | head -10"
        )
        if security_files.success and security_files.output.strip():
            self.add_finding(
                title="Modified files in /etc/security/ detected",
                description="Tampered access.conf or limits.conf can weaken authentication restrictions",
                severity=Severity.HIGH,
                evidence=security_files.output.strip(),
                remediation="Compare /etc/security/ files against RPM originals; restore with dnf reinstall pam",
            )

        # Check for pam_succeed_if used to bypass auth for specific users
        succeed_if = session.execute(
            "grep -rn 'pam_succeed_if' /etc/pam.d/ 2>/dev/null | grep -v '^#' "
            "| grep -i 'user\\|uid\\|gid' | head -10"
        )
        if succeed_if.success and succeed_if.output.strip():
            self.add_finding(
                title="pam_succeed_if rules target specific users or groups",
                description="pam_succeed_if can grant unconditional access to specific users, creating a backdoor",
                severity=Severity.HIGH,
                evidence=succeed_if.output.strip(),
                remediation="Audit pam_succeed_if entries; remove user-specific bypass rules",
            )

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Protect PAM configuration with immutable attributes: chattr +i /etc/pam.d/system-auth /etc/pam.d/password-auth",
            "Monitor /etc/pam.d/ with auditd rules: -w /etc/pam.d/ -p wa -k pam_modification",
            "Enforce MFA for SSH and privileged access using pam_google_authenticator or pam_duo set to 'required'",
            "Regularly verify PAM package integrity with rpm -V pam and aide --check",
            "Enable SELinux in enforcing mode to restrict PAM module loading and modification",
        ]

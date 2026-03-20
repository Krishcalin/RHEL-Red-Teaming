"""T1556 — Modify Authentication Process (Defense Evasion perspective).

Checks for PAM stack manipulation that suppresses auth logging, bypasses
account lockout, permits any password, and evades auth failure alerting
on RHEL systems.
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class ModifyAuthEvasionCheck(BaseModule):
    TECHNIQUE_ID = "T1556"
    TECHNIQUE_NAME = "Modify Authentication Process"
    TACTIC = Tactic.DEFENSE_EVASION
    SEVERITY = Severity.CRITICAL
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        self._check_pam_logging_suppression(session)
        self._check_faillock_bypass(session)
        self._check_pam_permit(session)
        self._check_auth_failure_logging(session)
        self._check_shadow_audit(session)

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    # -- PAM modules that suppress auth logging -------------------------------

    def _check_pam_logging_suppression(self, session: Session) -> None:
        # Check for pam_succeed_if with quiet or silent options
        result = session.execute(
            "grep -rn 'pam_succeed_if.*quiet\\|pam_succeed_if.*silent\\|pam_localuser.*quiet' "
            "/etc/pam.d/ 2>/dev/null"
        )
        if result.success and result.output.strip():
            self.add_finding(
                title="PAM modules configured to suppress logging",
                description=(
                    "PAM configuration includes quiet/silent flags that suppress "
                    "authentication event logging, making it harder to detect "
                    "unauthorized access attempts"
                ),
                severity=Severity.HIGH,
                evidence=result.output.strip()[:500],
                remediation="Remove quiet/silent flags from PAM modules unless explicitly required for known service accounts",
            )

        # Check for pam_nologin or pam_listfile used to silently deny without logging
        nolog = session.execute(
            "grep -rn 'pam_nologin\\|noreply' /etc/pam.d/ 2>/dev/null | grep -v '^#' || true"
        )
        if nolog.success and "noreply" in nolog.output:
            self.add_finding(
                title="PAM modules using noreply option",
                description="PAM modules with noreply suppress user-visible auth messages, which can mask unauthorized access",
                severity=Severity.MEDIUM,
                evidence=nolog.output.strip()[:500],
                remediation="Review PAM noreply directives and ensure auth events are still logged to syslog",
            )

    # -- pam_tally2/faillock bypass or misconfiguration -----------------------

    def _check_faillock_bypass(self, session: Session) -> None:
        # RHEL 8+ uses pam_faillock; older systems use pam_tally2
        faillock = session.execute("grep -rn 'pam_faillock\\|pam_tally2' /etc/pam.d/ 2>/dev/null")
        if not faillock.success or not faillock.output.strip():
            self.add_finding(
                title="No account lockout mechanism configured",
                description=(
                    "Neither pam_faillock nor pam_tally2 is configured in PAM. "
                    "Brute force attacks will not trigger account lockout, and "
                    "failed login attempts may go unnoticed."
                ),
                severity=Severity.CRITICAL,
                evidence="No pam_faillock or pam_tally2 found in /etc/pam.d/",
                remediation="Configure pam_faillock in /etc/pam.d/system-auth and /etc/pam.d/password-auth",
            )
        else:
            # Check for excessively high deny threshold
            deny_check = session.execute(
                "grep -rn 'pam_faillock' /etc/pam.d/ /etc/security/faillock.conf 2>/dev/null | grep 'deny=' || true"
            )
            if deny_check.success and deny_check.output.strip():
                for line in deny_check.output.strip().splitlines():
                    if "deny=" in line:
                        try:
                            deny_val = int(line.split("deny=")[1].split()[0])
                            if deny_val > 10:
                                self.add_finding(
                                    title=f"Account lockout threshold too high (deny={deny_val})",
                                    description="A high lockout threshold allows many brute force attempts before lockout, reducing detection effectiveness",
                                    severity=Severity.MEDIUM,
                                    evidence=line.strip(),
                                    remediation="Set deny=5 or lower in faillock configuration",
                                )
                        except (ValueError, IndexError):
                            pass

            # Check for even_deny_root
            root_deny = session.execute(
                "grep -rn 'pam_faillock' /etc/pam.d/ /etc/security/faillock.conf 2>/dev/null | grep 'even_deny_root' || true"
            )
            if not root_deny.success or not root_deny.output.strip():
                self.add_finding(
                    title="Root account exempt from lockout",
                    description="pam_faillock does not include even_deny_root — the root account cannot be locked out after failed attempts",
                    severity=Severity.HIGH,
                    evidence="even_deny_root not found in faillock configuration",
                    remediation="Add even_deny_root to pam_faillock configuration to include root in lockout policy",
                )

    # -- pam_permit in auth stack (accepts any password) ----------------------

    def _check_pam_permit(self, session: Session) -> None:
        result = session.execute(
            "grep -rn 'pam_permit' /etc/pam.d/ 2>/dev/null | grep -i 'auth' | grep -v '^#' || true"
        )
        if result.success and result.output.strip():
            self.add_finding(
                title="pam_permit found in authentication stack",
                description=(
                    "pam_permit in the auth stack accepts any credentials without "
                    "verification. An attacker can authenticate as any user without "
                    "knowing the password, completely bypassing authentication controls."
                ),
                severity=Severity.CRITICAL,
                evidence=result.output.strip()[:500],
                remediation="Remove pam_permit from auth stacks in /etc/pam.d/ — it should never be used for authentication",
            )

    # -- Auth failure logging to syslog ---------------------------------------

    def _check_auth_failure_logging(self, session: Session) -> None:
        # Check if auth.log or authpriv is configured in rsyslog
        rsyslog = session.execute(
            "grep -rn 'authpriv\\|auth\\.\\*' /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null"
        )
        if not rsyslog.success or not rsyslog.output.strip():
            self.add_finding(
                title="Auth failures not forwarded to syslog",
                description="No rsyslog rule captures authpriv or auth facility — authentication failures may not be logged",
                severity=Severity.HIGH,
                evidence="No authpriv/auth rules found in rsyslog configuration",
                remediation="Add 'authpriv.* /var/log/secure' to /etc/rsyslog.conf",
            )

        # Check if /var/log/secure exists and is being written to
        secure_log = session.execute("test -f /var/log/secure && stat --format='%s %Y' /var/log/secure 2>/dev/null || true")
        if secure_log.success and secure_log.output.strip():
            parts = secure_log.output.strip().split()
            if len(parts) >= 1:
                try:
                    size = int(parts[0])
                    if size == 0:
                        self.add_finding(
                            title="/var/log/secure is empty",
                            description="The authentication log file exists but is empty — auth events may not be logged",
                            severity=Severity.HIGH,
                            evidence=f"File size: {size} bytes",
                            remediation="Verify rsyslog is running and authpriv facility is configured",
                        )
                except ValueError:
                    pass

    # -- Shadow file changes not triggering audit alerts ----------------------

    def _check_shadow_audit(self, session: Session) -> None:
        # Check if auditd watches /etc/shadow
        audit_rules = session.execute("auditctl -l 2>/dev/null | grep shadow || true")
        if not audit_rules.success or not audit_rules.output.strip():
            self.add_finding(
                title="No audit rule for /etc/shadow modifications",
                description=(
                    "Changes to /etc/shadow are not monitored by auditd. "
                    "An attacker could modify password hashes without triggering alerts."
                ),
                severity=Severity.HIGH,
                evidence="No audit rules found matching /etc/shadow",
                remediation="Add audit rule: auditctl -w /etc/shadow -p wa -k shadow_changes",
            )

        # Also check /etc/passwd and /etc/gshadow
        for auth_file in ["/etc/passwd", "/etc/gshadow", "/etc/group"]:
            result = session.execute(f"auditctl -l 2>/dev/null | grep '{auth_file}' || true")
            if not result.success or not result.output.strip():
                self.add_finding(
                    title=f"No audit rule for {auth_file}",
                    description=f"Changes to {auth_file} are not monitored by auditd, allowing silent account manipulation",
                    severity=Severity.MEDIUM,
                    evidence=f"No audit rules found matching {auth_file}",
                    remediation=f"Add audit rule: auditctl -w {auth_file} -p wa -k auth_file_changes",
                )

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Configure pam_faillock with deny=5 and even_deny_root in system-auth and password-auth",
            "Monitor /etc/shadow, /etc/passwd, and PAM configuration with auditd watch rules",
            "Never use pam_permit in authentication stacks — audit all PAM configurations regularly",
            "Ensure authpriv facility is forwarded to a remote SIEM via rsyslog or journald",
            "Use AIDE to detect unauthorized modifications to PAM modules in /lib64/security/",
        ]

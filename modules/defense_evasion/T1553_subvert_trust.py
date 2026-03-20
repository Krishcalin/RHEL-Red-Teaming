"""T1553 — Subvert Trust Controls.

Checks for non-standard CA certificates, modified ca-certificates package,
custom trust anchors, and certificate manipulation on RHEL systems.
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class SubvertTrustCheck(BaseModule):
    TECHNIQUE_ID = "T1553"
    TECHNIQUE_NAME = "Subvert Trust Controls"
    TACTIC = Tactic.DEFENSE_EVASION
    SEVERITY = Severity.HIGH
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        self._check_custom_ca_anchors(session)
        self._check_update_ca_trust_status(session)
        self._check_recently_added_certs(session)
        self._check_custom_tls_certs(session)
        self._check_ca_certificates_integrity(session)
        self._check_user_trust_anchors(session)

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    # -- T1553.004 Custom CA certificates in anchors directory ----------------

    def _check_custom_ca_anchors(self, session: Session) -> None:
        result = session.execute(
            "ls -la /etc/pki/ca-trust/source/anchors/ 2>/dev/null | grep -v '^total' | grep -v '^d'"
        )
        if result.success and result.output.strip():
            files = result.output.strip().splitlines()
            if files:
                self.add_finding(
                    title=f"Non-standard CA certificates in trust anchors ({len(files)} found)",
                    description=(
                        "Custom certificates in /etc/pki/ca-trust/source/anchors/ "
                        "could allow TLS interception or trust of rogue CAs"
                    ),
                    severity=Severity.HIGH,
                    evidence="\n".join(files[:10]),
                    remediation=(
                        "Review certificates in /etc/pki/ca-trust/source/anchors/; "
                        "remove unauthorized CA certs and run update-ca-trust"
                    ),
                )

    # -- update-ca-trust status -----------------------------------------------

    def _check_update_ca_trust_status(self, session: Session) -> None:
        result = session.execute("update-ca-trust check 2>&1")
        if result.success and result.output.strip():
            output = result.output.strip()
            if "out of date" in output.lower() or "needs" in output.lower():
                self.add_finding(
                    title="CA trust store is out of date",
                    description="The CA trust store has not been updated after certificate changes",
                    severity=Severity.MEDIUM,
                    evidence=output[:500],
                    remediation="Run update-ca-trust extract to synchronize the trust store",
                )

    # -- Recently added certificates ------------------------------------------

    def _check_recently_added_certs(self, session: Session) -> None:
        result = session.execute(
            "find /etc/pki/ca-trust/source/anchors/ -type f -mtime -30 2>/dev/null"
        )
        if result.success and result.output.strip():
            recent = result.output.strip().splitlines()
            self.add_finding(
                title=f"Recently added CA certificates ({len(recent)} in last 30 days)",
                description="CA certificates added recently may indicate trust manipulation",
                severity=Severity.HIGH,
                evidence="\n".join(recent[:10]),
                remediation="Verify that recently added certificates are authorized and legitimate",
            )

    # -- Custom certs in /etc/pki/tls/certs/ ----------------------------------

    def _check_custom_tls_certs(self, session: Session) -> None:
        result = session.execute(
            "find /etc/pki/tls/certs/ -name '*.pem' -o -name '*.crt' 2>/dev/null | "
            "while read f; do rpm -qf \"$f\" 2>/dev/null || echo \"unpackaged: $f\"; done | "
            "grep '^unpackaged:' | head -20"
        )
        if result.success and result.output.strip():
            unpackaged = result.output.strip().splitlines()
            if unpackaged:
                self.add_finding(
                    title=f"Custom TLS certificates not from RPM packages ({len(unpackaged)} found)",
                    description="TLS certificates not managed by RPM may be unauthorized additions",
                    severity=Severity.MEDIUM,
                    evidence="\n".join(unpackaged[:10]),
                    remediation="Verify custom TLS certificates; use RPM-managed certificates where possible",
                )

    # -- ca-certificates package integrity ------------------------------------

    def _check_ca_certificates_integrity(self, session: Session) -> None:
        result = session.execute("rpm -V ca-certificates 2>/dev/null")
        if result.success and result.output.strip():
            modified = result.output.strip().splitlines()
            if modified:
                self.add_finding(
                    title=f"ca-certificates package has been modified ({len(modified)} files)",
                    description="RPM verification shows changes to ca-certificates package files",
                    severity=Severity.HIGH,
                    evidence="\n".join(modified[:10]),
                    remediation="Reinstall ca-certificates: yum reinstall ca-certificates && update-ca-trust",
                )

    # -- User-level trust anchors ---------------------------------------------

    def _check_user_trust_anchors(self, session: Session) -> None:
        result = session.execute(
            "find /home/ -path '*/.pki/nssdb/*' -o -path '*/.local/share/ca-certificates/*' 2>/dev/null | head -20"
        )
        if result.success and result.output.strip():
            user_certs = result.output.strip().splitlines()
            if user_certs:
                self.add_finding(
                    title=f"User-level trust anchors found ({len(user_certs)} files)",
                    description="Custom trust stores in user home directories may bypass system CA policy",
                    severity=Severity.MEDIUM,
                    evidence="\n".join(user_certs[:10]),
                    remediation="Audit user-level certificate stores; enforce centralized CA management policy",
                )

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Restrict write access to /etc/pki/ca-trust/source/anchors/ to root only",
            "Monitor certificate trust store changes with auditd watches on /etc/pki/",
            "Periodically verify ca-certificates integrity with rpm -V ca-certificates",
            "Use RHEL subscription-manager for centralized certificate authority management",
            "Enable SELinux to restrict modification of certificate trust stores",
        ]

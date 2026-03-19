"""T1649 — Steal or Forge Authentication Certificates.

Checks for accessible PKI certificates, private keys, and CA trust stores.
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class AuthCertificatesCheck(BaseModule):
    TECHNIQUE_ID = "T1649"
    TECHNIQUE_NAME = "Steal or Forge Authentication Certificates"
    TACTIC = Tactic.CREDENTIAL_ACCESS
    SEVERITY = Severity.HIGH
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        # Check for private key files
        key_search = session.execute(
            "find /etc /opt /home /root -name '*.key' -o -name '*.pem' -o -name '*.p12' -o -name '*.pfx' "
            "2>/dev/null | head -20"
        )
        if key_search.success and key_search.output.strip():
            for key_path in key_search.output.strip().splitlines()[:15]:
                readable = session.execute(f"test -r {key_path} && echo readable")
                if readable.success and readable.output.strip() == "readable":
                    # Check if it's actually a private key
                    header = session.execute(f"head -1 {key_path} 2>/dev/null")
                    if header.success and "PRIVATE KEY" in header.output:
                        perms = session.execute(f"stat -c '%a %U:%G' {key_path} 2>/dev/null")
                        self.add_finding(
                            title=f"Private key accessible: {key_path}",
                            description="TLS/PKI private key is readable — impersonation possible",
                            severity=Severity.CRITICAL,
                            evidence=f"{key_path}: {perms.output.strip() if perms.success else 'readable'}",
                            remediation=f"chmod 600 {key_path}; restrict to service account",
                        )

        # Check certificate directories
        cert_dirs = ["/etc/pki/tls/private", "/etc/pki/tls/certs", "/etc/ssl/private"]
        for cdir in cert_dirs:
            check = session.execute(f"test -d {cdir} && ls -la {cdir}/ 2>/dev/null | head -10")
            if check.success and check.output.strip():
                # Check if private directory is readable
                priv_readable = session.execute(f"test -r {cdir} && echo readable")
                if priv_readable.success and priv_readable.output.strip() == "readable" and "private" in cdir:
                    self.add_finding(
                        title=f"Private key directory readable: {cdir}",
                        description="Directory containing private keys is accessible",
                        severity=Severity.HIGH,
                        evidence=check.output.strip()[:400],
                        remediation=f"chmod 700 {cdir}",
                    )

        # Check CA trust store for unauthorized certificates
        custom_ca = session.execute("ls /etc/pki/ca-trust/source/anchors/ 2>/dev/null")
        if custom_ca.success and custom_ca.output.strip():
            self.add_finding(
                title="Custom CA certificates installed",
                description="Additional CA certificates are in the trust store — verify they are authorized",
                severity=Severity.MEDIUM,
                evidence=custom_ca.output.strip()[:300],
                remediation="Audit custom CA certificates; remove unauthorized ones",
            )

        # Check IPA/certmonger certificates
        certmonger = session.execute("getcert list 2>/dev/null | head -20")
        if certmonger.success and certmonger.output.strip():
            self.add_finding(
                title="Certmonger managed certificates found",
                description="IPA/certmonger is managing certificates on this system",
                severity=Severity.INFO,
                evidence=certmonger.output.strip()[:400],
            )

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Restrict private key files to 600 owned by the service account",
            "Set /etc/pki/tls/private to 700",
            "Audit custom CA certificates regularly",
            "Use short-lived certificates with automated renewal (certmonger)",
            "Monitor certificate file access with auditd",
        ]

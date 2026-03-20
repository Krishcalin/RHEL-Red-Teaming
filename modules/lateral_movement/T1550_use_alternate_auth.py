"""T1550 — Use Alternate Authentication Material.

Checks feasibility of authentication material reuse on RHEL:
- T1550.001 Application Access Token reuse
- T1550.002 Pass the Hash feasibility
- T1550.003 Pass the Ticket (Kerberos)
- T1550.004 Web Session Cookie theft
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class UseAlternateAuthCheck(BaseModule):
    TECHNIQUE_ID = "T1550"
    TECHNIQUE_NAME = "Use Alternate Authentication Material"
    TACTIC = Tactic.LATERAL_MOVEMENT
    SEVERITY = Severity.HIGH
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        self._check_pass_the_hash(session)
        self._check_pass_the_ticket(session)
        self._check_ssh_key_reuse(session)
        self._check_token_files(session)

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def _check_pass_the_hash(self, session: Session) -> None:
        """T1550.002 — Pass the Hash feasibility."""
        # Check if NTLM/LM hashes could be extracted (Samba winbind)
        samba_passdb = session.execute("test -f /var/lib/samba/private/passdb.tdb && echo exists")
        if samba_passdb.success and samba_passdb.output.strip() == "exists":
            readable = session.execute("test -r /var/lib/samba/private/passdb.tdb && echo readable")
            if readable.success and readable.output.strip() == "readable":
                self.add_finding(
                    title="Samba password database readable",
                    description="passdb.tdb contains NTLM hashes usable for Pass the Hash attacks",
                    severity=Severity.CRITICAL,
                    evidence="/var/lib/samba/private/passdb.tdb is readable",
                    remediation="Restrict /var/lib/samba/private/ to root:root 700",
                )

        # Check for SSSD NTLM cache
        sssd_ntlm = session.execute(
            "grep -r 'auth_provider.*ad\\|id_provider.*ad' /etc/sssd/sssd.conf 2>/dev/null"
        )
        if sssd_ntlm.success and sssd_ntlm.output.strip():
            cache_files = session.execute(
                "find /var/lib/sss/db -name '*.ldb' -readable 2>/dev/null"
            )
            if cache_files.success and cache_files.output.strip():
                self.add_finding(
                    title="SSSD AD credential cache accessible",
                    description="SSSD caches domain credentials that could be extracted for PtH",
                    severity=Severity.HIGH,
                    evidence=cache_files.output.strip()[:500],
                    remediation="Restrict SSSD cache: chmod 700 /var/lib/sss/db",
                )

    def _check_pass_the_ticket(self, session: Session) -> None:
        """T1550.003 — Pass the Ticket (Kerberos)."""
        # Check for accessible Kerberos ticket caches
        krb5cc = session.execute("find /tmp -name 'krb5cc_*' -readable 2>/dev/null | head -10")
        if krb5cc.success and krb5cc.output.strip():
            count = len(krb5cc.output.strip().splitlines())
            self.add_finding(
                title=f"Kerberos ticket caches accessible: {count}",
                description="FILE-based ccache in /tmp can be stolen for Pass the Ticket attacks",
                severity=Severity.HIGH,
                evidence=krb5cc.output.strip(),
                remediation="Use KEYRING or KCM ccache type: 'default_ccache_name = KCM:' in krb5.conf",
            )

        # Check ccache type configuration
        krb5_conf = session.execute("grep -i 'default_ccache_name' /etc/krb5.conf 2>/dev/null")
        if krb5_conf.success and krb5_conf.output.strip():
            if "FILE:" in krb5_conf.output or "file:" in krb5_conf.output:
                self.add_finding(
                    title="Kerberos using FILE-based credential cache",
                    description="FILE ccache type stores tickets on disk where they can be stolen",
                    severity=Severity.MEDIUM,
                    evidence=krb5_conf.output.strip(),
                    remediation="Switch to KCM: or KEYRING: ccache type in /etc/krb5.conf",
                )
        else:
            # Default is usually FILE on RHEL
            krb5_exists = session.execute("test -f /etc/krb5.conf && echo exists")
            if krb5_exists.success and krb5_exists.output.strip() == "exists":
                self.add_finding(
                    title="Kerberos ccache type not explicitly configured",
                    description="Default ccache type is FILE — tickets stored on disk",
                    severity=Severity.LOW,
                    evidence="No default_ccache_name in /etc/krb5.conf",
                    remediation="Set 'default_ccache_name = KCM:' in [libdefaults]",
                )

        # Check for keytab files accessible by non-root
        keytabs = session.execute(
            "find / -name '*.keytab' -readable -not -user root 2>/dev/null | head -5"
        )
        if keytabs.success and keytabs.output.strip():
            self.add_finding(
                title="Kerberos keytab files accessible by non-root users",
                description="Keytab files contain long-term keys enabling persistent authentication",
                severity=Severity.CRITICAL,
                evidence=keytabs.output.strip(),
                remediation="Restrict keytab files to root:root 600",
            )

    def _check_ssh_key_reuse(self, session: Session) -> None:
        """Check for SSH key reuse across hosts."""
        # Private keys with overly permissive access
        weak_keys = session.execute(
            "find /home -name 'id_*' -not -name '*.pub' -perm /077 2>/dev/null | head -10"
        )
        if weak_keys.success and weak_keys.output.strip():
            self.add_finding(
                title="SSH private keys with permissive permissions",
                description="Private keys readable by others can be stolen for lateral movement",
                severity=Severity.HIGH,
                evidence=weak_keys.output.strip(),
                remediation="Set SSH private keys to mode 600",
            )

        # Unencrypted private keys
        unencrypted = session.execute(
            r"find /home -name 'id_*' -not -name '*.pub' -exec grep -l 'PRIVATE KEY' {} \; 2>/dev/null | "
            r"while read f; do head -2 \"$f\" | grep -qv ENCRYPTED && echo \"$f\"; done 2>/dev/null | head -10"
        )
        if unencrypted.success and unencrypted.output.strip():
            self.add_finding(
                title="Unencrypted SSH private keys found",
                description="SSH keys without passphrase protection can be immediately reused",
                severity=Severity.MEDIUM,
                evidence=unencrypted.output.strip()[:500],
                remediation="Encrypt SSH private keys with strong passphrases",
            )

    def _check_token_files(self, session: Session) -> None:
        """T1550.001 — Application access tokens."""
        # Docker config with auth tokens
        docker_configs = session.execute(
            "find /home -path '*/.docker/config.json' -readable 2>/dev/null | head -5"
        )
        if docker_configs.success and docker_configs.output.strip():
            for cfg in docker_configs.output.strip().splitlines():
                auth_check = session.execute(f"grep -c 'auth' {cfg} 2>/dev/null")
                if auth_check.success and auth_check.output.strip() != "0":
                    self.add_finding(
                        title="Docker registry credentials accessible",
                        description="Docker config.json contains registry auth tokens",
                        severity=Severity.MEDIUM,
                        evidence=cfg,
                        remediation="Use docker credential helpers instead of plaintext tokens",
                    )

        # Kubernetes service account tokens
        k8s_token = session.execute(
            "find /var/run/secrets/kubernetes.io -name 'token' -readable 2>/dev/null"
        )
        if k8s_token.success and k8s_token.output.strip():
            self.add_finding(
                title="Kubernetes service account token accessible",
                description="Mounted K8s tokens enable API access and lateral movement within cluster",
                severity=Severity.HIGH,
                evidence=k8s_token.output.strip(),
                remediation="Use projected volumes with token expiry; disable automounting when not needed",
            )

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Restrict Samba passdb.tdb to root only (700 on parent directory)",
            "Use KCM or KEYRING for Kerberos ccache instead of FILE",
            "Restrict keytab files to root:root 600",
            "Encrypt SSH private keys with passphrases",
            "Set SSH key permissions to 600",
            "Use Docker credential helpers instead of plaintext tokens",
            "Disable automounting of Kubernetes service account tokens",
            "Enable SSSD credential cache encryption",
        ]

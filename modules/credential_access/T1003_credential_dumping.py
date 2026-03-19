"""T1003 — OS Credential Dumping.

Checks accessibility of credential stores: /etc/shadow, /proc, Kerberos ccache.
Sub-techniques: T1003.005 (Cached Domain Creds), T1003.007 (Proc), T1003.008 (/etc/shadow).
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class CredentialDumpingCheck(BaseModule):
    TECHNIQUE_ID = "T1003"
    TECHNIQUE_NAME = "OS Credential Dumping"
    TACTIC = Tactic.CREDENTIAL_ACCESS
    SEVERITY = Severity.CRITICAL
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        # T1003.008 — /etc/shadow
        shadow = session.execute("test -r /etc/shadow && echo readable")
        if shadow.success and shadow.output.strip() == "readable":
            # Get hash algorithm info
            hash_sample = session.execute("head -3 /etc/shadow 2>/dev/null | cut -d: -f2 | head -1")
            algo = "unknown"
            if hash_sample.success and hash_sample.output.strip():
                h = hash_sample.output.strip()
                if h.startswith("$6$"):
                    algo = "SHA-512"
                elif h.startswith("$5$"):
                    algo = "SHA-256"
                elif h.startswith("$y$"):
                    algo = "yescrypt"
                elif h.startswith("$2"):
                    algo = "bcrypt"
                elif h.startswith("$1$"):
                    algo = "MD5 (weak!)"

            self.add_finding(
                title="/etc/shadow is readable",
                description="Password hashes are accessible — offline cracking is possible",
                severity=Severity.CRITICAL,
                evidence=f"Hash algorithm: {algo}",
                remediation="Set /etc/shadow permissions to 640 owned by root:shadow",
            )

            if algo == "MD5 (weak!)":
                self.add_finding(
                    title="Weak hash algorithm: MD5",
                    description="Password hashes use MD5 ($1$) — trivially crackable",
                    severity=Severity.CRITICAL,
                    evidence="Hash prefix: $1$",
                    remediation="Migrate to SHA-512 or yescrypt: authselect select sssd with-sha512",
                )

        # /etc/gshadow
        gshadow = session.execute("test -r /etc/gshadow && echo readable")
        if gshadow.success and gshadow.output.strip() == "readable":
            self.add_finding(
                title="/etc/gshadow is readable",
                description="Group password hashes are accessible",
                severity=Severity.HIGH,
                remediation="Set /etc/gshadow permissions to 640 owned by root:shadow",
            )

        # T1003.007 — Proc Filesystem
        proc_mem = session.execute("test -r /proc/1/maps && echo readable")
        if proc_mem.success and proc_mem.output.strip() == "readable":
            self.add_finding(
                title="/proc/[pid]/maps readable for other processes",
                description="Process memory maps are accessible — credential extraction possible",
                severity=Severity.MEDIUM,
                evidence="/proc/1/maps is readable",
                remediation="Mount /proc with hidepid=2; set ptrace_scope=1",
            )

        # Check /proc/[pid]/environ
        proc_env = session.execute("cat /proc/self/environ 2>/dev/null | tr '\\0' '\\n' | grep -iE 'pass|secret|token|key=' | head -5")
        if proc_env.success and proc_env.output.strip():
            self.add_finding(
                title="Credentials found in process environment",
                description="Environment variables contain credential-like values",
                severity=Severity.HIGH,
                evidence=f"Found {len(proc_env.output.strip().splitlines())} credential-like env vars",
                remediation="Avoid passing credentials via environment variables",
            )

        # T1003.005 — Cached Domain Credentials
        # SSSD cache
        sssd_cache = session.execute("find /var/lib/sss/db -name '*.ldb' -readable 2>/dev/null")
        if sssd_cache.success and sssd_cache.output.strip():
            self.add_finding(
                title="SSSD credential cache accessible",
                description="SSSD LDB cache files are readable — cached domain credentials at risk",
                severity=Severity.HIGH,
                evidence=sssd_cache.output.strip(),
                remediation="Restrict /var/lib/sss/db permissions to root only",
            )

        # Kerberos credential cache
        krb5cc = session.execute("find /tmp -name 'krb5cc_*' -readable 2>/dev/null | head -10")
        if krb5cc.success and krb5cc.output.strip():
            self.add_finding(
                title="Kerberos credential caches accessible",
                description="Kerberos ticket caches in /tmp are readable — ticket theft possible",
                severity=Severity.HIGH,
                evidence=krb5cc.output.strip(),
                remediation="Use KCM or KEYRING ccache types instead of FILE",
            )

        # Check hash algorithm in login.defs
        encrypt_method = session.execute("grep '^ENCRYPT_METHOD' /etc/login.defs 2>/dev/null")
        if encrypt_method.success and encrypt_method.output.strip():
            method = encrypt_method.output.strip().split()[-1] if encrypt_method.output.split() else ""
            if method.upper() in ("MD5", "DES"):
                self.add_finding(
                    title=f"Weak ENCRYPT_METHOD in login.defs: {method}",
                    description="New passwords will use a weak hash algorithm",
                    severity=Severity.CRITICAL,
                    evidence=encrypt_method.output.strip(),
                    remediation="Set ENCRYPT_METHOD SHA512 or YESCRYPT in /etc/login.defs",
                )

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Set /etc/shadow and /etc/gshadow to 640 root:shadow",
            "Use SHA-512 or yescrypt for password hashing",
            "Mount /proc with hidepid=2",
            "Use KCM or KEYRING for Kerberos credential cache (not FILE)",
            "Restrict SSSD cache directory to root",
            "Set kernel.yama.ptrace_scope = 1",
        ]

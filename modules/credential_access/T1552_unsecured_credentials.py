"""T1552 — Unsecured Credentials.

Checks for credentials in files, shell history, and private keys.
Sub-techniques: T1552.001 (In Files), T1552.003 (Shell History), T1552.004 (Private Keys).
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule

HISTORY_FILES = [
    "~/.bash_history",
    "~/.zsh_history",
    "~/.sh_history",
    "~/.python_history",
    "~/.mysql_history",
    "~/.psql_history",
    "~/.rediscli_history",
]

CONFIG_CRED_PATHS = [
    ("/etc/fstab", "Mount credentials (CIFS)"),
    ("/etc/openldap/ldap.conf", "LDAP bind credentials"),
    ("/var/spool/cron/root", "Root crontab (may contain credentials)"),
    ("/etc/rsync.secrets", "Rsync secrets"),
    ("/etc/exports", "NFS exports"),
    ("/opt/*/config*", "Application configs"),
]


class UnsecuredCredentialsCheck(BaseModule):
    TECHNIQUE_ID = "T1552"
    TECHNIQUE_NAME = "Unsecured Credentials"
    TACTIC = Tactic.CREDENTIAL_ACCESS
    SEVERITY = Severity.HIGH
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        # T1552.003 — Shell History
        for hist_file in HISTORY_FILES:
            check = session.execute(f"test -r {hist_file} && echo readable")
            if check.success and check.output.strip() == "readable":
                # Search for credential patterns in history
                cred_search = session.execute(
                    f"grep -inE '(password|passwd|secret|token|key|credential|auth)' {hist_file} 2>/dev/null | head -10"
                )
                if cred_search.success and cred_search.output.strip():
                    self.add_finding(
                        title=f"Credentials in shell history: {hist_file}",
                        description="Shell history contains commands with credential-like strings",
                        severity=Severity.HIGH,
                        evidence=f"Matches in {hist_file}:\n{cred_search.output.strip()[:400]}",
                        remediation=f"Clear history: > {hist_file}; set HISTCONTROL=ignorespace",
                    )
                else:
                    self.add_finding(
                        title=f"Shell history accessible: {hist_file}",
                        description="Shell history is readable (may contain sensitive commands)",
                        severity=Severity.LOW,
                        evidence=hist_file,
                    )

        # T1552.001 — Credentials in Files
        # Search common config directories for plaintext credentials
        cred_files = session.execute(
            "grep -rlE '(password|passwd|secret|token|api_key|db_pass)\\s*[:=]' "
            "/etc /opt /var/www /srv 2>/dev/null | "
            "grep -v '.pyc' | grep -v '__pycache__' | head -20"
        )
        if cred_files.success and cred_files.output.strip():
            files = cred_files.output.strip().splitlines()
            self.add_finding(
                title=f"Config files with potential credentials: {len(files)}",
                description="Readable files contain credential-like patterns",
                severity=Severity.HIGH,
                evidence="\n".join(files[:15]),
                remediation="Move credentials to a secrets manager or encrypted vault",
            )

        # .env files
        env_files = session.execute(
            "find /home /opt /var/www /srv -name '.env' -readable 2>/dev/null | head -10"
        )
        if env_files.success and env_files.output.strip():
            self.add_finding(
                title=f".env files found: {len(env_files.output.strip().splitlines())}",
                description=".env files often contain plaintext secrets (API keys, DB passwords)",
                severity=Severity.HIGH,
                evidence=env_files.output.strip(),
                remediation="Restrict .env permissions to 600; use vault for secrets",
            )

        # T1552.004 — Private Keys
        # SSH keys with weak permissions
        ssh_keys = session.execute(
            "find /home /root -name 'id_rsa' -o -name 'id_ecdsa' -o -name 'id_ed25519' "
            "-o -name '*.pem' -o -name '*.key' 2>/dev/null | head -15"
        )
        if ssh_keys.success and ssh_keys.output.strip():
            for key_path in ssh_keys.output.strip().splitlines():
                perms = session.execute(f"stat -c '%a %U' {key_path} 2>/dev/null")
                if perms.success and perms.output.strip():
                    perm_val = perms.output.strip().split()[0]
                    if perm_val not in ("600", "400"):
                        self.add_finding(
                            title=f"Private key with weak permissions: {key_path}",
                            description=f"Key file has permissions {perm_val} (should be 600 or 400)",
                            severity=Severity.HIGH,
                            evidence=f"{key_path}: {perms.output.strip()}",
                            remediation=f"chmod 600 {key_path}",
                        )
                    else:
                        self.add_finding(
                            title=f"Private key found: {key_path}",
                            description="Private key exists (permissions are correct)",
                            severity=Severity.INFO,
                            evidence=f"{key_path}: {perms.output.strip()}",
                        )

        # Unprotected SSH keys (no passphrase)
        for key_path in (ssh_keys.output.strip().splitlines() if ssh_keys.success and ssh_keys.output.strip() else []):
            header = session.execute(f"head -2 {key_path} 2>/dev/null")
            if header.success and "ENCRYPTED" not in header.output:
                self.add_finding(
                    title=f"Unencrypted private key: {key_path}",
                    description="Private key has no passphrase — anyone with file access can use it",
                    severity=Severity.MEDIUM,
                    evidence=f"{key_path} has no ENCRYPTED header",
                    remediation=f"Add passphrase: ssh-keygen -p -f {key_path}",
                )

        # World-readable credentials in /etc
        world_readable = session.execute(
            "find /etc -maxdepth 2 -perm -o=r -name '*pass*' -o -name '*secret*' -o -name '*cred*' "
            "-o -name '*.key' -o -name '*.pem' 2>/dev/null | head -10"
        )
        if world_readable.success and world_readable.output.strip():
            self.add_finding(
                title="World-readable credential files in /etc",
                description="Files with credential-like names are readable by all users",
                severity=Severity.HIGH,
                evidence=world_readable.output.strip(),
                remediation="Restrict permissions to 640 or 600",
            )

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Set HISTCONTROL=ignorespace and HISTIGNORE for sensitive commands",
            "Move credentials from config files to a secrets manager (Vault, AWS SM)",
            "Set private key permissions to 600 and add passphrases",
            "Restrict .env file permissions to 600",
            "Use credential scanning tools in CI/CD pipelines",
        ]

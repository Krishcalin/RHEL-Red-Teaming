"""T1555 — Credentials from Password Stores.

Checks for accessible browser credential stores and password managers.
Sub-techniques: T1555.003 (Web Browsers), T1555.005 (Password Managers).
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule

BROWSER_CRED_STORES = [
    ("~/.mozilla/firefox/*/logins.json", "Firefox saved passwords"),
    ("~/.mozilla/firefox/*/key4.db", "Firefox key database"),
    ("~/.config/google-chrome/Default/Login Data", "Chrome saved passwords"),
    ("~/.config/google-chrome/Default/Cookies", "Chrome cookies"),
    ("~/.config/chromium/Default/Login Data", "Chromium saved passwords"),
]

PASSWORD_MANAGERS = [
    ("~/.password-store", "pass (GPG-based)"),
    ("~/.local/share/keyrings", "GNOME Keyring"),
    ("~/.local/share/kwalletd", "KDE Wallet"),
    ("~/.keepassxc", "KeePassXC"),
    ("~/.config/Bitwarden", "Bitwarden"),
]


class CredentialStoresCheck(BaseModule):
    TECHNIQUE_ID = "T1555"
    TECHNIQUE_NAME = "Credentials from Password Stores"
    TACTIC = Tactic.CREDENTIAL_ACCESS
    SEVERITY = Severity.HIGH
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        # T1555.003 — Browser credential stores
        for pattern, desc in BROWSER_CRED_STORES:
            check = session.execute(f"ls {pattern} 2>/dev/null")
            if check.success and check.output.strip():
                self.add_finding(
                    title=f"Browser credential store found: {desc}",
                    description=f"Browser-saved credentials are accessible at {check.output.strip().splitlines()[0]}",
                    severity=Severity.HIGH,
                    evidence=check.output.strip()[:300],
                    remediation="Use a dedicated password manager; disable browser credential storage",
                )

        # T1555.005 — Password Managers
        for path, desc in PASSWORD_MANAGERS:
            check = session.execute(f"test -d {path} && echo found")
            if check.success and check.output.strip() == "found":
                perms = session.execute(f"stat -c '%a' {path} 2>/dev/null")
                perm_val = perms.output.strip() if perms.success else "unknown"
                self.add_finding(
                    title=f"Password manager data found: {desc}",
                    description=f"{desc} data directory exists (permissions: {perm_val})",
                    severity=Severity.MEDIUM,
                    evidence=f"{path} (permissions: {perm_val})",
                    remediation="Ensure password manager data is encrypted and permissions are 700",
                )

        # GNOME Keyring — check if unlocked
        keyring_check = session.execute("ls ~/.local/share/keyrings/*.keyring 2>/dev/null")
        if keyring_check.success and keyring_check.output.strip():
            self.add_finding(
                title="GNOME Keyring files accessible",
                description="Keyring files store credentials that may be extractable",
                severity=Severity.MEDIUM,
                evidence=keyring_check.output.strip()[:300],
                remediation="Ensure keyring is locked when not in use; set restrictive permissions",
            )

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Disable browser credential storage via enterprise policies",
            "Use a dedicated password manager with strong encryption",
            "Set 700 permissions on password manager data directories",
            "Encrypt home directories at rest",
        ]

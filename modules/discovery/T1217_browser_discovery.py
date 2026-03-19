"""T1217 — Browser Information Discovery.

Checks for browser data accessibility (history, bookmarks, profiles).
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule

BROWSER_PATHS = [
    ("~/.mozilla/firefox", "Firefox profiles"),
    ("~/.config/google-chrome", "Google Chrome data"),
    ("~/.config/chromium", "Chromium data"),
    ("~/.config/BraveSoftware", "Brave browser data"),
    ("~/.local/share/qutebrowser", "qutebrowser data"),
]


class BrowserDiscoveryCheck(BaseModule):
    TECHNIQUE_ID = "T1217"
    TECHNIQUE_NAME = "Browser Information Discovery"
    TACTIC = Tactic.DISCOVERY
    SEVERITY = Severity.MEDIUM
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        for path, desc in BROWSER_PATHS:
            expanded = session.execute(f"test -d {path} && echo exists")
            if expanded.success and expanded.output.strip() == "exists":
                # Count files
                count = session.execute(f"find {path} -type f 2>/dev/null | wc -l")
                file_count = count.output.strip() if count.success else "unknown"

                self.add_finding(
                    title=f"Browser data found: {desc}",
                    description=f"{desc} directory exists with {file_count} files",
                    severity=Severity.MEDIUM,
                    evidence=f"Path: {path} ({file_count} files)",
                    remediation="Restrict browser profile permissions; encrypt sensitive data at rest",
                )

                # Check for credential stores
                cred_files = session.execute(
                    f"find {path} -name 'logins.json' -o -name 'Login Data' -o -name 'key*.db' 2>/dev/null | head -5"
                )
                if cred_files.success and cred_files.output.strip():
                    self.add_finding(
                        title=f"Browser credential stores accessible: {desc}",
                        description="Browser-saved passwords/credentials are accessible",
                        severity=Severity.HIGH,
                        evidence=cred_files.output.strip(),
                        remediation="Use a dedicated password manager; clear browser-saved credentials",
                    )

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Use a dedicated password manager instead of browser credential storage",
            "Restrict browser profile directory permissions",
            "Encrypt home directories at rest",
            "Disable browser credential storage via enterprise policies",
        ]

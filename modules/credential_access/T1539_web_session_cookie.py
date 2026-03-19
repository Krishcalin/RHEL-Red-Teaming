"""T1539 — Steal Web Session Cookie.

Checks for accessible browser cookies and session token files.
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule

COOKIE_STORES = [
    ("~/.mozilla/firefox/*/cookies.sqlite", "Firefox cookies"),
    ("~/.config/google-chrome/Default/Cookies", "Chrome cookies"),
    ("~/.config/chromium/Default/Cookies", "Chromium cookies"),
    ("~/.config/BraveSoftware/Brave-Browser/Default/Cookies", "Brave cookies"),
]


class WebSessionCookieCheck(BaseModule):
    TECHNIQUE_ID = "T1539"
    TECHNIQUE_NAME = "Steal Web Session Cookie"
    TACTIC = Tactic.CREDENTIAL_ACCESS
    SEVERITY = Severity.MEDIUM
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        for pattern, desc in COOKIE_STORES:
            check = session.execute(f"ls {pattern} 2>/dev/null")
            if check.success and check.output.strip():
                self.add_finding(
                    title=f"Browser cookie store accessible: {desc}",
                    description="Cookie database is readable — session tokens can be extracted",
                    severity=Severity.MEDIUM,
                    evidence=check.output.strip().splitlines()[0],
                    remediation="Encrypt home directories; restrict cookie file permissions",
                )

        # Check for curl cookie jars
        cookie_jars = session.execute(
            "find /home /root /tmp -name 'cookies.txt' -o -name '.cookies' -o -name 'cookie_jar' "
            "2>/dev/null | head -10"
        )
        if cookie_jars.success and cookie_jars.output.strip():
            self.add_finding(
                title="Cookie jar files found on disk",
                description="Plaintext cookie files from curl/wget are accessible",
                severity=Severity.MEDIUM,
                evidence=cookie_jars.output.strip(),
                remediation="Remove cookie jar files after use",
            )

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Encrypt home directories at rest",
            "Clear browser cookies regularly",
            "Remove curl/wget cookie jar files after use",
            "Use short session timeouts on web applications",
        ]

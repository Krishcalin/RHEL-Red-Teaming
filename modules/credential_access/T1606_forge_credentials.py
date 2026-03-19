"""T1606 — Forge Web Credentials.

Checks for web cookie security and session management weaknesses.
Sub-technique: T1606.001 (Web Cookies).
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class ForgeCredentialsCheck(BaseModule):
    TECHNIQUE_ID = "T1606"
    TECHNIQUE_NAME = "Forge Web Credentials"
    TACTIC = Tactic.CREDENTIAL_ACCESS
    SEVERITY = Severity.MEDIUM
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        # Check web server configurations for cookie security
        # Apache
        apache_conf = session.execute(
            "grep -rli 'HttpOnly\\|Secure\\|SameSite' /etc/httpd/conf/ /etc/httpd/conf.d/ 2>/dev/null"
        )
        apache_running = session.execute("systemctl is-active httpd 2>/dev/null")
        if apache_running.success and apache_running.output.strip() == "active":
            if not apache_conf.success or not apache_conf.output.strip():
                self.add_finding(
                    title="Apache: No cookie security headers configured",
                    description="HttpOnly, Secure, and SameSite cookie flags are not set in Apache config",
                    severity=Severity.MEDIUM,
                    evidence="No cookie security directives found in Apache configuration",
                    remediation="Add: Header edit Set-Cookie ^(.*)$ $1;HttpOnly;Secure;SameSite=Strict",
                )

        # Nginx
        nginx_running = session.execute("systemctl is-active nginx 2>/dev/null")
        if nginx_running.success and nginx_running.output.strip() == "active":
            nginx_conf = session.execute(
                "grep -rli 'HttpOnly\\|Secure\\|SameSite' /etc/nginx/ 2>/dev/null"
            )
            if not nginx_conf.success or not nginx_conf.output.strip():
                self.add_finding(
                    title="Nginx: No cookie security headers configured",
                    description="Cookie security flags are not configured in Nginx",
                    severity=Severity.MEDIUM,
                    remediation="Add proxy_cookie_flags to set HttpOnly, Secure, SameSite",
                )

        # Check for accessible cookie/session files
        session_dirs = [
            "/tmp/sess_*",
            "/var/lib/php/session/*",
            "/var/tmp/sess_*",
        ]
        for pattern in session_dirs:
            check = session.execute(f"ls {pattern} 2>/dev/null | head -5")
            if check.success and check.output.strip():
                self.add_finding(
                    title="Web session files accessible",
                    description="PHP/web session files are readable — session hijacking possible",
                    severity=Severity.HIGH,
                    evidence=check.output.strip()[:300],
                    remediation="Restrict session directory permissions; use Redis/memcached for sessions",
                )

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Set HttpOnly, Secure, and SameSite flags on all cookies",
            "Use secure session storage (Redis, memcached) instead of file-based",
            "Restrict session file directory permissions",
            "Implement CSRF protection on web applications",
        ]

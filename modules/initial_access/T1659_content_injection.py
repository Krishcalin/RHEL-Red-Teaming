"""T1659 — Content Injection.

Checks for injectable web content served by the host on RHEL systems.
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class ContentInjectionCheck(BaseModule):
    TECHNIQUE_ID = "T1659"
    TECHNIQUE_NAME = "Content Injection"
    TACTIC = Tactic.INITIAL_ACCESS
    SEVERITY = Severity.HIGH
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        self._check_writable_web_content(session)
        self._check_csp_headers(session)
        self._check_cgi_scripts(session)

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def _check_writable_web_content(self, session: Session) -> None:
        roots = ["/var/www/html", "/usr/share/nginx/html", "/srv/www"]
        for root in roots:
            result = session.execute(f"test -d {root} && find {root} -maxdepth 2 -writable -name '*.html' -o -writable -name '*.php' -o -writable -name '*.js' 2>/dev/null | head -10")
            if result.success and result.output.strip():
                self.add_finding(
                    title=f"Writable web files in {root}",
                    description="Web content files are writable — content injection is possible",
                    severity=Severity.HIGH,
                    evidence=result.output.strip()[:500],
                    remediation=f"Set web files owned by root, not writable by web server user",
                )

    def _check_csp_headers(self, session: Session) -> None:
        for conf_dir in ["/etc/httpd/conf", "/etc/nginx"]:
            result = session.execute(f"grep -ri 'Content-Security-Policy' {conf_dir}/ 2>/dev/null")
            if result.success and not result.output.strip():
                server = "Apache" if "httpd" in conf_dir else "Nginx"
                exists = session.execute(f"test -d {conf_dir} && echo exists")
                if exists.success and "exists" in exists.output:
                    self.add_finding(
                        title=f"No CSP headers configured ({server})",
                        description=f"{server} does not set Content-Security-Policy — XSS and injection attacks are easier",
                        severity=Severity.MEDIUM,
                        evidence=f"No CSP directive in {conf_dir}",
                        remediation=f"Add Content-Security-Policy header to {server} configuration",
                    )

    def _check_cgi_scripts(self, session: Session) -> None:
        result = session.execute("find /var/www/cgi-bin /usr/lib/cgi-bin -type f -executable 2>/dev/null | head -10")
        if result.success and result.output.strip():
            self.add_finding(
                title="CGI scripts found",
                description="Executable CGI scripts may be vulnerable to injection attacks",
                severity=Severity.MEDIUM,
                evidence=result.output.strip()[:300],
                remediation="Audit CGI scripts; migrate to modern web frameworks",
            )

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Set web files owned by root with restrictive permissions",
            "Configure Content-Security-Policy headers",
            "Audit and remove legacy CGI scripts",
            "Deploy WAF for content injection detection",
        ]

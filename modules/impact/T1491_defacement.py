"""T1491 — Defacement.

Checks web content write access, web server configuration, and content
integrity controls on RHEL systems.
Sub-techniques: Internal (T1491.001), External (T1491.002).
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class DefacementCheck(BaseModule):
    TECHNIQUE_ID = "T1491"
    TECHNIQUE_NAME = "Defacement"
    TACTIC = Tactic.IMPACT
    SEVERITY = Severity.HIGH
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    WEB_ROOTS = ["/var/www/html", "/var/www", "/usr/share/nginx/html",
                 "/srv/www", "/opt/www"]

    def check(self, session: Session) -> ModuleResult:
        self._check_web_root_writable(session)
        self._check_web_server_user(session)
        self._check_motd_issue(session)

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def _check_web_root_writable(self, session: Session) -> None:
        for root in self.WEB_ROOTS:
            result = session.execute(f"test -d {root} && find {root} -maxdepth 1 -writable -type f 2>/dev/null | head -10")
            if result.success and result.output.strip():
                count = len(result.output.strip().splitlines())
                self.add_finding(
                    title=f"Writable web files in {root}",
                    description=f"Found {count} writable files in {root} — web content can be defaced",
                    severity=Severity.HIGH,
                    evidence=result.output.strip()[:500],
                    remediation=f"Set web root owned by root, readable by web server: chown -R root:root {root}",
                )

    def _check_web_server_user(self, session: Session) -> None:
        for proc in ["httpd", "nginx", "apache2"]:
            result = session.execute(f"ps -eo user,comm 2>/dev/null | grep {proc} | head -3")
            if result.success and result.output.strip():
                users = set()
                for line in result.output.strip().splitlines():
                    parts = line.split()
                    if parts:
                        users.add(parts[0])
                if "root" in users and len(users) == 1:
                    self.add_finding(
                        title=f"{proc} running entirely as root",
                        description=f"All {proc} processes run as root — compromise gives full write access",
                        severity=Severity.HIGH,
                        evidence=result.output.strip()[:300],
                        remediation=f"Configure {proc} to drop privileges to a dedicated user (e.g., apache, nginx)",
                    )

    def _check_motd_issue(self, session: Session) -> None:
        for f in ["/etc/motd", "/etc/issue", "/etc/issue.net"]:
            result = session.execute(f"test -f {f} && find {f} -writable 2>/dev/null")
            if result.success and result.output.strip():
                self.add_finding(
                    title=f"Login banner writable: {f}",
                    description=f"Current user can modify {f} — internal defacement via login banners",
                    severity=Severity.LOW,
                    evidence=f"{f} is writable",
                    remediation=f"Set ownership: chown root:root {f} && chmod 644 {f}",
                )

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Set web root files owned by root, readable by web server user only",
            "Run web servers with least-privilege dedicated user accounts",
            "Deploy file integrity monitoring (AIDE) on web content directories",
            "Use content delivery from version control (git deploy) to detect changes",
            "Restrict write permissions on login banners (/etc/motd, /etc/issue)",
        ]

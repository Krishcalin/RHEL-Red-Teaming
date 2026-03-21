"""T1213 — Data from Information Repositories.

Checks database access and credential exposure on RHEL systems.
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class DataRepositoriesCheck(BaseModule):
    TECHNIQUE_ID = "T1213"
    TECHNIQUE_NAME = "Data from Information Repositories"
    TACTIC = Tactic.COLLECTION
    SEVERITY = Severity.HIGH
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        self._check_database_access(session)
        self._check_git_repos(session)
        self._check_wiki_docs(session)

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def _check_database_access(self, session: Session) -> None:
        dbs = {
            "mysql": ("3306", "MySQL"),
            "psql": ("5432", "PostgreSQL"),
            "mongo": ("27017", "MongoDB"),
            "redis-cli": ("6379", "Redis"),
        }
        for cli, (port, name) in dbs.items():
            result = session.execute(f"which {cli} 2>/dev/null")
            if result.success and result.output.strip():
                listening = session.execute(f"ss -tuln 2>/dev/null | grep ':{port} '")
                if listening.success and listening.output.strip():
                    self.add_finding(
                        title=f"{name} client and server accessible",
                        description=f"{name} CLI ({cli}) is available and port {port} is listening",
                        severity=Severity.HIGH,
                        evidence=f"{cli} at {result.output.strip()}; port {port} listening",
                        remediation=f"Restrict {name} access; require authentication; bind to localhost",
                    )

    def _check_git_repos(self, session: Session) -> None:
        result = session.execute("find /opt /srv /home -maxdepth 3 -name '.git' -type d 2>/dev/null | head -10")
        if result.success and result.output.strip():
            count = len(result.output.strip().splitlines())
            self.add_finding(
                title=f"{count} git repositories found",
                description="Git repositories may contain sensitive code, configs, or credentials",
                severity=Severity.MEDIUM,
                evidence=result.output.strip()[:500],
                remediation="Restrict git repository access; audit for secrets with git-secrets or gitleaks",
            )

    def _check_wiki_docs(self, session: Session) -> None:
        doc_dirs = ["/var/www/wiki", "/opt/confluence", "/opt/mediawiki", "/srv/gitea"]
        for d in doc_dirs:
            result = session.execute(f"test -d {d} && echo exists")
            if result.success and "exists" in result.output:
                self.add_finding(
                    title=f"Documentation platform found: {d}",
                    description=f"Knowledge base at {d} may contain sensitive documentation",
                    severity=Severity.MEDIUM,
                    evidence=f"{d} exists",
                    remediation=f"Restrict access to {d}; enforce authentication",
                )

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Require authentication for all database access",
            "Bind databases to localhost; use SSH tunnels for remote access",
            "Audit git repositories for embedded secrets",
            "Restrict documentation platform access with authentication",
        ]

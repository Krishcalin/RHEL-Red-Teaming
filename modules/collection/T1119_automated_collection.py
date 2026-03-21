"""T1119 — Automated Collection.

Checks scripted data collection feasibility on RHEL systems.
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class AutomatedCollectionCheck(BaseModule):
    TECHNIQUE_ID = "T1119"
    TECHNIQUE_NAME = "Automated Collection"
    TACTIC = Tactic.COLLECTION
    SEVERITY = Severity.MEDIUM
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        self._check_search_tools(session)
        self._check_locate_database(session)
        self._check_scripting_langs(session)

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def _check_search_tools(self, session: Session) -> None:
        tools = {"find": "file search", "grep": "content search",
                 "awk": "text processing", "sed": "stream editor"}
        available = []
        for tool, desc in tools.items():
            result = session.execute(f"which {tool} 2>/dev/null")
            if result.success and result.output.strip():
                available.append(tool)
        if len(available) >= 3:
            self.add_finding(
                title=f"Collection tools available: {', '.join(available)}",
                description="Standard search and processing tools enable automated data collection",
                severity=Severity.INFO,
                evidence=", ".join(available),
                remediation="Monitor bulk file operations with auditd rules",
            )

    def _check_locate_database(self, session: Session) -> None:
        result = session.execute("test -f /var/lib/mlocate/mlocate.db && echo exists 2>/dev/null; test -f /var/lib/plocate/plocate.db && echo exists 2>/dev/null")
        if result.success and "exists" in result.output:
            self.add_finding(
                title="File location database exists (mlocate/plocate)",
                description="Pre-built file index enables rapid automated file discovery",
                severity=Severity.LOW,
                evidence="mlocate/plocate database found",
                remediation="Restrict locate database access; configure PRUNEPATHS for sensitive dirs",
            )

    def _check_scripting_langs(self, session: Session) -> None:
        for lang in ["python3", "perl", "ruby"]:
            result = session.execute(f"which {lang} 2>/dev/null")
            if result.success and result.output.strip():
                self.add_finding(
                    title=f"Scripting language: {lang}",
                    description=f"{lang} enables writing automated collection scripts",
                    severity=Severity.INFO,
                    evidence=result.output.strip(),
                    remediation=f"Remove {lang} from production servers if not operationally needed",
                )

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Monitor bulk file access patterns with auditd",
            "Restrict locate database access and prune sensitive paths",
            "Remove scripting languages from production servers where possible",
        ]

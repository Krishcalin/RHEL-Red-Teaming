"""Abstract base class for all ATT&CK technique modules."""

from __future__ import annotations

import time
from abc import ABC, abstractmethod

import structlog

from core.models import Finding, ModuleResult, Severity, Status, Tactic
from core.session import Session

log = structlog.get_logger("module")


class BaseModule(ABC):
    """Base class that all technique modules must inherit from.

    Required class attributes:
        TECHNIQUE_ID: MITRE ATT&CK technique ID (e.g., "T1082")
        TECHNIQUE_NAME: Human-readable technique name
        TACTIC: The ATT&CK tactic this technique belongs to
        SEVERITY: Default severity level for findings
        SUPPORTED_OS: List of supported OS identifiers (e.g., ["rhel8", "rhel9"])
        REQUIRES_ROOT: Whether root/sudo is needed
        SAFE_MODE: Whether this module is safe to run in check-only mode
    """

    TECHNIQUE_ID: str = ""
    TECHNIQUE_NAME: str = ""
    TACTIC: Tactic = Tactic.DISCOVERY
    SEVERITY: Severity = Severity.MEDIUM
    SUPPORTED_OS: list[str] = ["rhel8", "rhel9"]
    REQUIRES_ROOT: bool = False
    SAFE_MODE: bool = True

    def __init__(self) -> None:
        self._findings: list[Finding] = []
        self._log = log.bind(
            technique_id=self.TECHNIQUE_ID,
            technique_name=self.TECHNIQUE_NAME,
        )

    def run(self, session: Session, simulate: bool = False) -> ModuleResult:
        """Execute the module check or simulation with timing and error handling."""
        self._findings = []
        start = time.time()

        self._log.info(
            "module_start",
            mode="simulate" if simulate else "check",
            target=session.target.host,
        )

        try:
            if simulate:
                result = self.simulate(session)
            else:
                result = self.check(session)
        except Exception as e:
            self._log.error("module_error", error=str(e))
            result = ModuleResult(
                technique_id=self.TECHNIQUE_ID,
                technique_name=self.TECHNIQUE_NAME,
                tactic=self.TACTIC,
                status=Status.ERROR,
                error_message=str(e),
                target_host=session.target.host,
            )

        result.duration_seconds = time.time() - start
        result.target_host = session.target.host
        result.mitigations = self.get_mitigations()

        self._log.info(
            "module_complete",
            status=result.status.value,
            findings=result.finding_count,
            duration=f"{result.duration_seconds:.2f}s",
        )

        return result

    @abstractmethod
    def check(self, session: Session) -> ModuleResult:
        """Passive, read-only check. Must not modify the target system."""
        ...

    @abstractmethod
    def simulate(self, session: Session) -> ModuleResult:
        """Active simulation. Requires --simulate flag. Must be reversible via cleanup()."""
        ...

    def cleanup(self, session: Session) -> None:
        """Revert any changes made during simulate(). Override in subclasses."""
        pass

    @abstractmethod
    def get_mitigations(self) -> list[str]:
        """Return recommended remediations for this technique."""
        ...

    def add_finding(
        self,
        title: str,
        description: str,
        severity: Severity | None = None,
        evidence: str = "",
        remediation: str = "",
        references: list[str] | None = None,
        metadata: dict | None = None,
    ) -> Finding:
        """Helper to create and track a finding."""
        finding = Finding(
            title=title,
            description=description,
            severity=severity or self.SEVERITY,
            evidence=evidence,
            remediation=remediation,
            references=references or [],
            metadata=metadata or {},
        )
        self._findings.append(finding)
        return finding

    def make_result(self, status: Status, raw_output: str = "") -> ModuleResult:
        """Helper to create a ModuleResult with accumulated findings."""
        return ModuleResult(
            technique_id=self.TECHNIQUE_ID,
            technique_name=self.TECHNIQUE_NAME,
            tactic=self.TACTIC,
            status=status,
            findings=list(self._findings),
            raw_output=raw_output,
        )

    def is_supported(self, os_id: str) -> bool:
        """Check if this module supports the target OS."""
        return os_id.lower() in [s.lower() for s in self.SUPPORTED_OS]

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} {self.TECHNIQUE_ID}: {self.TECHNIQUE_NAME}>"

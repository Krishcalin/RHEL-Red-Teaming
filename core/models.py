"""Data models for RHEL Red Teaming tool."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Status(str, Enum):
    VULNERABLE = "vulnerable"
    NOT_VULNERABLE = "not_vulnerable"
    ERROR = "error"
    SKIPPED = "skipped"
    PARTIAL = "partial"


class Tactic(str, Enum):
    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DEFENSE_EVASION = "defense_evasion"
    CREDENTIAL_ACCESS = "credential_access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral_movement"
    COLLECTION = "collection"
    COMMAND_AND_CONTROL = "command_and_control"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"


class SessionType(str, Enum):
    LOCAL = "local"
    SSH = "ssh"


@dataclass
class Target:
    """Represents a scan target."""

    host: str
    port: int = 22
    username: str | None = None
    password: str | None = None
    key_file: str | None = None
    session_type: SessionType = SessionType.LOCAL
    os_version: str | None = None
    hostname: str | None = None

    @property
    def is_local(self) -> bool:
        return self.host in ("localhost", "127.0.0.1", "::1")


@dataclass
class Finding:
    """A single security finding within a module result."""

    title: str
    description: str
    severity: Severity
    evidence: str = ""
    remediation: str = ""
    references: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class ModuleResult:
    """Result from a technique module check or simulation."""

    technique_id: str
    technique_name: str
    tactic: Tactic
    status: Status
    findings: list[Finding] = field(default_factory=list)
    timestamp: datetime = field(default_factory=datetime.now)
    duration_seconds: float = 0.0
    target_host: str = ""
    raw_output: str = ""
    error_message: str = ""
    mitigations: list[str] = field(default_factory=list)

    @property
    def is_vulnerable(self) -> bool:
        return self.status == Status.VULNERABLE

    @property
    def finding_count(self) -> int:
        return len(self.findings)

    @property
    def max_severity(self) -> Severity:
        if not self.findings:
            return Severity.INFO
        severity_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
        for sev in severity_order:
            if any(f.severity == sev for f in self.findings):
                return sev
        return Severity.INFO

    def to_dict(self) -> dict[str, Any]:
        return {
            "technique_id": self.technique_id,
            "technique_name": self.technique_name,
            "tactic": self.tactic.value,
            "status": self.status.value,
            "findings": [
                {
                    "title": f.title,
                    "description": f.description,
                    "severity": f.severity.value,
                    "evidence": f.evidence,
                    "remediation": f.remediation,
                    "references": f.references,
                    "metadata": f.metadata,
                }
                for f in self.findings
            ],
            "timestamp": self.timestamp.isoformat(),
            "duration_seconds": self.duration_seconds,
            "target_host": self.target_host,
            "error_message": self.error_message,
            "mitigations": self.mitigations,
        }


@dataclass
class ScanConfig:
    """Configuration for a scan run."""

    targets: list[Target] = field(default_factory=list)
    profile: str = "quick"
    simulate: bool = False
    tactics: list[Tactic] | None = None
    techniques: list[str] | None = None
    timeout: int = 300
    parallel: bool = False
    max_workers: int = 4
    output_dir: str = "reports"
    evidence_dir: str = "evidence"


@dataclass
class ScanResult:
    """Aggregated results from a complete scan run."""

    scan_id: str
    config: ScanConfig
    results: list[ModuleResult] = field(default_factory=list)
    start_time: datetime = field(default_factory=datetime.now)
    end_time: datetime | None = None
    target_info: dict[str, Any] = field(default_factory=dict)

    @property
    def total_checks(self) -> int:
        return len(self.results)

    @property
    def vulnerable_count(self) -> int:
        return sum(1 for r in self.results if r.is_vulnerable)

    @property
    def duration_seconds(self) -> float:
        if self.end_time is None:
            return 0.0
        return (self.end_time - self.start_time).total_seconds()

    def to_dict(self) -> dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "duration_seconds": self.duration_seconds,
            "total_checks": self.total_checks,
            "vulnerable_count": self.vulnerable_count,
            "target_info": self.target_info,
            "results": [r.to_dict() for r in self.results],
        }

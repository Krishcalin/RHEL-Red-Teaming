"""Structured logging and evidence chain for RHEL Red Teaming tool."""

from __future__ import annotations

import json
import os
from datetime import datetime
from pathlib import Path

import structlog


def setup_logging(
    log_level: str = "INFO",
    log_file: str | None = None,
    json_output: bool = False,
) -> structlog.stdlib.BoundLogger:
    """Configure structured logging for the tool."""
    processors: list[structlog.types.Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.UnicodeDecoder(),
    ]

    if json_output:
        processors.append(structlog.processors.JSONRenderer())
    else:
        processors.append(structlog.dev.ConsoleRenderer(colors=True))

    structlog.configure(
        processors=processors,
        wrapper_class=structlog.stdlib.BoundLogger,
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )

    logger = structlog.get_logger("rhel-rt")

    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)

    return logger


def get_logger(name: str = "rhel-rt") -> structlog.stdlib.BoundLogger:
    """Get a named logger instance."""
    return structlog.get_logger(name)


class EvidenceLogger:
    """Logs evidence artifacts from scan operations."""

    def __init__(self, evidence_dir: str = "evidence"):
        self.evidence_dir = Path(evidence_dir)
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        self.log = get_logger("evidence")

    def log_evidence(
        self,
        technique_id: str,
        target_host: str,
        evidence_type: str,
        data: str,
        metadata: dict | None = None,
    ) -> Path:
        """Write evidence artifact to disk with audit trail."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_host = target_host.replace(".", "_").replace(":", "_")
        filename = f"{timestamp}_{technique_id}_{safe_host}_{evidence_type}.json"

        evidence_path = self.evidence_dir / technique_id / filename
        evidence_path.parent.mkdir(parents=True, exist_ok=True)

        record = {
            "timestamp": datetime.now().isoformat(),
            "technique_id": technique_id,
            "target_host": target_host,
            "evidence_type": evidence_type,
            "data": data,
            "metadata": metadata or {},
        }

        evidence_path.write_text(json.dumps(record, indent=2), encoding="utf-8")

        self.log.info(
            "evidence_recorded",
            technique_id=technique_id,
            target=target_host,
            path=str(evidence_path),
        )

        return evidence_path

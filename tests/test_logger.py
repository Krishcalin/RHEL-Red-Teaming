"""Tests for structured logging and evidence chain."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from core.logger import EvidenceLogger, get_logger, setup_logging


class TestSetupLogging:
    def test_returns_logger(self):
        logger = setup_logging()
        assert logger is not None

    def test_json_output_mode(self):
        logger = setup_logging(json_output=True)
        assert logger is not None

    def test_custom_log_level(self):
        logger = setup_logging(log_level="DEBUG")
        assert logger is not None

    def test_log_file_creates_parent_dir(self, tmp_path: Path):
        log_file = str(tmp_path / "nested" / "test.log")
        logger = setup_logging(log_file=log_file)
        assert logger is not None
        assert (tmp_path / "nested").exists()


class TestGetLogger:
    def test_returns_logger(self):
        logger = get_logger("test-component")
        assert logger is not None

    def test_default_name(self):
        logger = get_logger()
        assert logger is not None


class TestEvidenceLogger:
    def test_creates_evidence_dir(self, tmp_path: Path):
        evidence_dir = tmp_path / "evidence"
        EvidenceLogger(evidence_dir=str(evidence_dir))
        assert evidence_dir.exists()

    def test_log_evidence_creates_file(self, tmp_path: Path):
        el = EvidenceLogger(evidence_dir=str(tmp_path))
        path = el.log_evidence(
            technique_id="T1082",
            target_host="192.168.1.10",
            evidence_type="command_output",
            data="uname -a: Linux rhel9 5.14.0",
        )
        assert path.exists()
        assert path.suffix == ".json"

    def test_evidence_file_content(self, tmp_path: Path):
        el = EvidenceLogger(evidence_dir=str(tmp_path))
        path = el.log_evidence(
            technique_id="T1082",
            target_host="localhost",
            evidence_type="check",
            data="test data",
            metadata={"key": "value"},
        )
        record = json.loads(path.read_text(encoding="utf-8"))
        assert record["technique_id"] == "T1082"
        assert record["target_host"] == "localhost"
        assert record["evidence_type"] == "check"
        assert record["data"] == "test data"
        assert record["metadata"] == {"key": "value"}

    def test_evidence_none_metadata(self, tmp_path: Path):
        el = EvidenceLogger(evidence_dir=str(tmp_path))
        path = el.log_evidence(
            technique_id="T1087",
            target_host="10.0.0.1",
            evidence_type="scan",
            data="some output",
        )
        record = json.loads(path.read_text(encoding="utf-8"))
        assert record["metadata"] == {}

    def test_evidence_subdirectory_by_technique(self, tmp_path: Path):
        el = EvidenceLogger(evidence_dir=str(tmp_path))
        path = el.log_evidence(
            technique_id="T1003",
            target_host="host1",
            evidence_type="cred_check",
            data="shadow file access",
        )
        assert "T1003" in str(path.parent.name)

    def test_host_sanitization(self, tmp_path: Path):
        el = EvidenceLogger(evidence_dir=str(tmp_path))
        path = el.log_evidence(
            technique_id="T1082",
            target_host="192.168.1.10",
            evidence_type="test",
            data="data",
        )
        assert "192_168_1_10" in path.name

    def test_ipv6_host_sanitization(self, tmp_path: Path):
        el = EvidenceLogger(evidence_dir=str(tmp_path))
        path = el.log_evidence(
            technique_id="T1082",
            target_host="::1",
            evidence_type="test",
            data="data",
        )
        assert "__1" in path.name

"""Tests for MITRE ATT&CK Navigator layer generation."""

from __future__ import annotations

import json
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from core.mitre_mapper import (
    LAYER_VERSION,
    NAV_VERSION,
    SEVERITY_SCORES,
    STATUS_COLORS,
    MitreMapper,
)
from core.models import (
    Finding,
    ModuleResult,
    ScanConfig,
    ScanResult,
    Severity,
    Status,
    Tactic,
)


@pytest.fixture
def scan_result() -> ScanResult:
    start = datetime(2026, 3, 20, 10, 0, 0)
    return ScanResult(
        scan_id="layer01",
        config=ScanConfig(),
        start_time=start,
        end_time=start + timedelta(seconds=20),
        target_info={"hostname": "rhel-test"},
        results=[
            ModuleResult(
                technique_id="T1082",
                technique_name="System Info",
                tactic=Tactic.DISCOVERY,
                status=Status.VULNERABLE,
                findings=[
                    Finding(title="Info Exposed", description="d", severity=Severity.HIGH),
                ],
            ),
            ModuleResult(
                technique_id="T1087",
                technique_name="Account Discovery",
                tactic=Tactic.DISCOVERY,
                status=Status.NOT_VULNERABLE,
            ),
            ModuleResult(
                technique_id="T1059",
                technique_name="Command Scripting",
                tactic=Tactic.EXECUTION,
                status=Status.ERROR,
                error_message="Permission denied",
            ),
        ],
    )


@pytest.fixture
def mapper(tmp_path: Path) -> MitreMapper:
    return MitreMapper(output_dir=str(tmp_path))


class TestMitreMapper:
    def test_generates_layer_file(self, mapper: MitreMapper, scan_result: ScanResult):
        path = mapper.generate_layer(scan_result)
        assert path.exists()
        assert path.name == "attack_layer_layer01.json"

    def test_layer_is_valid_json(self, mapper: MitreMapper, scan_result: ScanResult):
        path = mapper.generate_layer(scan_result)
        data = json.loads(path.read_text(encoding="utf-8"))
        assert data["domain"] == "enterprise-attack"
        assert data["name"] == "RHEL Red Team Scan - layer01"

    def test_layer_versions(self, mapper: MitreMapper, scan_result: ScanResult):
        path = mapper.generate_layer(scan_result)
        data = json.loads(path.read_text(encoding="utf-8"))
        assert data["versions"]["layer"] == LAYER_VERSION
        assert data["versions"]["navigator"] == NAV_VERSION

    def test_technique_entries(self, mapper: MitreMapper, scan_result: ScanResult):
        path = mapper.generate_layer(scan_result)
        data = json.loads(path.read_text(encoding="utf-8"))
        techs = data["techniques"]
        assert len(techs) == 3

        t1082 = next(t for t in techs if t["techniqueID"] == "T1082")
        assert t1082["color"] == STATUS_COLORS[Status.VULNERABLE]
        assert t1082["score"] == SEVERITY_SCORES[Severity.HIGH]
        assert t1082["tactic"] == "discovery"

    def test_tactic_dash_conversion(self, mapper: MitreMapper, scan_result: ScanResult):
        """Tactic names should use dashes, not underscores."""
        path = mapper.generate_layer(scan_result)
        data = json.loads(path.read_text(encoding="utf-8"))
        tactics = {t["tactic"] for t in data["techniques"]}
        for tactic in tactics:
            assert "_" not in tactic

    def test_not_vulnerable_has_no_score(self, mapper: MitreMapper, scan_result: ScanResult):
        path = mapper.generate_layer(scan_result)
        data = json.loads(path.read_text(encoding="utf-8"))
        t1087 = next(t for t in data["techniques"] if t["techniqueID"] == "T1087")
        assert "score" not in t1087
        assert t1087["color"] == STATUS_COLORS[Status.NOT_VULNERABLE]

    def test_error_technique_color(self, mapper: MitreMapper, scan_result: ScanResult):
        path = mapper.generate_layer(scan_result)
        data = json.loads(path.read_text(encoding="utf-8"))
        t1059 = next(t for t in data["techniques"] if t["techniqueID"] == "T1059")
        assert t1059["color"] == STATUS_COLORS[Status.ERROR]

    def test_legend_items(self, mapper: MitreMapper, scan_result: ScanResult):
        path = mapper.generate_layer(scan_result)
        data = json.loads(path.read_text(encoding="utf-8"))
        labels = {item["label"] for item in data["legendItems"]}
        assert labels == {"Vulnerable", "Secure", "Error", "Skipped", "Partial"}

    def test_description_includes_counts(self, mapper: MitreMapper, scan_result: ScanResult):
        path = mapper.generate_layer(scan_result)
        data = json.loads(path.read_text(encoding="utf-8"))
        assert "3 checks" in data["description"]
        assert "1 vulnerable" in data["description"]
        assert "rhel-test" in data["description"]

    def test_comment_building(self, mapper: MitreMapper, scan_result: ScanResult):
        path = mapper.generate_layer(scan_result)
        data = json.loads(path.read_text(encoding="utf-8"))
        t1082 = next(t for t in data["techniques"] if t["techniqueID"] == "T1082")
        assert "Status: vulnerable" in t1082["comment"]
        assert "Findings: 1" in t1082["comment"]
        assert "[high] Info Exposed" in t1082["comment"]

    def test_error_comment_includes_message(self, mapper: MitreMapper, scan_result: ScanResult):
        path = mapper.generate_layer(scan_result)
        data = json.loads(path.read_text(encoding="utf-8"))
        t1059 = next(t for t in data["techniques"] if t["techniqueID"] == "T1059")
        assert "Error: Permission denied" in t1059["comment"]

    def test_empty_scan_result(self, mapper: MitreMapper):
        sr = ScanResult(scan_id="empty", config=ScanConfig())
        path = mapper.generate_layer(sr)
        data = json.loads(path.read_text(encoding="utf-8"))
        assert data["techniques"] == []


class TestConstants:
    def test_all_statuses_have_colors(self):
        for status in Status:
            assert status in STATUS_COLORS

    def test_all_severities_have_scores(self):
        for sev in Severity:
            assert sev in SEVERITY_SCORES

    def test_severity_scores_ordered(self):
        assert SEVERITY_SCORES[Severity.CRITICAL] > SEVERITY_SCORES[Severity.HIGH]
        assert SEVERITY_SCORES[Severity.HIGH] > SEVERITY_SCORES[Severity.MEDIUM]
        assert SEVERITY_SCORES[Severity.MEDIUM] > SEVERITY_SCORES[Severity.LOW]
        assert SEVERITY_SCORES[Severity.LOW] > SEVERITY_SCORES[Severity.INFO]

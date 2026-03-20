"""Tests for report generation."""

from __future__ import annotations

import csv
import json
from datetime import datetime, timedelta
from io import StringIO
from pathlib import Path

import pytest

from core.models import (
    Finding,
    ModuleResult,
    ScanConfig,
    ScanResult,
    Severity,
    Status,
    Tactic,
)
from core.reporter import Reporter


@pytest.fixture
def scan_result() -> ScanResult:
    """Create a sample scan result for report testing."""
    start = datetime(2026, 3, 20, 10, 0, 0)
    sr = ScanResult(
        scan_id="test123",
        config=ScanConfig(),
        start_time=start,
        end_time=start + timedelta(seconds=30),
        target_info={"hostname": "rhel-test", "ID": "rhel"},
        results=[
            ModuleResult(
                technique_id="T1082",
                technique_name="System Info Discovery",
                tactic=Tactic.DISCOVERY,
                status=Status.VULNERABLE,
                findings=[
                    Finding(
                        title="Exposed system info",
                        description="System information readable",
                        severity=Severity.MEDIUM,
                        evidence="/etc/os-release readable",
                        remediation="Restrict access",
                    ),
                ],
                duration_seconds=1.5,
            ),
            ModuleResult(
                technique_id="T1087",
                technique_name="Account Discovery",
                tactic=Tactic.DISCOVERY,
                status=Status.NOT_VULNERABLE,
                duration_seconds=0.8,
            ),
            ModuleResult(
                technique_id="T1059",
                technique_name="Command Scripting",
                tactic=Tactic.EXECUTION,
                status=Status.ERROR,
                error_message="Permission denied",
                duration_seconds=0.1,
            ),
        ],
    )
    return sr


@pytest.fixture
def reporter(tmp_path: Path) -> Reporter:
    """Create a reporter writing to a temp directory."""
    return Reporter(output_dir=str(tmp_path), template_dir="templates")


class TestReporterJSON:
    def test_generates_json_file(self, reporter: Reporter, scan_result: ScanResult):
        path = reporter.generate(scan_result, fmt="json")
        assert path.exists()
        assert path.suffix == ".json"

    def test_json_is_valid(self, reporter: Reporter, scan_result: ScanResult):
        path = reporter.generate(scan_result, fmt="json")
        data = json.loads(path.read_text(encoding="utf-8"))
        assert data["scan_id"] == "test123"
        assert data["total_checks"] == 3
        assert data["vulnerable_count"] == 1

    def test_json_contains_results(self, reporter: Reporter, scan_result: ScanResult):
        path = reporter.generate(scan_result, fmt="json")
        data = json.loads(path.read_text(encoding="utf-8"))
        assert len(data["results"]) == 3
        assert data["results"][0]["technique_id"] == "T1082"


class TestReporterCSV:
    def test_generates_csv_file(self, reporter: Reporter, scan_result: ScanResult):
        path = reporter.generate(scan_result, fmt="csv")
        assert path.exists()
        assert path.suffix == ".csv"

    def test_csv_has_header_and_rows(self, reporter: Reporter, scan_result: ScanResult):
        path = reporter.generate(scan_result, fmt="csv")
        content = path.read_text(encoding="utf-8")
        reader = csv.reader(StringIO(content))
        rows = list(reader)
        assert len(rows) == 4  # header + 3 results
        assert rows[0][0] == "Technique ID"

    def test_csv_data_values(self, reporter: Reporter, scan_result: ScanResult):
        path = reporter.generate(scan_result, fmt="csv")
        content = path.read_text(encoding="utf-8")
        reader = csv.reader(StringIO(content))
        rows = list(reader)
        # First data row is T1082
        assert rows[1][0] == "T1082"
        assert rows[1][3] == "vulnerable"


class TestReporterHTML:
    def test_html_fallback_when_no_template_dir(self, scan_result: ScanResult, tmp_path: Path):
        """When template dir doesn't exist, should fall back to JSON."""
        r = Reporter(output_dir=str(tmp_path), template_dir=str(tmp_path / "nonexistent"))
        path = r.generate(scan_result, fmt="html")
        # Falls back to JSON
        assert path.suffix == ".json"

    def test_html_generation_with_template(self, scan_result: ScanResult, tmp_path: Path):
        """When template exists, should generate HTML."""
        template_dir = tmp_path / "tpl"
        template_dir.mkdir()
        (template_dir / "report.html").write_text(
            "<html>{{ summary.total }} checks, {{ summary.vulnerable }} vulnerable</html>",
            encoding="utf-8",
        )
        r = Reporter(output_dir=str(tmp_path), template_dir=str(template_dir))
        path = r.generate(scan_result, fmt="html")
        assert path.suffix == ".html"
        content = path.read_text(encoding="utf-8")
        assert "3 checks" in content
        assert "1 vulnerable" in content


class TestReporterCompliance:
    def test_json_includes_compliance_data(self, reporter: Reporter, scan_result: ScanResult):
        path = reporter.generate(scan_result, fmt="json")
        data = json.loads(path.read_text(encoding="utf-8"))
        # T1082 has compliance mappings
        t1082 = data["results"][0]
        assert "compliance" in t1082
        assert len(t1082["compliance"]) > 0

    def test_json_includes_compliance_summary(self, reporter: Reporter, scan_result: ScanResult):
        path = reporter.generate(scan_result, fmt="json")
        data = json.loads(path.read_text(encoding="utf-8"))
        assert "compliance_summary" in data

    def test_csv_includes_compliance_columns(self, reporter: Reporter, scan_result: ScanResult):
        path = reporter.generate(scan_result, fmt="csv")
        content = path.read_text(encoding="utf-8")
        reader = csv.reader(StringIO(content))
        header = next(reader)
        assert "CIS Controls" in header
        assert "NIST 800-53" in header
        assert "CIS RHEL Benchmark" in header


class TestReporterEdgeCases:
    def test_unsupported_format_raises(self, reporter: Reporter, scan_result: ScanResult):
        with pytest.raises(ValueError, match="Unsupported format"):
            reporter.generate(scan_result, fmt="xml")

    def test_empty_results(self, reporter: Reporter):
        sr = ScanResult(scan_id="empty", config=ScanConfig())
        path = reporter.generate(sr, fmt="json")
        data = json.loads(path.read_text(encoding="utf-8"))
        assert data["total_checks"] == 0
        assert data["results"] == []

    def test_output_dir_created(self, tmp_path: Path, scan_result: ScanResult):
        out = tmp_path / "nested" / "reports"
        r = Reporter(output_dir=str(out))
        path = r.generate(scan_result, fmt="json")
        assert out.exists()
        assert path.exists()

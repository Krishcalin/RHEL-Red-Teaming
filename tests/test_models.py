"""Tests for core data models."""

from __future__ import annotations

from datetime import datetime, timedelta

from core.models import (
    Finding,
    ModuleResult,
    ScanConfig,
    ScanResult,
    Severity,
    SessionType,
    Status,
    Tactic,
    Target,
)


# --- Target ---


class TestTarget:
    def test_localhost_is_local(self):
        assert Target(host="localhost").is_local is True

    def test_loopback_is_local(self):
        assert Target(host="127.0.0.1").is_local is True

    def test_ipv6_loopback_is_local(self):
        assert Target(host="::1").is_local is True

    def test_remote_host_is_not_local(self):
        assert Target(host="10.0.0.5").is_local is False

    def test_hostname_is_not_local(self):
        assert Target(host="server1.example.com").is_local is False

    def test_default_values(self):
        t = Target(host="localhost")
        assert t.port == 22
        assert t.username is None
        assert t.password is None
        assert t.key_file is None
        assert t.session_type == SessionType.LOCAL
        assert t.os_version is None
        assert t.hostname is None

    def test_ssh_target_fields(self):
        t = Target(
            host="10.0.0.5",
            port=2222,
            username="admin",
            password="secret",
            session_type=SessionType.SSH,
        )
        assert t.port == 2222
        assert t.username == "admin"
        assert t.session_type == SessionType.SSH


# --- Finding ---


class TestFinding:
    def test_basic_finding(self):
        f = Finding(title="Test", description="Desc", severity=Severity.HIGH)
        assert f.title == "Test"
        assert f.severity == Severity.HIGH
        assert f.evidence == ""
        assert f.references == []
        assert f.metadata == {}

    def test_finding_with_all_fields(self):
        f = Finding(
            title="Weak Password",
            description="Password policy too weak",
            severity=Severity.CRITICAL,
            evidence="minlen=4",
            remediation="Set minlen >= 14",
            references=["CIS 5.4.1"],
            metadata={"file": "/etc/security/pwquality.conf"},
        )
        assert f.remediation == "Set minlen >= 14"
        assert len(f.references) == 1
        assert f.metadata["file"] == "/etc/security/pwquality.conf"


# --- ModuleResult ---


class TestModuleResult:
    def _make_result(self, status=Status.VULNERABLE, findings=None):
        return ModuleResult(
            technique_id="T1082",
            technique_name="System Info Discovery",
            tactic=Tactic.DISCOVERY,
            status=status,
            findings=findings or [],
        )

    def test_is_vulnerable(self):
        assert self._make_result(Status.VULNERABLE).is_vulnerable is True

    def test_is_not_vulnerable(self):
        assert self._make_result(Status.NOT_VULNERABLE).is_vulnerable is False

    def test_finding_count_empty(self):
        assert self._make_result().finding_count == 0

    def test_finding_count(self):
        findings = [
            Finding(title="A", description="a", severity=Severity.HIGH),
            Finding(title="B", description="b", severity=Severity.LOW),
        ]
        assert self._make_result(findings=findings).finding_count == 2

    def test_max_severity_no_findings(self):
        assert self._make_result().max_severity == Severity.INFO

    def test_max_severity_critical(self):
        findings = [
            Finding(title="A", description="a", severity=Severity.LOW),
            Finding(title="B", description="b", severity=Severity.CRITICAL),
        ]
        assert self._make_result(findings=findings).max_severity == Severity.CRITICAL

    def test_max_severity_medium(self):
        findings = [
            Finding(title="A", description="a", severity=Severity.LOW),
            Finding(title="B", description="b", severity=Severity.MEDIUM),
        ]
        assert self._make_result(findings=findings).max_severity == Severity.MEDIUM

    def test_to_dict_structure(self):
        findings = [Finding(title="F1", description="d1", severity=Severity.HIGH)]
        r = self._make_result(findings=findings)
        d = r.to_dict()

        assert d["technique_id"] == "T1082"
        assert d["tactic"] == "discovery"
        assert d["status"] == "vulnerable"
        assert len(d["findings"]) == 1
        assert d["findings"][0]["title"] == "F1"
        assert d["findings"][0]["severity"] == "high"
        assert "timestamp" in d
        assert isinstance(d["mitigations"], list)

    def test_to_dict_roundtrip_types(self):
        r = self._make_result(Status.NOT_VULNERABLE)
        d = r.to_dict()
        assert isinstance(d["timestamp"], str)
        assert isinstance(d["duration_seconds"], float)


# --- ScanConfig ---


class TestScanConfig:
    def test_defaults(self):
        c = ScanConfig()
        assert c.profile == "quick"
        assert c.simulate is False
        assert c.tactics is None
        assert c.techniques is None
        assert c.timeout == 300
        assert c.parallel is False

    def test_custom_config(self):
        c = ScanConfig(
            profile="full",
            simulate=True,
            tactics=[Tactic.DISCOVERY, Tactic.EXECUTION],
            techniques=["T1082"],
            timeout=600,
        )
        assert c.simulate is True
        assert len(c.tactics) == 2
        assert c.techniques == ["T1082"]


# --- ScanResult ---


class TestScanResult:
    def _make_scan_result(self, results=None, end_time=None):
        sr = ScanResult(
            scan_id="abc123",
            config=ScanConfig(),
            results=results or [],
            start_time=datetime(2026, 3, 20, 10, 0, 0),
        )
        if end_time:
            sr.end_time = end_time
        return sr

    def test_total_checks(self):
        results = [
            ModuleResult(
                technique_id="T1082", technique_name="A",
                tactic=Tactic.DISCOVERY, status=Status.VULNERABLE,
            ),
            ModuleResult(
                technique_id="T1087", technique_name="B",
                tactic=Tactic.DISCOVERY, status=Status.NOT_VULNERABLE,
            ),
        ]
        sr = self._make_scan_result(results=results)
        assert sr.total_checks == 2

    def test_vulnerable_count(self):
        results = [
            ModuleResult(
                technique_id="T1082", technique_name="A",
                tactic=Tactic.DISCOVERY, status=Status.VULNERABLE,
            ),
            ModuleResult(
                technique_id="T1087", technique_name="B",
                tactic=Tactic.DISCOVERY, status=Status.NOT_VULNERABLE,
            ),
            ModuleResult(
                technique_id="T1069", technique_name="C",
                tactic=Tactic.DISCOVERY, status=Status.VULNERABLE,
            ),
        ]
        sr = self._make_scan_result(results=results)
        assert sr.vulnerable_count == 2

    def test_duration_no_end_time(self):
        sr = self._make_scan_result()
        assert sr.duration_seconds == 0.0

    def test_duration_with_end_time(self):
        start = datetime(2026, 3, 20, 10, 0, 0)
        end = start + timedelta(seconds=42.5)
        sr = self._make_scan_result(end_time=end)
        assert sr.duration_seconds == 42.5

    def test_to_dict_structure(self):
        sr = self._make_scan_result()
        d = sr.to_dict()
        assert d["scan_id"] == "abc123"
        assert d["end_time"] is None
        assert d["total_checks"] == 0
        assert d["vulnerable_count"] == 0
        assert isinstance(d["results"], list)

    def test_to_dict_with_end_time(self):
        end = datetime(2026, 3, 20, 10, 1, 0)
        sr = self._make_scan_result(end_time=end)
        d = sr.to_dict()
        assert d["end_time"] is not None
        assert d["duration_seconds"] == 60.0


# --- Enums ---


class TestEnums:
    def test_severity_values(self):
        assert Severity.CRITICAL.value == "critical"
        assert Severity.INFO.value == "info"

    def test_status_values(self):
        assert Status.VULNERABLE.value == "vulnerable"
        assert Status.PARTIAL.value == "partial"

    def test_tactic_count(self):
        assert len(Tactic) == 12

    def test_session_type_values(self):
        assert SessionType.LOCAL.value == "local"
        assert SessionType.SSH.value == "ssh"

    def test_severity_is_str(self):
        """Severity enum values can be used as strings."""
        assert f"Level: {Severity.HIGH}" == "Level: high"

    def test_tactic_is_str(self):
        """Tactic enum values can be used as strings."""
        assert f"Tactic: {Tactic.DISCOVERY}" == "Tactic: discovery"

"""Tests for the BaseModule abstract class."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from core.models import Finding, ModuleResult, Severity, Status, Tactic
from core.session import CommandResult, Session
from modules.base import BaseModule


class ConcreteModule(BaseModule):
    """Concrete implementation for testing the abstract base class."""

    TECHNIQUE_ID = "T9999"
    TECHNIQUE_NAME = "Test Module"
    TACTIC = Tactic.DISCOVERY
    SEVERITY = Severity.MEDIUM
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def __init__(self, check_result=None, simulate_result=None, check_raises=None):
        super().__init__()
        self._check_result = check_result
        self._simulate_result = simulate_result
        self._check_raises = check_raises
        self.cleanup_called = False

    def check(self, session):
        if self._check_raises:
            raise self._check_raises
        if self._check_result:
            return self._check_result
        return self.make_result(Status.NOT_VULNERABLE)

    def simulate(self, session):
        if self._simulate_result:
            return self._simulate_result
        self.add_finding("Sim Finding", "Test simulation", Severity.HIGH)
        return self.make_result(Status.VULNERABLE)

    def cleanup(self, session):
        self.cleanup_called = True

    def get_mitigations(self):
        return ["Apply patch", "Restrict access"]


def _mock_session():
    from core.models import SessionType, Target
    target = Target(host="localhost", session_type=SessionType.LOCAL)
    session = Session(target)
    session._connected = True
    session.execute = MagicMock(return_value=CommandResult(stdout="", stderr="", return_code=0))
    return session


class TestBaseModuleRun:
    def test_check_mode(self):
        m = ConcreteModule()
        session = _mock_session()
        result = m.run(session, simulate=False)
        assert result.status == Status.NOT_VULNERABLE
        assert result.target_host == "localhost"
        assert result.duration_seconds > 0

    def test_simulate_mode(self):
        m = ConcreteModule()
        session = _mock_session()
        result = m.run(session, simulate=True)
        assert result.status == Status.VULNERABLE
        assert result.finding_count >= 1

    def test_mitigations_attached(self):
        m = ConcreteModule()
        session = _mock_session()
        result = m.run(session)
        assert result.mitigations == ["Apply patch", "Restrict access"]

    def test_error_handling(self):
        m = ConcreteModule(check_raises=RuntimeError("boom"))
        session = _mock_session()
        result = m.run(session, simulate=False)
        assert result.status == Status.ERROR
        assert "boom" in result.error_message

    def test_findings_reset_between_runs(self):
        m = ConcreteModule()
        session = _mock_session()
        # First run in simulate mode adds findings
        r1 = m.run(session, simulate=True)
        assert r1.finding_count >= 1
        # Second run in check mode should start fresh
        r2 = m.run(session, simulate=False)
        assert r2.finding_count == 0


class TestAddFinding:
    def test_basic_finding(self):
        m = ConcreteModule()
        f = m.add_finding("Title", "Description")
        assert f.title == "Title"
        assert f.severity == Severity.MEDIUM  # default from module

    def test_custom_severity(self):
        m = ConcreteModule()
        f = m.add_finding("Title", "Desc", severity=Severity.CRITICAL)
        assert f.severity == Severity.CRITICAL

    def test_finding_with_evidence(self):
        m = ConcreteModule()
        f = m.add_finding(
            "Title", "Desc",
            evidence="ls -la output",
            remediation="chmod 600",
            references=["CIS 1.2.3"],
            metadata={"path": "/etc/shadow"},
        )
        assert f.evidence == "ls -la output"
        assert f.remediation == "chmod 600"
        assert f.references == ["CIS 1.2.3"]
        assert f.metadata["path"] == "/etc/shadow"

    def test_findings_accumulate(self):
        m = ConcreteModule()
        m.add_finding("F1", "d1")
        m.add_finding("F2", "d2")
        m.add_finding("F3", "d3")
        assert len(m._findings) == 3


class TestMakeResult:
    def test_includes_accumulated_findings(self):
        m = ConcreteModule()
        m.add_finding("F1", "d1", severity=Severity.HIGH)
        m.add_finding("F2", "d2", severity=Severity.LOW)
        result = m.make_result(Status.VULNERABLE)
        assert result.finding_count == 2
        assert result.technique_id == "T9999"
        assert result.tactic == Tactic.DISCOVERY

    def test_empty_findings(self):
        m = ConcreteModule()
        result = m.make_result(Status.NOT_VULNERABLE)
        assert result.finding_count == 0

    def test_raw_output(self):
        m = ConcreteModule()
        result = m.make_result(Status.VULNERABLE, raw_output="cmd output here")
        assert result.raw_output == "cmd output here"


class TestIsSupported:
    def test_supported_os(self):
        m = ConcreteModule()
        assert m.is_supported("rhel8") is True
        assert m.is_supported("rhel9") is True

    def test_unsupported_os(self):
        m = ConcreteModule()
        assert m.is_supported("ubuntu22") is False

    def test_case_insensitive(self):
        m = ConcreteModule()
        assert m.is_supported("RHEL8") is True
        assert m.is_supported("Rhel9") is True


class TestRepr:
    def test_repr(self):
        m = ConcreteModule()
        r = repr(m)
        assert "ConcreteModule" in r
        assert "T9999" in r
        assert "Test Module" in r

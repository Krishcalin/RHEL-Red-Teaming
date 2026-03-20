"""Tests for safety controls validation.

Validates that the tool enforces:
- Simulate flag gating
- Cleanup invocation after vulnerable simulations
- OS guard (auto-skip unsupported OS)
- Root guard (auto-skip when root required but not available)
- Check-only mode is read-only
"""

from __future__ import annotations

from unittest.mock import MagicMock, call, patch

import pytest

from core.engine import ScanEngine
from core.models import (
    ModuleResult,
    ScanConfig,
    Severity,
    SessionType,
    Status,
    Tactic,
    Target,
)
from core.session import CommandResult, Session
from modules.base import BaseModule


# --- Test Modules ---


class SafeCheckModule(BaseModule):
    TECHNIQUE_ID = "T8001"
    TECHNIQUE_NAME = "Safe Check Only"
    TACTIC = Tactic.DISCOVERY
    SEVERITY = Severity.LOW
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def __init__(self):
        super().__init__()
        self.check_called = False
        self.simulate_called = False
        self.cleanup_called = False

    def check(self, session):
        self.check_called = True
        return self.make_result(Status.NOT_VULNERABLE)

    def simulate(self, session):
        self.simulate_called = True
        self.add_finding("Sim finding", "test", Severity.HIGH)
        return self.make_result(Status.VULNERABLE)

    def cleanup(self, session):
        self.cleanup_called = True

    def get_mitigations(self):
        return []


class RootRequiredModule(BaseModule):
    TECHNIQUE_ID = "T8002"
    TECHNIQUE_NAME = "Root Required"
    TACTIC = Tactic.CREDENTIAL_ACCESS
    SEVERITY = Severity.HIGH
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = True
    SAFE_MODE = True

    def check(self, session):
        return self.make_result(Status.VULNERABLE)

    def simulate(self, session):
        return self.make_result(Status.VULNERABLE)

    def cleanup(self, session):
        pass

    def get_mitigations(self):
        return []


class UbuntuOnlyModule(BaseModule):
    TECHNIQUE_ID = "T8003"
    TECHNIQUE_NAME = "Ubuntu Only"
    TACTIC = Tactic.DISCOVERY
    SEVERITY = Severity.LOW
    SUPPORTED_OS = ["ubuntu22"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session):
        return self.make_result(Status.VULNERABLE)

    def simulate(self, session):
        return self.make_result(Status.VULNERABLE)

    def cleanup(self, session):
        pass

    def get_mitigations(self):
        return []


class CleanupFailModule(BaseModule):
    TECHNIQUE_ID = "T8004"
    TECHNIQUE_NAME = "Cleanup Fails"
    TACTIC = Tactic.EXECUTION
    SEVERITY = Severity.MEDIUM
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = False

    def check(self, session):
        return self.make_result(Status.NOT_VULNERABLE)

    def simulate(self, session):
        self.add_finding("Found issue", "desc", Severity.HIGH)
        return self.make_result(Status.VULNERABLE)

    def cleanup(self, session):
        raise RuntimeError("cleanup failed!")

    def get_mitigations(self):
        return []


# --- Helpers ---


def _mock_session(is_root: bool = True):
    target = Target(host="localhost", session_type=SessionType.LOCAL)
    session = MagicMock(spec=Session)
    session.target = target
    session.get_os_info.return_value = {
        "ID": "rhel",
        "VERSION_ID": "9.3",
        "PLATFORM_ID": "platform:el9",
        "hostname": "testhost",
        "kernel": "5.14.0",
    }
    uid = "0" if is_root else "1000"
    session.execute.return_value = CommandResult(stdout=f"{uid}\n", stderr="", return_code=0)
    session.__enter__ = MagicMock(return_value=session)
    session.__exit__ = MagicMock(return_value=False)
    return session


def _run_engine_with_modules(modules, simulate=False, is_root=True):
    config = ScanConfig(simulate=simulate)
    engine = ScanEngine(config)
    engine.modules = modules

    session = _mock_session(is_root=is_root)
    with patch.object(Session, '__new__', return_value=session):
        target = Target(host="localhost", session_type=SessionType.LOCAL)
        return engine.run(target)


# --- Simulate Flag Gating ---


class TestSimulateFlag:
    def test_check_mode_calls_check(self):
        m = SafeCheckModule()
        _run_engine_with_modules([m], simulate=False)
        assert m.check_called is True
        assert m.simulate_called is False

    def test_simulate_mode_calls_simulate(self):
        m = SafeCheckModule()
        _run_engine_with_modules([m], simulate=True)
        assert m.simulate_called is True
        assert m.check_called is False


# --- Cleanup Invocation ---


class TestCleanup:
    def test_cleanup_called_after_vulnerable_simulate(self):
        m = SafeCheckModule()
        _run_engine_with_modules([m], simulate=True)
        assert m.cleanup_called is True

    def test_cleanup_not_called_in_check_mode(self):
        m = SafeCheckModule()
        _run_engine_with_modules([m], simulate=False)
        assert m.cleanup_called is False

    def test_cleanup_failure_does_not_crash(self):
        """Engine should handle cleanup exceptions gracefully."""
        m = CleanupFailModule()
        result = _run_engine_with_modules([m], simulate=True)
        # Should not raise, and the result should still be recorded
        assert result.total_checks == 1
        assert result.results[0].status == Status.VULNERABLE


# --- OS Guard ---


class TestOSGuard:
    def test_unsupported_os_skipped(self):
        m = UbuntuOnlyModule()
        result = _run_engine_with_modules([m])
        assert result.results[0].status == Status.SKIPPED
        assert "not supported" in result.results[0].error_message

    def test_supported_os_runs(self):
        m = SafeCheckModule()
        result = _run_engine_with_modules([m])
        assert result.results[0].status != Status.SKIPPED


# --- Root Guard ---


class TestRootGuard:
    def test_root_required_skipped_without_root(self):
        m = RootRequiredModule()
        result = _run_engine_with_modules([m], is_root=False)
        assert result.results[0].status == Status.SKIPPED
        assert "root" in result.results[0].error_message.lower()

    def test_root_required_runs_with_root(self):
        m = RootRequiredModule()
        result = _run_engine_with_modules([m], is_root=True)
        assert result.results[0].status != Status.SKIPPED


# --- BaseModule Safety ---


class TestBaseModuleSafety:
    def test_run_catches_exceptions(self):
        """BaseModule.run() should catch exceptions and return ERROR status."""

        class CrashingModule(BaseModule):
            TECHNIQUE_ID = "T8005"
            TECHNIQUE_NAME = "Crasher"
            TACTIC = Tactic.DISCOVERY
            SEVERITY = Severity.LOW
            SUPPORTED_OS = ["rhel8", "rhel9"]
            REQUIRES_ROOT = False
            SAFE_MODE = True

            def check(self, session):
                raise ValueError("unexpected error")

            def simulate(self, session):
                raise ValueError("unexpected error")

            def cleanup(self, session):
                pass

            def get_mitigations(self):
                return []

        m = CrashingModule()
        session = _mock_session()
        result = m.run(session, simulate=False)
        assert result.status == Status.ERROR
        assert "unexpected error" in result.error_message

    def test_findings_isolated_between_runs(self):
        """Each run() should start with a clean findings list."""
        m = SafeCheckModule()
        session = _mock_session()

        # First run: simulate adds a finding
        r1 = m.run(session, simulate=True)
        assert r1.finding_count >= 1

        # Second run: check should have no findings
        r2 = m.run(session, simulate=False)
        assert r2.finding_count == 0

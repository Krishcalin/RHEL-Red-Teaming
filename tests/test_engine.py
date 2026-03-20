"""Tests for the core scan engine."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from core.engine import ScanEngine
from core.models import (
    ModuleResult,
    ScanConfig,
    Severity,
    Status,
    Tactic,
    SessionType,
    Target,
)
from core.session import CommandResult, Session
from modules.base import BaseModule


# --- Helpers ---


class StubModule(BaseModule):
    """Minimal concrete module for engine testing."""

    TECHNIQUE_ID = "T0001"
    TECHNIQUE_NAME = "Stub Check"
    TACTIC = Tactic.DISCOVERY
    SEVERITY = Severity.LOW
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def __init__(self, **overrides):
        for k, v in overrides.items():
            setattr(self.__class__, k, v)
        super().__init__()
        self.cleanup_called = False

    def check(self, session):
        return self.make_result(Status.NOT_VULNERABLE)

    def simulate(self, session):
        self.add_finding("Sim", "simulated", Severity.HIGH)
        return self.make_result(Status.VULNERABLE)

    def cleanup(self, session):
        self.cleanup_called = True

    def get_mitigations(self):
        return ["Fix it"]


class FailingModule(BaseModule):
    """Module that raises during check."""

    TECHNIQUE_ID = "T0002"
    TECHNIQUE_NAME = "Failing Check"
    TACTIC = Tactic.EXECUTION
    SEVERITY = Severity.MEDIUM
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session):
        raise RuntimeError("check exploded")

    def simulate(self, session):
        raise RuntimeError("simulate exploded")

    def cleanup(self, session):
        pass

    def get_mitigations(self):
        return []


def _mock_session_for_engine():
    """Create a mock session that engine.run() can use."""
    target = Target(host="localhost", session_type=SessionType.LOCAL)
    session = MagicMock(spec=Session)
    session.target = target
    session.get_os_info.return_value = {
        "ID": "rhel",
        "VERSION_ID": "9.3",
        "PLATFORM_ID": "platform:el9",
        "PRETTY_NAME": "Red Hat Enterprise Linux 9.3",
        "hostname": "testhost",
        "kernel": "5.14.0-362.el9",
        "arch": "x86_64",
    }
    session.execute.return_value = CommandResult(stdout="0\n", stderr="", return_code=0)
    session.__enter__ = MagicMock(return_value=session)
    session.__exit__ = MagicMock(return_value=False)
    return session


# --- Init & Discovery ---


def test_engine_init():
    """Engine should initialize with a module list."""
    config = ScanConfig()
    engine = ScanEngine(config)
    assert isinstance(engine.modules, list)


def test_engine_discovers_modules():
    """Engine should discover at least some modules from the modules/ dir."""
    config = ScanConfig()
    engine = ScanEngine(config)
    assert len(engine.modules) > 0


# --- Filtering ---


def test_engine_filter_by_tactic():
    """Engine should filter modules by tactic."""
    config = ScanConfig(tactics=[Tactic.DISCOVERY])
    engine = ScanEngine(config)
    filtered = engine._filter_modules()
    assert len(filtered) > 0
    for m in filtered:
        assert m.TACTIC == Tactic.DISCOVERY


def test_engine_filter_by_technique():
    """Engine should filter modules by technique ID."""
    config = ScanConfig(techniques=["T1082"])
    engine = ScanEngine(config)
    filtered = engine._filter_modules()
    assert len(filtered) > 0
    for m in filtered:
        assert m.TECHNIQUE_ID == "T1082"


def test_engine_filter_by_tactic_and_technique():
    """Combined tactic + technique filter."""
    config = ScanConfig(tactics=[Tactic.DISCOVERY], techniques=["T1082"])
    engine = ScanEngine(config)
    filtered = engine._filter_modules()
    for m in filtered:
        assert m.TACTIC == Tactic.DISCOVERY
        assert m.TECHNIQUE_ID == "T1082"


def test_engine_filter_nonexistent_technique():
    """Filtering by a technique that doesn't exist should return empty."""
    config = ScanConfig(techniques=["T9999"])
    engine = ScanEngine(config)
    filtered = engine._filter_modules()
    assert len(filtered) == 0


def test_engine_no_filter_returns_all():
    """No filter should return all modules."""
    config = ScanConfig()
    engine = ScanEngine(config)
    all_modules = engine._filter_modules()
    assert len(all_modules) == len(engine.modules)


# --- OS Detection ---


class TestOSDetection:
    def _engine(self):
        return ScanEngine(ScanConfig())

    def test_detect_rhel9(self):
        e = self._engine()
        assert e._detect_os_id({"ID": "rhel", "VERSION_ID": "9.3"}) == "rhel9"

    def test_detect_rhel8(self):
        e = self._engine()
        assert e._detect_os_id({"ID": "rhel", "VERSION_ID": "8.9"}) == "rhel8"

    def test_detect_redhat_platform_id(self):
        e = self._engine()
        result = e._detect_os_id({
            "ID": "centos",
            "VERSION_ID": "9",
            "PLATFORM_ID": "platform:Red Hat el9",
        })
        assert result == "rhel9"

    def test_detect_unknown_os(self):
        e = self._engine()
        result = e._detect_os_id({"ID": "ubuntu", "VERSION_ID": "22.04"})
        assert result == "ubuntu22.04"

    def test_detect_empty_info(self):
        e = self._engine()
        result = e._detect_os_id({})
        assert result == ""


# --- Root Check ---


class TestRootCheck:
    def test_has_root(self):
        e = ScanEngine(ScanConfig())
        session = MagicMock()
        session.execute.return_value = CommandResult(stdout="0\n", stderr="", return_code=0)
        assert e._has_root(session) is True

    def test_not_root(self):
        e = ScanEngine(ScanConfig())
        session = MagicMock()
        session.execute.return_value = CommandResult(stdout="1000\n", stderr="", return_code=0)
        assert e._has_root(session) is False


# --- Run with Mocked Modules ---


class TestEngineRun:
    def test_run_returns_scan_result(self):
        config = ScanConfig(techniques=["T1082"])
        engine = ScanEngine(config)
        session = _mock_session_for_engine()

        with patch.object(Session, '__new__', return_value=session):
            target = Target(host="localhost", session_type=SessionType.LOCAL)
            result = engine.run(target)

        assert result.scan_id is not None
        assert result.end_time is not None
        assert result.total_checks > 0

    def test_run_skips_unsupported_os(self):
        """Modules not supporting detected OS should be skipped."""
        config = ScanConfig()
        engine = ScanEngine(config)
        # Replace all modules with one that only supports a fake OS
        unsupported = StubModule(SUPPORTED_OS=["fakeos99"])
        unsupported.TECHNIQUE_ID = "T0001"
        engine.modules = [unsupported]

        session = _mock_session_for_engine()
        with patch.object(Session, '__new__', return_value=session):
            target = Target(host="localhost", session_type=SessionType.LOCAL)
            result = engine.run(target)

        assert result.total_checks == 1
        assert result.results[0].status == Status.SKIPPED
        assert "not supported" in result.results[0].error_message

    def test_run_skips_root_required_without_root(self):
        """Modules requiring root should be skipped when not root."""
        config = ScanConfig()
        engine = ScanEngine(config)
        root_module = StubModule(REQUIRES_ROOT=True)
        root_module.TECHNIQUE_ID = "T0001"
        engine.modules = [root_module]

        session = _mock_session_for_engine()
        # Not root
        session.execute.return_value = CommandResult(stdout="1000\n", stderr="", return_code=0)

        with patch.object(Session, '__new__', return_value=session):
            target = Target(host="localhost", session_type=SessionType.LOCAL)
            result = engine.run(target)

        assert result.results[0].status == Status.SKIPPED
        assert "root" in result.results[0].error_message.lower()

    def test_run_empty_filter_returns_early(self):
        """Engine should return early when no modules match filter."""
        config = ScanConfig(techniques=["T9999"])
        engine = ScanEngine(config)
        target = Target(host="localhost", session_type=SessionType.LOCAL)
        result = engine.run(target)
        assert result.total_checks == 0

"""Tests for session management."""

from __future__ import annotations

from core.models import SessionType, Target
from core.session import CommandResult


def test_target_is_local():
    """Localhost targets should be detected as local."""
    t = Target(host="localhost")
    assert t.is_local is True

    t2 = Target(host="127.0.0.1")
    assert t2.is_local is True


def test_target_is_remote():
    """Non-localhost targets should not be local."""
    t = Target(host="192.168.1.20", session_type=SessionType.SSH)
    assert t.is_local is False


def test_command_result_success():
    """CommandResult with return_code 0 should report success."""
    r = CommandResult(stdout="ok\n", stderr="", return_code=0)
    assert r.success is True
    assert r.output == "ok"


def test_command_result_failure():
    """CommandResult with non-zero return_code should report failure."""
    r = CommandResult(stdout="", stderr="error", return_code=1)
    assert r.success is False

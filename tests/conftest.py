"""Shared test fixtures for RHEL Red Teaming tests."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from core.models import SessionType, Target
from core.session import CommandResult, Session


@pytest.fixture
def local_target() -> Target:
    """Create a localhost target for testing."""
    return Target(host="localhost", session_type=SessionType.LOCAL)


@pytest.fixture
def ssh_target() -> Target:
    """Create an SSH target for testing."""
    return Target(
        host="192.168.1.20",
        port=22,
        username="testuser",
        password="testpass",
        session_type=SessionType.SSH,
    )


@pytest.fixture
def mock_session(local_target: Target) -> Session:
    """Create a mock session that returns configurable command results."""
    session = Session(local_target)
    session._connected = True
    session.execute = MagicMock(return_value=CommandResult(stdout="", stderr="", return_code=0))
    return session


def make_command_result(stdout: str = "", stderr: str = "", return_code: int = 0) -> CommandResult:
    """Helper to create CommandResult instances in tests."""
    return CommandResult(stdout=stdout, stderr=stderr, return_code=return_code)

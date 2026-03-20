"""Tests for session management."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from core.models import SessionType, Target
from core.session import CommandResult, Session


# --- CommandResult ---


class TestCommandResult:
    def test_success(self):
        r = CommandResult(stdout="ok\n", stderr="", return_code=0)
        assert r.success is True

    def test_failure(self):
        r = CommandResult(stdout="", stderr="error", return_code=1)
        assert r.success is False

    def test_output_strips_whitespace(self):
        r = CommandResult(stdout="  hello world  \n", stderr="", return_code=0)
        assert r.output == "hello world"

    def test_output_empty(self):
        r = CommandResult(stdout="", stderr="", return_code=0)
        assert r.output == ""

    def test_negative_return_code(self):
        r = CommandResult(stdout="", stderr="timeout", return_code=-1)
        assert r.success is False


# --- Target ---


class TestTarget:
    def test_localhost_is_local(self):
        assert Target(host="localhost").is_local is True

    def test_loopback_is_local(self):
        assert Target(host="127.0.0.1").is_local is True

    def test_remote_is_not_local(self):
        assert Target(host="192.168.1.20", session_type=SessionType.SSH).is_local is False


# --- Session Connect/Disconnect ---


class TestSessionConnect:
    def test_local_connect(self):
        t = Target(host="localhost", session_type=SessionType.LOCAL)
        s = Session(t)
        s.connect()
        assert s._connected is True
        s.disconnect()
        assert s._connected is False

    def test_local_context_manager(self):
        t = Target(host="localhost", session_type=SessionType.LOCAL)
        with Session(t) as s:
            assert s._connected is True
        assert s._connected is False

    @patch("core.session.paramiko.SSHClient")
    def test_ssh_connect(self, mock_ssh_cls):
        mock_client = MagicMock()
        mock_ssh_cls.return_value = mock_client

        t = Target(
            host="10.0.0.5",
            port=22,
            username="admin",
            password="pass",
            session_type=SessionType.SSH,
        )
        s = Session(t)
        s.connect()
        assert s._connected is True
        mock_client.connect.assert_called_once()

    @patch("core.session.paramiko.SSHClient")
    def test_ssh_connect_with_key_file(self, mock_ssh_cls):
        mock_client = MagicMock()
        mock_ssh_cls.return_value = mock_client

        t = Target(
            host="10.0.0.5",
            username="admin",
            key_file="/home/admin/.ssh/id_rsa",
            session_type=SessionType.SSH,
        )
        s = Session(t)
        s.connect()
        call_kwargs = mock_client.connect.call_args[1]
        assert call_kwargs["key_filename"] == "/home/admin/.ssh/id_rsa"

    @patch("core.session.paramiko.SSHClient")
    def test_ssh_disconnect(self, mock_ssh_cls):
        mock_client = MagicMock()
        mock_ssh_cls.return_value = mock_client

        t = Target(host="10.0.0.5", username="u", password="p", session_type=SessionType.SSH)
        s = Session(t)
        s.connect()
        s.disconnect()
        assert s._connected is False
        mock_client.close.assert_called_once()


# --- Session Execute ---


class TestSessionExecute:
    def test_execute_not_connected_raises(self):
        t = Target(host="localhost", session_type=SessionType.LOCAL)
        s = Session(t)
        with pytest.raises(RuntimeError, match="not connected"):
            s.execute("echo hello")

    def test_execute_sudo_wraps_command(self):
        t = Target(host="localhost", session_type=SessionType.LOCAL)
        s = Session(t)
        s._connected = True

        with patch.object(s, "_execute_local") as mock_exec:
            mock_exec.return_value = CommandResult("", "", 0)
            s.execute("whoami", sudo=True)
            mock_exec.assert_called_once_with("sudo -n whoami", 60)

    @patch("core.session.subprocess.run")
    def test_local_execute(self, mock_run):
        mock_run.return_value = MagicMock(
            stdout="hello\n", stderr="", returncode=0,
        )
        t = Target(host="localhost", session_type=SessionType.LOCAL)
        s = Session(t)
        s._connected = True
        result = s.execute("echo hello")
        assert result.success is True
        assert result.output == "hello"

    @patch("core.session.subprocess.run")
    def test_local_execute_timeout(self, mock_run):
        import subprocess
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="sleep 999", timeout=5)

        t = Target(host="localhost", session_type=SessionType.LOCAL)
        s = Session(t)
        s._connected = True
        result = s.execute("sleep 999", timeout=5)
        assert result.success is False
        assert "timed out" in result.stderr.lower()

    @patch("core.session.subprocess.run")
    def test_local_execute_exception(self, mock_run):
        mock_run.side_effect = OSError("Permission denied")

        t = Target(host="localhost", session_type=SessionType.LOCAL)
        s = Session(t)
        s._connected = True
        result = s.execute("restricted_cmd")
        assert result.success is False
        assert "Permission denied" in result.stderr


# --- Session File Operations ---


class TestSessionFileOps:
    def test_read_file_success(self):
        t = Target(host="localhost", session_type=SessionType.LOCAL)
        s = Session(t)
        s._connected = True
        s.execute = MagicMock(return_value=CommandResult("file content\n", "", 0))
        assert s.read_file("/etc/hostname") == "file content\n"

    def test_read_file_not_found(self):
        t = Target(host="localhost", session_type=SessionType.LOCAL)
        s = Session(t)
        s._connected = True
        s.execute = MagicMock(return_value=CommandResult("", "No such file", 1))
        assert s.read_file("/nonexistent") is None

    def test_file_exists_true(self):
        t = Target(host="localhost", session_type=SessionType.LOCAL)
        s = Session(t)
        s._connected = True
        s.execute = MagicMock(return_value=CommandResult("exists\n", "", 0))
        assert s.file_exists("/etc/passwd") is True

    def test_file_exists_false(self):
        t = Target(host="localhost", session_type=SessionType.LOCAL)
        s = Session(t)
        s._connected = True
        s.execute = MagicMock(return_value=CommandResult("", "", 1))
        assert s.file_exists("/nonexistent") is False

    def test_dir_exists_true(self):
        t = Target(host="localhost", session_type=SessionType.LOCAL)
        s = Session(t)
        s._connected = True
        s.execute = MagicMock(return_value=CommandResult("exists\n", "", 0))
        assert s.dir_exists("/etc") is True

    def test_dir_exists_false(self):
        t = Target(host="localhost", session_type=SessionType.LOCAL)
        s = Session(t)
        s._connected = True
        s.execute = MagicMock(return_value=CommandResult("", "", 1))
        assert s.dir_exists("/nope") is False


# --- Session OS Info ---


class TestSessionOSInfo:
    def test_get_os_info(self):
        t = Target(host="localhost", session_type=SessionType.LOCAL)
        s = Session(t)
        s._connected = True

        def mock_execute(cmd, timeout=60, sudo=False):
            if "os-release" in cmd:
                return CommandResult(
                    'NAME="Red Hat Enterprise Linux"\nVERSION_ID="9.3"\nID=rhel\n',
                    "", 0,
                )
            if "uname -r" in cmd:
                return CommandResult("5.14.0-362.el9.x86_64\n", "", 0)
            if cmd == "hostname":
                return CommandResult("testhost\n", "", 0)
            if "uname -m" in cmd:
                return CommandResult("x86_64\n", "", 0)
            return CommandResult("", "", 1)

        s.execute = MagicMock(side_effect=mock_execute)
        info = s.get_os_info()
        assert info["ID"] == "rhel"
        assert info["VERSION_ID"] == "9.3"
        assert info["kernel"] == "5.14.0-362.el9.x86_64"
        assert info["hostname"] == "testhost"
        assert info["arch"] == "x86_64"

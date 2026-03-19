"""Target session management for RHEL Red Teaming tool."""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path

import paramiko
import structlog

from core.models import SessionType, Target

log = structlog.get_logger("session")


@dataclass
class CommandResult:
    """Result from executing a command on a target."""

    stdout: str
    stderr: str
    return_code: int

    @property
    def success(self) -> bool:
        return self.return_code == 0

    @property
    def output(self) -> str:
        return self.stdout.strip()


class Session:
    """Manages connections to scan targets (local or SSH)."""

    def __init__(self, target: Target):
        self.target = target
        self._ssh_client: paramiko.SSHClient | None = None
        self._connected = False

    def connect(self) -> None:
        """Establish connection to the target."""
        if self.target.is_local:
            self._connected = True
            log.info("session_connected", target=self.target.host, type="local")
            return

        self._ssh_client = paramiko.SSHClient()
        self._ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        connect_kwargs: dict = {
            "hostname": self.target.host,
            "port": self.target.port,
            "username": self.target.username,
        }

        if self.target.key_file:
            connect_kwargs["key_filename"] = self.target.key_file
        elif self.target.password:
            connect_kwargs["password"] = self.target.password

        self._ssh_client.connect(**connect_kwargs)
        self._connected = True

        log.info(
            "session_connected",
            target=self.target.host,
            type="ssh",
            user=self.target.username,
        )

    def disconnect(self) -> None:
        """Close the connection."""
        if self._ssh_client:
            self._ssh_client.close()
            self._ssh_client = None
        self._connected = False
        log.info("session_disconnected", target=self.target.host)

    def execute(self, command: str, timeout: int = 60, sudo: bool = False) -> CommandResult:
        """Execute a command on the target."""
        if not self._connected:
            raise RuntimeError("Session not connected. Call connect() first.")

        if sudo:
            command = f"sudo -n {command}"

        if self.target.is_local:
            return self._execute_local(command, timeout)
        return self._execute_ssh(command, timeout)

    def _execute_local(self, command: str, timeout: int) -> CommandResult:
        """Execute command locally via subprocess."""
        log.debug("execute_local", command=command)
        try:
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            return CommandResult(
                stdout=result.stdout,
                stderr=result.stderr,
                return_code=result.returncode,
            )
        except subprocess.TimeoutExpired:
            log.warning("command_timeout", command=command, timeout=timeout)
            return CommandResult(stdout="", stderr="Command timed out", return_code=-1)
        except Exception as e:
            log.error("command_failed", command=command, error=str(e))
            return CommandResult(stdout="", stderr=str(e), return_code=-1)

    def _execute_ssh(self, command: str, timeout: int) -> CommandResult:
        """Execute command via SSH."""
        if not self._ssh_client:
            raise RuntimeError("SSH client not initialized")

        log.debug("execute_ssh", target=self.target.host, command=command)
        try:
            stdin, stdout, stderr = self._ssh_client.exec_command(command, timeout=timeout)
            return CommandResult(
                stdout=stdout.read().decode("utf-8", errors="replace"),
                stderr=stderr.read().decode("utf-8", errors="replace"),
                return_code=stdout.channel.recv_exit_status(),
            )
        except Exception as e:
            log.error("ssh_command_failed", target=self.target.host, command=command, error=str(e))
            return CommandResult(stdout="", stderr=str(e), return_code=-1)

    def read_file(self, path: str) -> str | None:
        """Read a file from the target."""
        result = self.execute(f"cat {path}")
        if result.success:
            return result.stdout
        return None

    def file_exists(self, path: str) -> bool:
        """Check if a file exists on the target."""
        result = self.execute(f"test -f {path} && echo exists")
        return result.output == "exists"

    def dir_exists(self, path: str) -> bool:
        """Check if a directory exists on the target."""
        result = self.execute(f"test -d {path} && echo exists")
        return result.output == "exists"

    def get_os_info(self) -> dict[str, str]:
        """Gather OS information from the target."""
        info: dict[str, str] = {}

        result = self.execute("cat /etc/os-release")
        if result.success:
            for line in result.stdout.splitlines():
                if "=" in line:
                    key, _, value = line.partition("=")
                    info[key.strip()] = value.strip().strip('"')

        result = self.execute("uname -r")
        if result.success:
            info["kernel"] = result.output

        result = self.execute("hostname")
        if result.success:
            info["hostname"] = result.output

        result = self.execute("uname -m")
        if result.success:
            info["arch"] = result.output

        return info

    def __enter__(self) -> Session:
        self.connect()
        return self

    def __exit__(self, *args: object) -> None:
        self.disconnect()

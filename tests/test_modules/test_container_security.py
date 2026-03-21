"""Tests for container security modules."""

from __future__ import annotations

import importlib
from unittest.mock import MagicMock

from core.models import Severity, Status, Tactic, SessionType, Target
from core.session import CommandResult, Session


def make_session(responses: dict[str, CommandResult] | None = None) -> Session:
    target = Target(host="localhost", session_type=SessionType.LOCAL)
    session = Session(target)
    session._connected = True
    default = CommandResult(stdout="", stderr="", return_code=1)
    resp = responses or {}

    def mock_execute(command: str, timeout: int = 60, sudo: bool = False) -> CommandResult:
        for pattern, result in resp.items():
            if pattern in command:
                return result
        return default

    session.execute = MagicMock(side_effect=mock_execute)
    return session


# ---------------------------------------------------------------------------
# CS001 — Runtime Configuration
# ---------------------------------------------------------------------------


class TestRuntimeConfigCheck:
    def test_attributes(self):
        from modules.container_security.CS001_runtime_config import RuntimeConfigCheck
        m = RuntimeConfigCheck()
        assert m.TECHNIQUE_ID == "CS001"
        assert m.SAFE_MODE is True

    def test_docker_installed(self):
        from modules.container_security.CS001_runtime_config import RuntimeConfigCheck
        session = make_session({
            "which podman": CommandResult("", "", 1),
            "which docker": CommandResult("/usr/bin/docker\n", "", 0),
            "podman ps": CommandResult("", "", 1),
            "docker ps": CommandResult("", "", 1),
            "cat /etc/subuid": CommandResult("", "", 1),
            "systemctl is-active docker": CommandResult("active\n", "", 0),
            "ls -la /var/run/docker.sock": CommandResult("srw-rw---- 1 root docker /var/run/docker.sock\n", "", 0),
            "cat /etc/containers/registries.conf": CommandResult("", "", 1),
        })
        m = RuntimeConfigCheck()
        result = m.check(session)
        assert result.status == Status.VULNERABLE
        assert any("Docker" in f.title for f in result.findings)

    def test_clean(self):
        from modules.container_security.CS001_runtime_config import RuntimeConfigCheck
        m = RuntimeConfigCheck()
        result = m.check(make_session({}))
        assert result.status == Status.NOT_VULNERABLE


# ---------------------------------------------------------------------------
# CS002 — Image Security
# ---------------------------------------------------------------------------


class TestImageSecurityCheck:
    def test_attributes(self):
        from modules.container_security.CS002_image_security import ImageSecurityCheck
        m = ImageSecurityCheck()
        assert m.TECHNIQUE_ID == "CS002"

    def test_unsigned_policy(self):
        from modules.container_security.CS002_image_security import ImageSecurityCheck
        session = make_session({
            "cat /etc/containers/policy.json": CommandResult('{"default": [{"type": "insecureAcceptAnything"}]}\n', "", 0),
            "which trivy": CommandResult("", "", 1),
            "which grype": CommandResult("", "", 1),
            "which clair": CommandResult("", "", 1),
            "which skopeo": CommandResult("", "", 1),
            "which podman": CommandResult("/usr/bin/podman\n", "", 0),
            "podman images": CommandResult("", "", 1),
        })
        m = ImageSecurityCheck()
        result = m.check(session)
        assert result.status == Status.VULNERABLE
        assert any("unsigned" in f.title.lower() for f in result.findings)


# ---------------------------------------------------------------------------
# CS003 — Privilege Escalation
# ---------------------------------------------------------------------------


class TestContainerPrivescCheck:
    def test_attributes(self):
        from modules.container_security.CS003_privilege_escalation import ContainerPrivescCheck
        m = ContainerPrivescCheck()
        assert m.TECHNIQUE_ID == "CS003"
        assert m.SEVERITY == Severity.CRITICAL

    def test_privileged_container(self):
        from modules.container_security.CS003_privilege_escalation import ContainerPrivescCheck
        session = make_session({
            "podman inspect --format '{{.Name}} {{.HostConfig.Privileged}}'": CommandResult("/web true\n", "", 0),
            "podman inspect --format '{{.Name}} {{.HostConfig.CapAdd}}'": CommandResult("/web []\n", "", 0),
            "podman inspect --format '{{.Name}} {{.HostConfig.NetworkMode}}'": CommandResult("/web bridge\n", "", 0),
            "podman inspect --format '{{.Name}} {{.HostConfig.PidMode}}'": CommandResult("/web \n", "", 0),
            "podman inspect --format '{{.Name}} {{.HostConfig.IpcMode}}'": CommandResult("/web \n", "", 0),
            "podman inspect --format '{{.Name}} {{range .Mounts}}": CommandResult("/web \n", "", 0),
        })
        m = ContainerPrivescCheck()
        result = m.check(session)
        assert result.status == Status.VULNERABLE
        assert any("Privileged" in f.title for f in result.findings)


# ---------------------------------------------------------------------------
# CS004 — Network Security
# ---------------------------------------------------------------------------


class TestContainerNetworkCheck:
    def test_attributes(self):
        from modules.container_security.CS004_network_security import ContainerNetworkCheck
        m = ContainerNetworkCheck()
        assert m.TECHNIQUE_ID == "CS004"

    def test_exposed_ports(self):
        from modules.container_security.CS004_network_security import ContainerNetworkCheck
        session = make_session({
            "podman ps --format": CommandResult("web 0.0.0.0:8080->80/tcp\n", "", 0),
            "podman inspect --format '{{.Name}} {{.HostConfig.NetworkMode}}'": CommandResult("/web bridge\n", "", 0),
            "cat /etc/docker/daemon.json": CommandResult("", "", 1),
        })
        m = ContainerNetworkCheck()
        result = m.check(session)
        assert result.status == Status.VULNERABLE


# ---------------------------------------------------------------------------
# CS005 — Seccomp and SELinux
# ---------------------------------------------------------------------------


class TestSeccompSelinuxCheck:
    def test_attributes(self):
        from modules.container_security.CS005_seccomp_apparmor import SeccompSelinuxCheck
        m = SeccompSelinuxCheck()
        assert m.TECHNIQUE_ID == "CS005"


# ---------------------------------------------------------------------------
# CS006 — Resource Limits
# ---------------------------------------------------------------------------


class TestResourceLimitsCheck:
    def test_attributes(self):
        from modules.container_security.CS006_resource_limits import ResourceLimitsCheck
        m = ResourceLimitsCheck()
        assert m.TECHNIQUE_ID == "CS006"

    def test_no_memory_limit(self):
        from modules.container_security.CS006_resource_limits import ResourceLimitsCheck
        session = make_session({
            "podman inspect --format '{{.Name}} {{.HostConfig.Memory}}'": CommandResult("/web 0\n", "", 0),
            "podman inspect --format '{{.Name}} {{.HostConfig.NanoCpus}}'": CommandResult("/web 0\n", "", 0),
            "podman inspect --format '{{.Name}} {{.HostConfig.PidsLimit}}'": CommandResult("/web 0\n", "", 0),
        })
        m = ResourceLimitsCheck()
        result = m.check(session)
        assert result.status == Status.VULNERABLE


# ---------------------------------------------------------------------------
# CS007 — Secrets Management
# ---------------------------------------------------------------------------


class TestSecretsManagementCheck:
    def test_attributes(self):
        from modules.container_security.CS007_secrets_management import SecretsManagementCheck
        m = SecretsManagementCheck()
        assert m.TECHNIQUE_ID == "CS007"

    def test_env_secret(self):
        from modules.container_security.CS007_secrets_management import SecretsManagementCheck
        session = make_session({
            "podman inspect --format '{{.Name}} {{range .Config.Env}}": CommandResult(
                "/web MYSQL_ROOT_PASSWORD=secret123 PATH=/usr/bin\n", "", 0
            ),
            "podman history": CommandResult("", "", 1),
            "podman inspect --format '{{.Name}} {{range .Mounts}}{{.Source}}": CommandResult("/web \n", "", 0),
        })
        m = SecretsManagementCheck()
        result = m.check(session)
        assert result.status == Status.VULNERABLE
        assert any("Secret" in f.title or "secret" in f.title.lower() for f in result.findings)


# ---------------------------------------------------------------------------
# CS008–CS010: Attribute tests
# ---------------------------------------------------------------------------


class TestFilesystemSecurityCheck:
    def test_attributes(self):
        from modules.container_security.CS008_filesystem_security import FilesystemSecurityCheck
        m = FilesystemSecurityCheck()
        assert m.TECHNIQUE_ID == "CS008"


class TestLoggingMonitoringCheck:
    def test_attributes(self):
        from modules.container_security.CS009_logging_monitoring import LoggingMonitoringCheck
        m = LoggingMonitoringCheck()
        assert m.TECHNIQUE_ID == "CS009"


class TestContainerSupplyChainCheck:
    def test_attributes(self):
        from modules.container_security.CS010_supply_chain import ContainerSupplyChainCheck
        m = ContainerSupplyChainCheck()
        assert m.TECHNIQUE_ID == "CS010"

    def test_stale_images(self):
        from modules.container_security.CS010_supply_chain import ContainerSupplyChainCheck
        session = make_session({
            "podman images --format": CommandResult(
                "myapp:v1 6 months ago\nbase:latest 2 years ago\n", "", 0
            ),
            "which cosign": CommandResult("", "", 1),
            "which sigstore": CommandResult("", "", 1),
            "which podman": CommandResult("/usr/bin/podman\n", "", 0),
            "find /opt /srv /home": CommandResult("", "", 1),
        })
        m = ContainerSupplyChainCheck()
        result = m.check(session)
        assert result.status == Status.VULNERABLE


# ---------------------------------------------------------------------------
# Cross-module validation
# ---------------------------------------------------------------------------


class TestContainerSecurityCommon:
    MODULE_CLASSES = [
        ("modules.container_security.CS001_runtime_config", "RuntimeConfigCheck"),
        ("modules.container_security.CS002_image_security", "ImageSecurityCheck"),
        ("modules.container_security.CS003_privilege_escalation", "ContainerPrivescCheck"),
        ("modules.container_security.CS004_network_security", "ContainerNetworkCheck"),
        ("modules.container_security.CS005_seccomp_apparmor", "SeccompSelinuxCheck"),
        ("modules.container_security.CS006_resource_limits", "ResourceLimitsCheck"),
        ("modules.container_security.CS007_secrets_management", "SecretsManagementCheck"),
        ("modules.container_security.CS008_filesystem_security", "FilesystemSecurityCheck"),
        ("modules.container_security.CS009_logging_monitoring", "LoggingMonitoringCheck"),
        ("modules.container_security.CS010_supply_chain", "ContainerSupplyChainCheck"),
    ]

    def test_all_safe_mode(self):
        for mod_path, cls_name in self.MODULE_CLASSES:
            mod = importlib.import_module(mod_path)
            cls = getattr(mod, cls_name)
            assert cls().SAFE_MODE is True, f"{cls_name} not safe"

    def test_all_have_mitigations(self):
        for mod_path, cls_name in self.MODULE_CLASSES:
            mod = importlib.import_module(mod_path)
            cls = getattr(mod, cls_name)
            assert len(cls().get_mitigations()) > 0, f"{cls_name} no mitigations"

    def test_all_have_technique_ids(self):
        for mod_path, cls_name in self.MODULE_CLASSES:
            mod = importlib.import_module(mod_path)
            cls = getattr(mod, cls_name)
            assert cls().TECHNIQUE_ID.startswith("CS"), f"{cls_name} ID should start with CS"

    def test_simulate_delegates(self):
        for mod_path, cls_name in self.MODULE_CLASSES:
            mod = importlib.import_module(mod_path)
            cls = getattr(mod, cls_name)
            session = make_session({})
            assert cls().check(session).status == cls().simulate(session).status

    def test_clean_system_not_vulnerable(self):
        """No containers running = no findings."""
        for mod_path, cls_name in self.MODULE_CLASSES:
            mod = importlib.import_module(mod_path)
            cls = getattr(mod, cls_name)
            result = cls().check(make_session({}))
            assert result.status == Status.NOT_VULNERABLE, f"{cls_name} found issues on empty system"

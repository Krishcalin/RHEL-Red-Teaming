"""Tests for discovery modules."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from core.models import Severity, Status, Tactic, SessionType, Target
from core.session import CommandResult, Session


def make_session(responses: dict[str, CommandResult] | None = None) -> Session:
    """Create a mock session with configurable command responses."""
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


class TestSystemInfoCheck:
    def test_module_attributes(self):
        from modules.discovery.T1082_system_info import SystemInfoCheck
        m = SystemInfoCheck()
        assert m.TECHNIQUE_ID == "T1082"
        assert m.TACTIC == Tactic.DISCOVERY
        assert m.SAFE_MODE is True
        assert m.REQUIRES_ROOT is False

    def test_check_finds_exposed_info(self):
        from modules.discovery.T1082_system_info import SystemInfoCheck
        session = make_session({
            "uname -a": CommandResult("Linux rhel9 5.14.0 x86_64", "", 0),
            "cat /etc/os-release": CommandResult("NAME=Red Hat\nVERSION=9.3", "", 0),
            "cat /proc/cpuinfo": CommandResult("model name: Intel", "", 0),
            "cat /proc/meminfo": CommandResult("MemTotal: 8192 kB", "", 0),
            "df -h": CommandResult("/dev/sda1 50G 20G 30G", "", 0),
            "lscpu": CommandResult("Architecture: x86_64", "", 0),
            "hostnamectl": CommandResult("Static hostname: rhel9", "", 0),
            "dmesg": CommandResult("kernel log\n0", "", 0),
            "mount": CommandResult("", "", 1),
        })
        m = SystemInfoCheck()
        result = m.check(session)
        assert result.technique_id == "T1082"
        assert result.finding_count > 0


class TestAccountDiscovery:
    def test_module_attributes(self):
        from modules.discovery.T1087_account_discovery import AccountDiscoveryCheck
        m = AccountDiscoveryCheck()
        assert m.TECHNIQUE_ID == "T1087"
        assert m.TACTIC == Tactic.DISCOVERY

    def test_detects_uid0_accounts(self):
        from modules.discovery.T1087_account_discovery import AccountDiscoveryCheck
        passwd = "root:x:0:0::/root:/bin/bash\nhacker:x:0:0::/tmp:/bin/bash\nnobody:x:65534:65534::/:/sbin/nologin"
        session = make_session({
            "cat /etc/passwd": CommandResult(passwd, "", 0),
            "getent passwd": CommandResult("3", "", 0),
            "systemctl is-active sssd": CommandResult("inactive", "", 0),
            "last": CommandResult("", "", 1),
        })
        m = AccountDiscoveryCheck()
        result = m.check(session)
        critical = [f for f in result.findings if f.severity == Severity.CRITICAL]
        assert len(critical) >= 1
        assert "UID 0" in critical[0].title


class TestPermissionGroups:
    def test_module_attributes(self):
        from modules.discovery.T1069_permission_groups import PermissionGroupsCheck
        m = PermissionGroupsCheck()
        assert m.TECHNIQUE_ID == "T1069"

    def test_detects_privileged_groups(self):
        from modules.discovery.T1069_permission_groups import PermissionGroupsCheck
        groups = "root:x:0:\nwheel:x:10:admin,bob\ndocker:x:991:testuser"
        session = make_session({
            "cat /etc/group": CommandResult(groups, "", 0),
            "id": CommandResult("uid=1000(testuser) gid=1000(testuser) groups=1000(testuser),991(docker)", "", 0),
            "getent group": CommandResult("3", "", 0),
        })
        m = PermissionGroupsCheck()
        result = m.check(session)
        assert result.finding_count >= 2


class TestNetworkServiceDiscovery:
    def test_module_attributes(self):
        from modules.discovery.T1046_network_service_discovery import NetworkServiceDiscoveryCheck
        m = NetworkServiceDiscoveryCheck()
        assert m.TECHNIQUE_ID == "T1046"

    def test_detects_no_firewall(self):
        from modules.discovery.T1046_network_service_discovery import NetworkServiceDiscoveryCheck
        session = make_session({
            "ss -tulnp": CommandResult("Netid State\ntcp LISTEN 0.0.0.0:22", "", 0),
            "ss -tlnp": CommandResult("", "", 1),
            "which nmap": CommandResult("", "", 1),
            "firewall-cmd --state": CommandResult("not running", "", 1),
        })
        m = NetworkServiceDiscoveryCheck()
        result = m.check(session)
        firewall_findings = [f for f in result.findings if "firewall" in f.title.lower() or "Firewall" in f.title]
        assert len(firewall_findings) >= 1


class TestFileDiscovery:
    def test_module_attributes(self):
        from modules.discovery.T1083_file_discovery import FileDiscoveryCheck
        m = FileDiscoveryCheck()
        assert m.TECHNIQUE_ID == "T1083"
        assert m.SAFE_MODE is True


class TestProcessDiscovery:
    def test_module_attributes(self):
        from modules.discovery.T1057_process_discovery import ProcessDiscoveryCheck
        m = ProcessDiscoveryCheck()
        assert m.TECHNIQUE_ID == "T1057"

    def test_detects_cred_in_cmdline(self):
        from modules.discovery.T1057_process_discovery import ProcessDiscoveryCheck
        session = make_session({
            "ps aux": CommandResult("USER PID\nroot 1 /sbin/init\nmysql 100 mysqld", "", 0),
            "grep -iE": CommandResult("mysql 100 mysqld --password=secret123", "", 0),
            "ls /proc": CommandResult("", "", 1),
        })
        m = ProcessDiscoveryCheck()
        result = m.check(session)
        cred_findings = [f for f in result.findings if "credential" in f.title.lower()]
        assert len(cred_findings) >= 1


class TestPasswordPolicy:
    def test_module_attributes(self):
        from modules.discovery.T1201_password_policy import PasswordPolicyCheck
        m = PasswordPolicyCheck()
        assert m.TECHNIQUE_ID == "T1201"

    def test_detects_weak_minlen(self):
        from modules.discovery.T1201_password_policy import PasswordPolicyCheck
        session = make_session({
            "cat /etc/security/pwquality.conf": CommandResult("minlen = 6\ndcredit = -1", "", 0),
            "grep -E": CommandResult("PASS_MAX_DAYS 99999\nPASS_MIN_DAYS 0", "", 0),
            "grep -r faillock": CommandResult("", "", 1),
            "awk": CommandResult("", "", 1),
        })
        m = PasswordPolicyCheck()
        result = m.check(session)
        weak = [f for f in result.findings if "Weak" in f.title or "minimum" in f.title.lower()]
        assert len(weak) >= 1


class TestNetworkConnections:
    def test_module_attributes(self):
        from modules.discovery.T1049_network_connections import NetworkConnectionsCheck
        m = NetworkConnectionsCheck()
        assert m.TECHNIQUE_ID == "T1049"


class TestNetworkConfig:
    def test_module_attributes(self):
        from modules.discovery.T1016_network_config import NetworkConfigCheck
        m = NetworkConfigCheck()
        assert m.TECHNIQUE_ID == "T1016"


class TestSoftwareDiscovery:
    def test_module_attributes(self):
        from modules.discovery.T1518_software_discovery import SoftwareDiscoveryCheck
        m = SoftwareDiscoveryCheck()
        assert m.TECHNIQUE_ID == "T1518"


class TestServiceDiscovery:
    def test_module_attributes(self):
        from modules.discovery.T1007_service_discovery import ServiceDiscoveryCheck
        m = ServiceDiscoveryCheck()
        assert m.TECHNIQUE_ID == "T1007"


class TestOwnerDiscovery:
    def test_module_attributes(self):
        from modules.discovery.T1033_owner_discovery import OwnerDiscoveryCheck
        m = OwnerDiscoveryCheck()
        assert m.TECHNIQUE_ID == "T1033"


class TestRemoteSystemDiscovery:
    def test_module_attributes(self):
        from modules.discovery.T1018_remote_system_discovery import RemoteSystemDiscoveryCheck
        m = RemoteSystemDiscoveryCheck()
        assert m.TECHNIQUE_ID == "T1018"


class TestNetworkShare:
    def test_module_attributes(self):
        from modules.discovery.T1135_network_share import NetworkShareCheck
        m = NetworkShareCheck()
        assert m.TECHNIQUE_ID == "T1135"


class TestTimeDiscovery:
    def test_module_attributes(self):
        from modules.discovery.T1124_time_discovery import TimeDiscoveryCheck
        m = TimeDiscoveryCheck()
        assert m.TECHNIQUE_ID == "T1124"


class TestPeripheralDiscovery:
    def test_module_attributes(self):
        from modules.discovery.T1120_peripheral_discovery import PeripheralDiscoveryCheck
        m = PeripheralDiscoveryCheck()
        assert m.TECHNIQUE_ID == "T1120"


class TestWindowDiscovery:
    def test_module_attributes(self):
        from modules.discovery.T1010_window_discovery import WindowDiscoveryCheck
        m = WindowDiscoveryCheck()
        assert m.TECHNIQUE_ID == "T1010"


class TestBrowserDiscovery:
    def test_module_attributes(self):
        from modules.discovery.T1217_browser_discovery import BrowserDiscoveryCheck
        m = BrowserDiscoveryCheck()
        assert m.TECHNIQUE_ID == "T1217"


class TestDriverDiscovery:
    def test_module_attributes(self):
        from modules.discovery.T1652_driver_discovery import DriverDiscoveryCheck
        m = DriverDiscoveryCheck()
        assert m.TECHNIQUE_ID == "T1652"


class TestLogEnumeration:
    def test_module_attributes(self):
        from modules.discovery.T1654_log_enumeration import LogEnumerationCheck
        m = LogEnumerationCheck()
        assert m.TECHNIQUE_ID == "T1654"


class TestLocalStorage:
    def test_module_attributes(self):
        from modules.discovery.T1680_local_storage import LocalStorageCheck
        m = LocalStorageCheck()
        assert m.TECHNIQUE_ID == "T1680"


class TestLanguageDiscovery:
    def test_module_attributes(self):
        from modules.discovery.T1614_language_discovery import LanguageDiscoveryCheck
        m = LanguageDiscoveryCheck()
        assert m.TECHNIQUE_ID == "T1614"


class TestVMDiscovery:
    def test_module_attributes(self):
        from modules.discovery.T1673_vm_discovery import VMDiscoveryCheck
        m = VMDiscoveryCheck()
        assert m.TECHNIQUE_ID == "T1673"


class TestDebuggerEvasion:
    def test_module_attributes(self):
        from modules.discovery.T1622_debugger_evasion import DebuggerEvasionCheck
        m = DebuggerEvasionCheck()
        assert m.TECHNIQUE_ID == "T1622"


class TestNetworkSniffing:
    def test_module_attributes(self):
        from modules.discovery.T1040_network_sniffing import NetworkSniffingCheck
        m = NetworkSniffingCheck()
        assert m.TECHNIQUE_ID == "T1040"


class TestSandboxEvasion:
    def test_module_attributes(self):
        from modules.discovery.T1497_sandbox_evasion import SandboxEvasionCheck
        m = SandboxEvasionCheck()
        assert m.TECHNIQUE_ID == "T1497"

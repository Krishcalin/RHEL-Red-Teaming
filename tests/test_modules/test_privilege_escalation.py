"""Tests for privilege escalation modules."""

from __future__ import annotations

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


class TestElevationControl:
    def test_module_attributes(self):
        from modules.privilege_escalation.T1548_elevation_control import ElevationControlCheck
        m = ElevationControlCheck()
        assert m.TECHNIQUE_ID == "T1548"
        assert m.TACTIC == Tactic.PRIVILEGE_ESCALATION
        assert m.SAFE_MODE is True

    def test_detects_exploitable_suid(self):
        from modules.privilege_escalation.T1548_elevation_control import ElevationControlCheck
        session = make_session({
            "find / -perm -4000": CommandResult("/usr/bin/passwd\n/usr/bin/find\n/usr/bin/python3", "", 0),
            "find / -perm -2000": CommandResult("", "", 1),
            "grep -r 'NOPASSWD'": CommandResult("", "", 1),
            "grep -r '\\*'": CommandResult("", "", 1),
            "sudo -l": CommandResult("", "", 1),
            "grep -r 'timestamp_timeout'": CommandResult("", "", 1),
            "grep -r 'env_keep'": CommandResult("", "", 1),
            "find /etc/sudoers.d": CommandResult("", "", 1),
            "sudo -ln": CommandResult("", "", 1),
        })
        m = ElevationControlCheck()
        result = m.check(session)
        critical = [f for f in result.findings if f.severity == Severity.CRITICAL]
        assert len(critical) >= 1
        assert any("GTFOBins" in f.title for f in critical)

    def test_detects_nopasswd(self):
        from modules.privilege_escalation.T1548_elevation_control import ElevationControlCheck
        session = make_session({
            "find / -perm -4000": CommandResult("/usr/bin/passwd", "", 0),
            "find / -perm -2000": CommandResult("", "", 1),
            "grep -r 'NOPASSWD'": CommandResult("admin ALL=(ALL) NOPASSWD: ALL", "", 0),
            "grep -r '\\*'": CommandResult("", "", 1),
            "sudo -l": CommandResult("", "", 1),
            "grep -r 'timestamp_timeout'": CommandResult("", "", 1),
            "grep -r 'env_keep'": CommandResult("", "", 1),
            "find /etc/sudoers.d": CommandResult("", "", 1),
            "sudo -ln": CommandResult("", "", 1),
        })
        m = ElevationControlCheck()
        result = m.check(session)
        nopasswd = [f for f in result.findings if "NOPASSWD" in f.title]
        assert len(nopasswd) >= 1


class TestExploitPrivEsc:
    def test_module_attributes(self):
        from modules.privilege_escalation.T1068_exploitation_privesc import ExploitPrivEscCheck
        m = ExploitPrivEscCheck()
        assert m.TECHNIQUE_ID == "T1068"
        assert m.SEVERITY == Severity.CRITICAL

    def test_detects_weak_aslr(self):
        from modules.privilege_escalation.T1068_exploitation_privesc import ExploitPrivEscCheck
        session = make_session({
            "uname -r": CommandResult("5.14.0-362.el9.x86_64", "", 0),
            "dnf check-update kernel": CommandResult("", "", 0),
            "yum check-update kernel": CommandResult("", "", 0),
            "needs-restarting": CommandResult("", "", 0),
            "cat /proc/sys/kernel/randomize_va_space": CommandResult("0", "", 0),
            "sysctl -n": CommandResult("0", "", 0),
            "which gcc": CommandResult("", "", 1),
            "which make": CommandResult("", "", 1),
            "mokutil": CommandResult("", "", 1),
        })
        m = ExploitPrivEscCheck()
        result = m.check(session)
        aslr = [f for f in result.findings if "ASLR" in f.title]
        assert len(aslr) >= 1


class TestProcessInjection:
    def test_module_attributes(self):
        from modules.privilege_escalation.T1055_process_injection import ProcessInjectionCheck
        m = ProcessInjectionCheck()
        assert m.TECHNIQUE_ID == "T1055"


class TestHijackExecution:
    def test_module_attributes(self):
        from modules.privilege_escalation.T1574_hijack_execution import HijackExecutionCheck
        m = HijackExecutionCheck()
        assert m.TECHNIQUE_ID == "T1574"

    def test_detects_ld_preload(self):
        from modules.privilege_escalation.T1574_hijack_execution import HijackExecutionCheck
        session = make_session({
            "cat /etc/ld.so.preload": CommandResult("/tmp/evil.so", "", 0),
            "test -w /etc/ld.so.preload": CommandResult("", "", 1),
            "echo $LD_PRELOAD": CommandResult("", "", 0),
            "echo $LD_LIBRARY_PATH": CommandResult("", "", 0),
            "ldconfig -p": CommandResult("", "", 1),
            "find /usr/bin": CommandResult("", "", 1),
            "echo $PATH": CommandResult("/usr/bin:/usr/sbin", "", 0),
        })
        m = HijackExecutionCheck()
        result = m.check(session)
        preload = [f for f in result.findings if "ld.so.preload" in f.title.lower()]
        assert len(preload) >= 1


class TestEscapeToHost:
    def test_module_attributes(self):
        from modules.privilege_escalation.T1611_escape_to_host import EscapeToHostCheck
        m = EscapeToHostCheck()
        assert m.TECHNIQUE_ID == "T1611"
        assert m.SEVERITY == Severity.CRITICAL


class TestBootAutostart:
    def test_module_attributes(self):
        from modules.privilege_escalation.T1547_boot_autostart import BootAutostartCheck
        m = BootAutostartCheck()
        assert m.TECHNIQUE_ID == "T1547"


class TestEventTriggered:
    def test_module_attributes(self):
        from modules.privilege_escalation.T1546_event_triggered import EventTriggeredCheck
        m = EventTriggeredCheck()
        assert m.TECHNIQUE_ID == "T1546"


class TestSystemdService:
    def test_module_attributes(self):
        from modules.privilege_escalation.T1543_systemd_service import SystemdServiceCheck
        m = SystemdServiceCheck()
        assert m.TECHNIQUE_ID == "T1543"


class TestInitScripts:
    def test_module_attributes(self):
        from modules.privilege_escalation.T1037_init_scripts import InitScriptsCheck
        m = InitScriptsCheck()
        assert m.TECHNIQUE_ID == "T1037"


class TestScheduledTasks:
    def test_module_attributes(self):
        from modules.privilege_escalation.T1053_scheduled_tasks import ScheduledTasksCheck
        m = ScheduledTasksCheck()
        assert m.TECHNIQUE_ID == "T1053"


class TestAccountManipulation:
    def test_module_attributes(self):
        from modules.privilege_escalation.T1098_account_manipulation import AccountManipulationCheck
        m = AccountManipulationCheck()
        assert m.TECHNIQUE_ID == "T1098"

    def test_detects_writable_passwd(self):
        from modules.privilege_escalation.T1098_account_manipulation import AccountManipulationCheck
        session = make_session({
            "test -r /root/.ssh/authorized_keys": CommandResult("", "", 1),
            "find /home /root -name 'authorized_keys'": CommandResult("", "", 1),
            "grep -i 'AuthorizedKeysFile'": CommandResult("", "", 1),
            "which usermod": CommandResult("", "", 1),
            "which groupadd": CommandResult("", "", 1),
            "test -w /etc/group": CommandResult("", "", 1),
            "test -w /etc/passwd": CommandResult("writable", "", 0),
        })
        m = AccountManipulationCheck()
        result = m.check(session)
        critical = [f for f in result.findings if f.severity == Severity.CRITICAL]
        assert len(critical) >= 1


class TestValidAccounts:
    def test_module_attributes(self):
        from modules.privilege_escalation.T1078_valid_accounts import ValidAccountsCheck
        m = ValidAccountsCheck()
        assert m.TECHNIQUE_ID == "T1078"

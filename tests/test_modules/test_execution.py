"""Tests for execution modules."""

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


# ---------------------------------------------------------------------------
# T1059 — Command and Scripting Interpreter
# ---------------------------------------------------------------------------

class TestCommandScriptingCheck:
    def test_module_attributes(self):
        from modules.execution.T1059_command_scripting import CommandScriptingCheck
        m = CommandScriptingCheck()
        assert m.TECHNIQUE_ID == "T1059"
        assert m.TACTIC == Tactic.EXECUTION
        assert m.SAFE_MODE is True

    def test_check_finds_vulnerabilities(self):
        from modules.execution.T1059_command_scripting import CommandScriptingCheck
        session = make_session({
            "cat /etc/shells": CommandResult(
                "/bin/sh\n/bin/bash\n/bin/zsh\n/usr/bin/tmux", "", 0
            ),
            "which rbash": CommandResult("", "", 1),
            "echo $HISTCONTROL": CommandResult("ignoreboth", "", 0),
            "grep -r 'HISTFILE'": CommandResult("", "", 1),
            "grep -r 'readonly HISTFILE": CommandResult("", "", 1),
            "which python3": CommandResult("/usr/bin/python3", "", 0),
            "stat -c": CommandResult("0755 root", "", 0),
            "which node": CommandResult("/usr/bin/node", "", 0),
            "which perl": CommandResult("/usr/bin/perl", "", 0),
            "which lua": CommandResult("/usr/bin/lua", "", 0),
            "getenforce": CommandResult("Permissive", "", 0),
        })
        m = CommandScriptingCheck()
        result = m.check(session)
        assert result.status == Status.VULNERABLE
        assert result.finding_count >= 4
        # Verify specific findings
        titles = [f.title for f in result.findings]
        assert any("Unrestricted shells" in t for t in titles)
        assert any("rbash" in t for t in titles)
        assert any("HISTCONTROL" in t for t in titles)
        assert any("SELinux" in t for t in titles)


# ---------------------------------------------------------------------------
# T1053 — Scheduled Task/Job
# ---------------------------------------------------------------------------

class TestScheduledTaskCheck:
    def test_module_attributes(self):
        from modules.execution.T1053_scheduled_tasks import ScheduledTaskCheck
        m = ScheduledTaskCheck()
        assert m.TECHNIQUE_ID == "T1053"
        assert m.TACTIC == Tactic.EXECUTION
        assert m.SAFE_MODE is True

    def test_check_finds_vulnerabilities(self):
        from modules.execution.T1053_scheduled_tasks import ScheduledTaskCheck
        session = make_session({
            "systemctl is-active atd": CommandResult("active", "", 0),
            "cat /etc/at.allow": CommandResult("", "", 1),
            "cat /etc/at.deny": CommandResult("", "", 0),
            "atq": CommandResult("1\tMon Mar 20 10:00:00 2026 a root", "", 0),
            "cat /etc/cron.allow": CommandResult("", "", 1),
            "cat /etc/cron.deny": CommandResult("", "", 0),
            "ls -la /var/spool/cron/": CommandResult(
                "total 4\n-rw------- 1 root root 50 Mar 20 10:00 root", "", 0
            ),
            "find /etc/cron.d": CommandResult("/etc/cron.d/backdoor.sh", "", 0),
            "stat -c": CommandResult("644 root:root", "", 0),
            "systemctl list-timers": CommandResult(
                "NEXT  LEFT  LAST  PASSED  UNIT  ACTIVATES\n"
                "Mon   1h    Sun   23h     backup.timer  backup.service", "", 0
            ),
            "find /etc/systemd/system/": CommandResult(
                "/etc/systemd/system/myjob.timer", "", 0
            ),
            "for t in": CommandResult("backup.timer", "", 0),
        })
        m = ScheduledTaskCheck()
        result = m.check(session)
        assert result.status == Status.VULNERABLE
        assert result.finding_count >= 4
        titles = [f.title for f in result.findings]
        assert any("atd" in t for t in titles)
        assert any("at.deny" in t.lower() or "at.allow" in t.lower() or "at" in t.lower() for t in titles)
        assert any("cron" in t.lower() for t in titles)


# ---------------------------------------------------------------------------
# T1106 — Native API
# ---------------------------------------------------------------------------

class TestNativeAPICheck:
    def test_module_attributes(self):
        from modules.execution.T1106_native_api import NativeAPICheck
        m = NativeAPICheck()
        assert m.TECHNIQUE_ID == "T1106"
        assert m.TACTIC == Tactic.EXECUTION
        assert m.SAFE_MODE is True

    def test_check_finds_vulnerabilities(self):
        from modules.execution.T1106_native_api import NativeAPICheck
        session = make_session({
            "sysctl -n kernel.yama.ptrace_scope": CommandResult("0", "", 0),
            "sysctl -n kernel.unprivileged_bpf_disabled": CommandResult("0", "", 0),
            "sysctl -n kernel.kptr_restrict": CommandResult("0", "", 0),
            "sysctl -n kernel.dmesg_restrict": CommandResult("0", "", 0),
            "grep -c CONFIG_SECCOMP": CommandResult("0", "", 0),
            "grep -l Seccomp": CommandResult("", "", 1),
            "ls /proc/sys/kernel/yama/": CommandResult("", "", 1),
        })
        m = NativeAPICheck()
        result = m.check(session)
        assert result.status == Status.VULNERABLE
        assert result.finding_count >= 4
        titles = [f.title for f in result.findings]
        assert any("ptrace" in t for t in titles)
        assert any("eBPF" in t for t in titles)
        assert any("kptr" in t.lower() or "Kernel pointer" in t for t in titles)
        assert any("dmesg" in t for t in titles)


# ---------------------------------------------------------------------------
# T1129 — Shared Modules
# ---------------------------------------------------------------------------

class TestSharedModulesCheck:
    def test_module_attributes(self):
        from modules.execution.T1129_shared_modules import SharedModulesCheck
        m = SharedModulesCheck()
        assert m.TECHNIQUE_ID == "T1129"
        assert m.TACTIC == Tactic.EXECUTION
        assert m.SAFE_MODE is True

    def test_check_finds_vulnerabilities(self):
        from modules.execution.T1129_shared_modules import SharedModulesCheck
        session = make_session({
            "echo ${LD_PRELOAD:-}": CommandResult("/tmp/evil.so", "", 0),
            "grep -r 'LD_PRELOAD'": CommandResult(
                "/etc/profile.d/custom.sh:export LD_PRELOAD=/tmp/evil.so", "", 0
            ),
            "cat /etc/ld.so.preload": CommandResult("/usr/lib64/libhax.so", "", 0),
            "stat -c '%a %U:%G' /etc/ld.so.preload": CommandResult("666 root:root", "", 0),
            "echo ${LD_LIBRARY_PATH:-}": CommandResult("/opt/custom/lib", "", 0),
            "grep -r 'LD_LIBRARY_PATH'": CommandResult(
                "/etc/profile.d/paths.sh:export LD_LIBRARY_PATH=/opt/custom/lib", "", 0
            ),
            "ldconfig -v": CommandResult("/usr/lib64:\n/tmp/libs:", "", 0),
            "test -w": CommandResult("writable", "", 0),
            "find /usr/lib64": CommandResult("/usr/lib64/libevil.so", "", 0),
            "find /usr/lib": CommandResult("", "", 1),
            "find /lib64": CommandResult("", "", 1),
            "find /lib": CommandResult("", "", 1),
            "ls -la /etc/ld.so.conf.d/": CommandResult(
                "total 4\n-rw-r--r-- 1 root root 20 custom.conf", "", 0
            ),
            "find /etc/ld.so.conf.d/": CommandResult(
                "/etc/ld.so.conf.d/custom.conf", "", 0
            ),
            "cat /etc/ld.so.conf.d/": CommandResult("/home/user/mylibs", "", 0),
        })
        m = SharedModulesCheck()
        result = m.check(session)
        assert result.status == Status.VULNERABLE
        assert result.finding_count >= 4
        titles = [f.title for f in result.findings]
        assert any("LD_PRELOAD" in t for t in titles)
        assert any("ld.so.preload" in t for t in titles)


# ---------------------------------------------------------------------------
# T1072 — Software Deployment Tools
# ---------------------------------------------------------------------------

class TestSoftwareDeploymentCheck:
    def test_module_attributes(self):
        from modules.execution.T1072_software_deployment import SoftwareDeploymentCheck
        m = SoftwareDeploymentCheck()
        assert m.TECHNIQUE_ID == "T1072"
        assert m.TACTIC == Tactic.EXECUTION
        assert m.SAFE_MODE is True

    def test_check_finds_vulnerabilities(self):
        from modules.execution.T1072_software_deployment import SoftwareDeploymentCheck
        session = make_session({
            "which ansible": CommandResult("/usr/bin/ansible", "", 0),
            "stat -c '%a %U:%G' /etc/ansible/ansible.cfg": CommandResult(
                "644 root:root", "", 0
            ),
            "stat -c '%a %U:%G' /etc/ansible/hosts": CommandResult(
                "644 root:root", "", 0
            ),
            "which puppet": CommandResult("/usr/bin/puppet", "", 0),
            "systemctl is-active puppet": CommandResult("active", "", 0),
            "which chef-client": CommandResult("", "", 1),
            "which salt-minion": CommandResult("", "", 1),
            "find /root/.ssh": CommandResult(
                "/root/.ssh/authorized_keys", "", 0
            ),
            "cat '/root/.ssh/authorized_keys'": CommandResult(
                "ssh-rsa AAAA... admin@server", "", 0
            ),
            "grep -rl 'gpgcheck=0'": CommandResult(
                "/etc/yum.repos.d/local.repo", "", 0
            ),
            "grep -i 'gpgcheck'": CommandResult("gpgcheck=0", "", 0),
            "find /etc/puppet": CommandResult(
                "/etc/puppet/puppet.conf", "", 0
            ),
            "find /etc/chef": CommandResult("", "", 1),
            "find /etc/salt": CommandResult("", "", 1),
            "find /etc/ansible": CommandResult(
                "/etc/ansible/ansible.cfg", "", 0
            ),
            "grep -rhi": CommandResult(
                "0 3 * * * /opt/scripts/deploy.sh", "", 0
            ),
        })
        m = SoftwareDeploymentCheck()
        result = m.check(session)
        assert result.status == Status.VULNERABLE
        assert result.finding_count >= 4
        titles = [f.title for f in result.findings]
        assert any("Ansible" in t for t in titles)
        assert any("GPG" in t or "gpg" in t for t in titles)


# ---------------------------------------------------------------------------
# T1569 — System Services
# ---------------------------------------------------------------------------

class TestSystemServicesCheck:
    def test_module_attributes(self):
        from modules.execution.T1569_system_services import SystemServicesCheck
        m = SystemServicesCheck()
        assert m.TECHNIQUE_ID == "T1569"
        assert m.TACTIC == Tactic.EXECUTION
        assert m.SAFE_MODE is True

    def test_check_finds_vulnerabilities(self):
        from modules.execution.T1569_system_services import SystemServicesCheck
        session = make_session({
            "pkaction": CommandResult(
                "implicit any: yes\nimplicit active: yes", "", 0
            ),
            "ls -la $(which systemctl": CommandResult(
                "-rwxr-xr-x 1 root root 900000 /usr/bin/systemctl", "", 0
            ),
            # Services running as root
            "systemctl list-units --type=service --state=running": CommandResult(
                "httpd.service loaded active running\n"
                "sshd.service loaded active running", "", 0
            ),
            "systemctl show -p MainPID": CommandResult(
                "MainPID=1234\nUser=root", "", 0
            ),
            "systemctl show httpd": CommandResult(
                "NoNewPrivileges=no\nProtectSystem=no\n"
                "ProtectHome=no\nPrivateTmp=no\nPrivateDevices=no", "", 0
            ),
            "systemctl show sshd": CommandResult(
                "NoNewPrivileges=no\nProtectSystem=no\n"
                "ProtectHome=no\nPrivateTmp=no\nPrivateDevices=no", "", 0
            ),
            "find /etc/systemd/system": CommandResult(
                "/etc/systemd/system/backdoor.service", "", 0
            ),
            "find /usr/lib/systemd/system": CommandResult("", "", 1),
            "find /usr/local/lib/systemd/system": CommandResult("", "", 1),
        })
        m = SystemServicesCheck()
        result = m.check(session)
        assert result.status == Status.VULNERABLE
        assert result.finding_count >= 3
        titles = [f.title for f in result.findings]
        assert any("Polkit" in t or "polkit" in t for t in titles)
        assert any("root" in t.lower() for t in titles)


# ---------------------------------------------------------------------------
# T1204 — User Execution
# ---------------------------------------------------------------------------

class TestUserExecutionCheck:
    def test_module_attributes(self):
        from modules.execution.T1204_user_execution import UserExecutionCheck
        m = UserExecutionCheck()
        assert m.TECHNIQUE_ID == "T1204"
        assert m.TACTIC == Tactic.EXECUTION
        assert m.SAFE_MODE is True

    def test_check_finds_vulnerabilities(self):
        from modules.execution.T1204_user_execution import UserExecutionCheck
        session = make_session({
            "mount": CommandResult(
                "tmpfs on /tmp type tmpfs (rw,nosuid,nodev)\n"
                "tmpfs on /dev/shm type tmpfs (rw,nosuid,nodev)", "", 0
            ),
            "find /tmp /var/tmp /dev/shm -type f -executable": CommandResult(
                "/tmp/payload.elf\n/var/tmp/miner", "", 0
            ),
            "which wget": CommandResult("/usr/bin/wget", "", 0),
            "which curl": CommandResult("/usr/bin/curl", "", 0),
            "which chmod": CommandResult("/usr/bin/chmod", "", 0),
            "find /usr/share/applications": CommandResult(
                "/usr/share/applications/evil.desktop", "", 0
            ),
            "grep '^Exec='": CommandResult(
                "Exec=bash -c '/tmp/payload.sh'", "", 0
            ),
            "which xdg-open": CommandResult("/usr/bin/xdg-open", "", 0),
            "xdg-mime query default": CommandResult("org.gnome.Terminal.desktop", "", 0),
        })
        m = UserExecutionCheck()
        result = m.check(session)
        assert result.status == Status.VULNERABLE
        assert result.finding_count >= 3
        titles = [f.title for f in result.findings]
        assert any("noexec" in t.lower() for t in titles)
        assert any("Executable files" in t or "executable" in t.lower() for t in titles)
        assert any("Download" in t or "download" in t for t in titles)


# ---------------------------------------------------------------------------
# T1203 — Exploitation for Client Execution
# ---------------------------------------------------------------------------

class TestClientExecutionCheck:
    def test_module_attributes(self):
        from modules.execution.T1203_client_execution import ClientExecutionCheck
        m = ClientExecutionCheck()
        assert m.TECHNIQUE_ID == "T1203"
        assert m.TACTIC == Tactic.EXECUTION
        assert m.SAFE_MODE is True

    def test_check_finds_vulnerabilities(self):
        from modules.execution.T1203_client_execution import ClientExecutionCheck
        session = make_session({
            "sysctl -n kernel.randomize_va_space": CommandResult("0", "", 0),
            "grep -o ' nx '": CommandResult("", "", 1),
            "dmesg": CommandResult("NX not supported", "", 0),
            "grep -m1 'flags'": CommandResult(
                "flags: fpu vme de pse tsc msr pae mce", "", 0
            ),
            "which readelf": CommandResult("/usr/bin/readelf", "", 0),
            "readelf -s": CommandResult("unprotected", "", 0),
            "readelf -l": CommandResult("", "", 1),
            "readelf -d": CommandResult("", "", 1),
            "readelf -h": CommandResult("Type: EXEC (Executable file)", "", 0),
            "rpm -qa --last": CommandResult(
                "httpd-2.4.37-47.el8.x86_64  Mon 20 Mar 2026", "", 0
            ),
            "yum updateinfo": CommandResult("15", "", 0),
            "dnf updateinfo": CommandResult("15", "", 0),
        })
        m = ClientExecutionCheck()
        result = m.check(session)
        assert result.status == Status.VULNERABLE
        assert result.finding_count >= 3
        titles = [f.title for f in result.findings]
        assert any("ASLR" in t for t in titles)
        assert any("security update" in t.lower() or "Security update" in t for t in titles)


# ---------------------------------------------------------------------------
# T1674 — Input Injection
# ---------------------------------------------------------------------------

class TestInputInjectionCheck:
    def test_module_attributes(self):
        from modules.execution.T1674_input_injection import InputInjectionCheck
        m = InputInjectionCheck()
        assert m.TECHNIQUE_ID == "T1674"
        assert m.TACTIC == Tactic.EXECUTION
        assert m.SAFE_MODE is True

    def test_check_finds_vulnerabilities(self):
        from modules.execution.T1674_input_injection import InputInjectionCheck
        session = make_session({
            "grep -i '^\\s*X11Forwarding'": CommandResult(
                "X11Forwarding yes", "", 0
            ),
            "grep -i '^\\s*X11UseLocalhost'": CommandResult(
                "X11UseLocalhost no", "", 0
            ),
            "which xdotool": CommandResult("/usr/bin/xdotool", "", 0),
            "which xte": CommandResult("", "", 1),
            "which xdo": CommandResult("", "", 1),
            "which xmodmap": CommandResult("", "", 1),
            "which xinput": CommandResult("", "", 1),
            "find /home /root -name '.Xauthority'": CommandResult(
                "/home/user/.Xauthority", "", 0
            ),
            "stat -c '%a %U %G'": CommandResult("644 user user", "", 0),
            "echo $XDG_SESSION_TYPE": CommandResult("x11", "", 0),
            "ls -la /dev/input/": CommandResult(
                "crw-rw-r-- 1 root input 13, 64 event0\n"
                "crw-rw-r-- 1 root input 13, 65 event1", "", 0
            ),
        })
        m = InputInjectionCheck()
        result = m.check(session)
        assert result.status == Status.VULNERABLE
        assert result.finding_count >= 3
        titles = [f.title for f in result.findings]
        assert any("X11 forwarding" in t for t in titles)
        assert any("X11UseLocalhost" in t for t in titles)
        assert any("Input device" in t or "input" in t.lower() for t in titles)


# ---------------------------------------------------------------------------
# T1559 — Inter-Process Communication
# ---------------------------------------------------------------------------

class TestIPCCheck:
    def test_module_attributes(self):
        from modules.execution.T1559_ipc import IPCCheck
        m = IPCCheck()
        assert m.TECHNIQUE_ID == "T1559"
        assert m.TACTIC == Tactic.EXECUTION
        assert m.SAFE_MODE is True

    def test_check_finds_vulnerabilities(self):
        from modules.execution.T1559_ipc import IPCCheck
        session = make_session({
            "ls /etc/dbus-1/system.d/": CommandResult(
                "org.freedesktop.PolicyKit1.conf\ncustom-service.conf", "", 0
            ),
            "grep -l 'allow.*send_destination": CommandResult(
                "/etc/dbus-1/system.d/custom-service.conf", "", 0
            ),
            "grep -n '<allow'": CommandResult(
                "5:  <allow send_destination=\"com.example.Service\"/>", "", 0
            ),
            "find /tmp /var/run /run -type s -perm -o+w": CommandResult(
                "/tmp/mysocket.sock\n/var/run/app.sock", "", 0
            ),
            "ipcs -m": CommandResult(
                "key        shmid      owner      perms      bytes\n"
                "0x00000000 65536      root       666        4096", "", 0
            ),
            "ipcs -q": CommandResult(
                "key        msqid      owner      perms\n"
                "0x00000001 32768      root       666", "", 0
            ),
            "find /tmp /var -type p -perm -o+w": CommandResult(
                "/tmp/myfifo", "", 0
            ),
            "sysctl -n fs.mqueue.msg_max": CommandResult("10000", "", 0),
            "sysctl -n fs.mqueue.msgsize_max": CommandResult("8192", "", 0),
            "sysctl -n fs.mqueue.queues_max": CommandResult("256", "", 0),
        })
        m = IPCCheck()
        result = m.check(session)
        assert result.status == Status.VULNERABLE
        assert result.finding_count >= 4
        titles = [f.title for f in result.findings]
        assert any("D-Bus" in t for t in titles)
        assert any("socket" in t.lower() for t in titles)
        assert any("Shared memory" in t or "shared memory" in t for t in titles)
        assert any("named pipe" in t.lower() for t in titles)

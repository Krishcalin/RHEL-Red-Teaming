"""Tests for defense evasion modules."""

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
# 1. T1562 — Impair Defenses
# ---------------------------------------------------------------------------

class TestImpairDefensesCheck:
    def test_module_attributes(self):
        from modules.defense_evasion.T1562_impair_defenses import ImpairDefensesCheck
        mod = ImpairDefensesCheck()
        assert mod.TECHNIQUE_ID == "T1562"
        assert mod.TACTIC == Tactic.DEFENSE_EVASION
        assert mod.SAFE_MODE is True

    def test_check_finds_vulnerabilities(self):
        from modules.defense_evasion.T1562_impair_defenses import ImpairDefensesCheck
        session = make_session({
            "getenforce": CommandResult(stdout="Permissive", stderr="", return_code=0),
            "systemctl is-active auditd": CommandResult(stdout="inactive", stderr="", return_code=0),
            "systemctl is-active firewalld": CommandResult(stdout="inactive", stderr="", return_code=0),
            "iptables -L -n": CommandResult(stdout="5", stderr="", return_code=0),
            "pgrep -x": CommandResult(stdout="1", stderr="", return_code=0),
            "echo $HISTCONTROL": CommandResult(stdout="ignoreboth", stderr="", return_code=0),
            "echo $HISTSIZE": CommandResult(stdout="100", stderr="", return_code=0),
            "echo $HISTFILESIZE": CommandResult(stdout="100", stderr="", return_code=0),
            "echo $HISTFILE": CommandResult(stdout="/dev/null", stderr="", return_code=0),
            "grep -r 'unset HISTFILE'": CommandResult(stdout="/etc/profile.d/custom.sh:unset HISTFILE", stderr="", return_code=0),
            "firewall-cmd --state": CommandResult(stdout="not running", stderr="", return_code=0),
            "iptables -L -n 2>/dev/null | grep -c": CommandResult(stdout="3", stderr="", return_code=0),
            "nft list ruleset": CommandResult(stdout="1", stderr="", return_code=0),
            "grep -ri 'TLSv1": CommandResult(stdout="/etc/ssl/openssl.cnf:TLSv1", stderr="", return_code=0),
            "grep -E '^[^#]*@@?'": CommandResult(stdout="", stderr="", return_code=1),
            "ls -la /etc/rsyslog.conf": CommandResult(stdout="-rw-rw-r-- 1 root root 1234 Jan 1 00:00 /etc/rsyslog.conf", stderr="", return_code=0),
            "auditctl -s": CommandResult(stdout="enabled 0\nbacklog_limit 64", stderr="", return_code=0),
            "auditctl -l": CommandResult(stdout="0", stderr="", return_code=0),
        })
        mod = ImpairDefensesCheck()
        result = mod.check(session)
        assert result.status == Status.VULNERABLE
        assert len(mod._findings) > 0


# ---------------------------------------------------------------------------
# 2. T1070 — Indicator Removal
# ---------------------------------------------------------------------------

class TestIndicatorRemovalCheck:
    def test_module_attributes(self):
        from modules.defense_evasion.T1070_indicator_removal import IndicatorRemovalCheck
        mod = IndicatorRemovalCheck()
        assert mod.TECHNIQUE_ID == "T1070"
        assert mod.TACTIC == Tactic.DEFENSE_EVASION
        assert mod.SAFE_MODE is True

    def test_check_finds_vulnerabilities(self):
        from modules.defense_evasion.T1070_indicator_removal import IndicatorRemovalCheck
        session = make_session({
            "stat -c": CommandResult(stdout="644 root root", stderr="", return_code=0),
            "lsattr": CommandResult(stdout="-------------e-- /var/log/messages", stderr="", return_code=0),
            "grep -r 'compress'": CommandResult(stdout="", stderr="", return_code=1),
            "for d in /root /home/*; do": CommandResult(stdout="/root: -rw-rw-rw- 1 root root 500 Jan 1 00:00 /root/.bash_history", stderr="", return_code=0),
            "which shred": CommandResult(stdout="/usr/bin/shred", stderr="", return_code=0),
            "which srm": CommandResult(stdout="", stderr="", return_code=1),
            "which wipe": CommandResult(stdout="", stderr="", return_code=1),
            "systemd-tmpfiles-clean": CommandResult(stdout="disabled", stderr="", return_code=0),
            "test -w": CommandResult(stdout="writable", stderr="", return_code=0),
            "find /tmp /var/tmp /dev/shm -newer": CommandResult(stdout="/tmp/suspicious_file", stderr="", return_code=0),
            "ls -d /var/log/journal": CommandResult(stdout="", stderr="", return_code=1),
            "grep -E '^(SystemMaxUse|MaxRetentionSec)'": CommandResult(stdout="SystemMaxUse=50M", stderr="", return_code=0),
            "find /tmp -maxdepth 2 -type f -mmin -60 -executable": CommandResult(stdout="/tmp/evil", stderr="", return_code=0),
            "find /dev/shm -maxdepth 2 -type f -mmin -60 -executable": CommandResult(stdout="/dev/shm/payload", stderr="", return_code=0),
            "find /var/tmp -maxdepth 2 -type f -mmin -60 -executable": CommandResult(stdout="", stderr="", return_code=1),
        })
        mod = IndicatorRemovalCheck()
        result = mod.check(session)
        assert result.status == Status.VULNERABLE
        assert len(mod._findings) > 0


# ---------------------------------------------------------------------------
# 3. T1036 — Masquerading
# ---------------------------------------------------------------------------

class TestMasqueradingCheck:
    def test_module_attributes(self):
        from modules.defense_evasion.T1036_masquerading import MasqueradingCheck
        mod = MasqueradingCheck()
        assert mod.TECHNIQUE_ID == "T1036"
        assert mod.TACTIC == Tactic.DEFENSE_EVASION
        assert mod.SAFE_MODE is True

    def test_check_finds_vulnerabilities(self):
        from modules.defense_evasion.T1036_masquerading import MasqueradingCheck
        session = make_session({
            "find /usr/local/bin /usr/local/sbin /tmp /var/tmp /dev/shm": CommandResult(stdout="/tmp/ls", stderr="", return_code=0),
            "find /home -maxdepth 3": CommandResult(stdout="/home/user/ps", stderr="", return_code=0),
            "find /etc/systemd/system /run/systemd/system -name": CommandResult(stdout="/etc/systemd/system/sshd.service", stderr="", return_code=0),
            "ls /usr/lib/systemd/system/": CommandResult(stdout="/usr/lib/systemd/system/sshd.service", stderr="", return_code=0),
            "find /usr/bin -maxdepth 1 -type f -executable": CommandResult(stdout="/usr/bin/custom_tool", stderr="", return_code=0),
            "find /usr/sbin -maxdepth 1 -type f -executable": CommandResult(stdout="", stderr="", return_code=1),
            "ps -eo ppid,pid,user,comm": CommandResult(stdout="1 100 root proc1\n1 101 root proc2\n1 102 root proc3\n1 103 root proc4\n1 104 root proc5\n1 105 root proc6", stderr="", return_code=0),
            "ls -1 /proc/*/exe": CommandResult(stdout="PID=123 exe=/usr/bin/real cmdline=/usr/bin/fake", stderr="", return_code=0),
        })
        mod = MasqueradingCheck()
        result = mod.check(session)
        assert result.status == Status.VULNERABLE
        assert len(mod._findings) > 0


# ---------------------------------------------------------------------------
# 4. T1027 — Obfuscated Files or Information
# ---------------------------------------------------------------------------

class TestObfuscatedFilesCheck:
    def test_module_attributes(self):
        from modules.defense_evasion.T1027_obfuscated_files import ObfuscatedFilesCheck
        mod = ObfuscatedFilesCheck()
        assert mod.TECHNIQUE_ID == "T1027"
        assert mod.TACTIC == Tactic.DEFENSE_EVASION
        assert mod.SAFE_MODE is True

    def test_check_finds_vulnerabilities(self):
        from modules.defense_evasion.T1027_obfuscated_files import ObfuscatedFilesCheck
        session = make_session({
            "which upx": CommandResult(stdout="/usr/bin/upx", stderr="", return_code=0),
            "find /tmp /var/tmp /dev/shm -type f -executable": CommandResult(stdout="/tmp/packed_binary", stderr="", return_code=0),
            "which gcc": CommandResult(stdout="/usr/bin/gcc", stderr="", return_code=0),
            "which g++": CommandResult(stdout="/usr/bin/g++", stderr="", return_code=0),
            "which cc": CommandResult(stdout="", stderr="", return_code=1),
            "which make": CommandResult(stdout="/usr/bin/make", stderr="", return_code=0),
            "which as": CommandResult(stdout="", stderr="", return_code=1),
            "which ld": CommandResult(stdout="", stderr="", return_code=1),
            "find /tmp /dev/shm /var/tmp -maxdepth 3 -type f": CommandResult(stdout="/tmp/exploit.c", stderr="", return_code=0),
            "grep -r 'base64' /var/spool/cron/": CommandResult(stdout="/var/spool/cron/root:* * * * * echo test | base64 -d | bash", stderr="", return_code=0),
            "grep -rl 'base64' /etc/systemd/system/": CommandResult(stdout="/etc/systemd/system/backdoor.service", stderr="", return_code=0),
            "find /dev/shm -type f": CommandResult(stdout="/dev/shm/payload.dat", stderr="", return_code=0),
            "env 2>/dev/null": CommandResult(stdout="BIGVAR (600 chars)", stderr="", return_code=0),
            "find /tmp -maxdepth 2 -type f -size": CommandResult(stdout="/tmp/encoded.dat", stderr="", return_code=0),
            "find /var/tmp -maxdepth 2 -type f -size": CommandResult(stdout="", stderr="", return_code=1),
            "find /dev/shm -maxdepth 2 -type f -size": CommandResult(stdout="", stderr="", return_code=1),
        })
        mod = ObfuscatedFilesCheck()
        result = mod.check(session)
        assert result.status == Status.VULNERABLE
        assert len(mod._findings) > 0


# ---------------------------------------------------------------------------
# 5. T1222 — File and Directory Permissions Modification
# ---------------------------------------------------------------------------

class TestFilePermissionsCheck:
    def test_module_attributes(self):
        from modules.defense_evasion.T1222_file_permissions import FilePermissionsCheck
        mod = FilePermissionsCheck()
        assert mod.TECHNIQUE_ID == "T1222"
        assert mod.TACTIC == Tactic.DEFENSE_EVASION
        assert mod.SAFE_MODE is True

    def test_check_finds_vulnerabilities(self):
        from modules.defense_evasion.T1222_file_permissions import FilePermissionsCheck
        session = make_session({
            "find /etc /usr /var/log -xdev -type f -perm -0002": CommandResult(stdout="/etc/cron.d/bad_job", stderr="", return_code=0),
            "find / -xdev -type f \\( -perm -4000 -o -perm -2000": CommandResult(stdout="/usr/local/bin/suid_binary", stderr="", return_code=0),
            "find / -xdev \\( -nouser -o -nogroup": CommandResult(stdout="/tmp/orphaned_file", stderr="", return_code=0),
            "grep -i 'umask'": CommandResult(stdout="umask 002", stderr="", return_code=0),
            "getfacl": CommandResult(stdout="# file: /etc/shadow\nuser:hacker:rw-", stderr="", return_code=0),
            "getcap -r /": CommandResult(stdout="/usr/bin/python3 cap_setuid+ep", stderr="", return_code=0),
        })
        mod = FilePermissionsCheck()
        result = mod.check(session)
        assert result.status == Status.VULNERABLE
        assert len(mod._findings) > 0


# ---------------------------------------------------------------------------
# 6. T1564 — Hide Artifacts
# ---------------------------------------------------------------------------

class TestHideArtifactsCheck:
    def test_module_attributes(self):
        from modules.defense_evasion.T1564_hide_artifacts import HideArtifactsCheck
        mod = HideArtifactsCheck()
        assert mod.TECHNIQUE_ID == "T1564"
        assert mod.TACTIC == Tactic.DEFENSE_EVASION
        assert mod.SAFE_MODE is True

    def test_check_finds_vulnerabilities(self):
        from modules.defense_evasion.T1564_hide_artifacts import HideArtifactsCheck
        session = make_session({
            "ls -d /var/www /srv/www /opt/www": CommandResult(stdout="/var/www", stderr="", return_code=0),
            "find /tmp -maxdepth 3 -name '.*'": CommandResult(stdout="/tmp/.hidden_backdoor", stderr="", return_code=0),
            "find /var/tmp -maxdepth 3 -name '.*'": CommandResult(stdout="", stderr="", return_code=1),
            "find /dev/shm -maxdepth 3 -name '.*'": CommandResult(stdout="", stderr="", return_code=1),
            "find /var/www -maxdepth 3 -name '.*'": CommandResult(stdout="", stderr="", return_code=1),
            "losetup -a": CommandResult(stdout="/dev/loop0: [65025]:1234 (/tmp/hidden.img)", stderr="", return_code=0),
            "ls -la /dev/mapper/": CommandResult(stdout="suspicious_dm 1 0 0 dm-5", stderr="", return_code=0),
            "virsh list --all": CommandResult(stdout=" Id  Name  State\n 1   vm1   running", stderr="", return_code=0),
            "docker ps -a": CommandResult(stdout="CONTAINER ID  IMAGE\nabc123  evil/image", stderr="", return_code=0),
            "grep -i nohup": CommandResult(stdout="1234 root nohup ./backdoor", stderr="", return_code=0),
            "for pid in": CommandResult(stdout="PID=1234 comm=malware SigIgn=1\nPID=1235 comm=evil SigIgn=1\nPID=1236 comm=bad SigIgn=1\nPID=1237 comm=hid SigIgn=1", stderr="", return_code=0),
            "findmnt -t none": CommandResult(stdout="/usr /dev/sdb1 bind", stderr="", return_code=0),
            "find /usr/bin -maxdepth 1 -type f -executable": CommandResult(stdout="/usr/bin/test: user.custom_attr", stderr="", return_code=0),
            "find /usr/sbin -maxdepth 1 -type f -executable": CommandResult(stdout="", stderr="", return_code=1),
            "find /usr/local/bin -maxdepth 1 -type f -executable": CommandResult(stdout="", stderr="", return_code=1),
        })
        mod = HideArtifactsCheck()
        result = mod.check(session)
        assert result.status == Status.VULNERABLE
        assert len(mod._findings) > 0


# ---------------------------------------------------------------------------
# 7. T1055 — Process Injection
# ---------------------------------------------------------------------------

class TestProcessInjectionCheck:
    def test_module_attributes(self):
        from modules.defense_evasion.T1055_process_injection import ProcessInjectionCheck
        mod = ProcessInjectionCheck()
        assert mod.TECHNIQUE_ID == "T1055"
        assert mod.TACTIC == Tactic.DEFENSE_EVASION
        assert mod.SAFE_MODE is True

    def test_check_finds_vulnerabilities(self):
        from modules.defense_evasion.T1055_process_injection import ProcessInjectionCheck
        session = make_session({
            "cat /proc/sys/kernel/yama/ptrace_scope": CommandResult(stdout="0", stderr="", return_code=0),
            "ls -la /proc/1/mem": CommandResult(stdout="-rw-r--r-- 1 root root 0 Jan 1 00:00 /proc/1/mem", stderr="", return_code=0),
            "sysctl kernel.yama.ptrace_scope": CommandResult(stdout="kernel.yama.ptrace_scope = 0", stderr="", return_code=0),
            "cat /proc/self/maps": CommandResult(stdout="7fff12345000-7fff12346000 rwxp 00000000 00:00 0 [vdso]", stderr="", return_code=0),
            "grep -c 'process_vm_readv": CommandResult(stdout="4", stderr="", return_code=0),
            "getcap -r / 2>/dev/null | grep cap_sys_ptrace": CommandResult(stdout="/usr/bin/strace cap_sys_ptrace+ep", stderr="", return_code=0),
            "getsebool deny_ptrace": CommandResult(stdout="deny_ptrace --> off", stderr="", return_code=0),
        })
        mod = ProcessInjectionCheck()
        result = mod.check(session)
        assert result.status == Status.VULNERABLE
        assert len(mod._findings) > 0


# ---------------------------------------------------------------------------
# 8. T1014 — Rootkit
# ---------------------------------------------------------------------------

class TestRootkitCheck:
    def test_module_attributes(self):
        from modules.defense_evasion.T1014_rootkit import RootkitCheck
        mod = RootkitCheck()
        assert mod.TECHNIQUE_ID == "T1014"
        assert mod.TACTIC == Tactic.DEFENSE_EVASION
        assert mod.SAFE_MODE is True

    def test_check_finds_vulnerabilities(self):
        from modules.defense_evasion.T1014_rootkit import RootkitCheck
        session = make_session({
            "which rkhunter": CommandResult(stdout="", stderr="", return_code=1),
            "which chkrootkit": CommandResult(stdout="", stderr="", return_code=1),
            "diff <(lsmod": CommandResult(stdout="> hidden_module", stderr="", return_code=0),
            "diff <(ps -eo pid": CommandResult(stdout="> 9999", stderr="", return_code=0),
            "diff <(ss -tlnp": CommandResult(stdout="> 0.0.0.0:4444\n> 0.0.0.0:5555\n> 0.0.0.0:6666\n> 0.0.0.0:7777\n> 0.0.0.0:8888\n> 0.0.0.0:9999", stderr="", return_code=0),
            "rpm -Va --nomtime": CommandResult(stdout="..5....T.  /usr/bin/ls\n..5....T.  /usr/sbin/sshd", stderr="", return_code=0),
            "cat /etc/ld.so.preload": CommandResult(stdout="/lib/libevil.so", stderr="", return_code=0),
            "echo $LD_PRELOAD": CommandResult(stdout="/tmp/hook.so", stderr="", return_code=0),
            "cat /proc/sys/kernel/modules_disabled": CommandResult(stdout="0", stderr="", return_code=0),
            "cat /sys/kernel/security/lockdown": CommandResult(stdout="[none] integrity confidentiality", stderr="", return_code=0),
            "for mod in": CommandResult(stdout="unsigned: evil_mod", stderr="", return_code=0),
            "dmesg": CommandResult(stdout="[12345.678] module: tainting kernel", stderr="", return_code=0),
            "cat /proc/keys": CommandResult(stdout="", stderr="", return_code=1),
        })
        mod = RootkitCheck()
        result = mod.check(session)
        assert result.status == Status.VULNERABLE
        assert len(mod._findings) > 0


# ---------------------------------------------------------------------------
# 9. T1553 — Subvert Trust Controls
# ---------------------------------------------------------------------------

class TestSubvertTrustCheck:
    def test_module_attributes(self):
        from modules.defense_evasion.T1553_subvert_trust import SubvertTrustCheck
        mod = SubvertTrustCheck()
        assert mod.TECHNIQUE_ID == "T1553"
        assert mod.TACTIC == Tactic.DEFENSE_EVASION
        assert mod.SAFE_MODE is True

    def test_check_finds_vulnerabilities(self):
        from modules.defense_evasion.T1553_subvert_trust import SubvertTrustCheck
        session = make_session({
            "ls -la /etc/pki/ca-trust/source/anchors/": CommandResult(stdout="-rw-r--r-- 1 root root 1234 Jan 1 00:00 rogue_ca.pem", stderr="", return_code=0),
            "update-ca-trust check": CommandResult(stdout="CA trust store is out of date", stderr="", return_code=0),
            "find /etc/pki/ca-trust/source/anchors/ -type f -mtime -30": CommandResult(stdout="/etc/pki/ca-trust/source/anchors/rogue_ca.pem", stderr="", return_code=0),
            "find /etc/pki/tls/certs/": CommandResult(stdout="unpackaged: /etc/pki/tls/certs/custom.pem", stderr="", return_code=0),
            "rpm -V ca-certificates": CommandResult(stdout="S.5....T.  c /etc/pki/tls/certs/ca-bundle.crt", stderr="", return_code=0),
            "find /home/ -path": CommandResult(stdout="/home/user/.pki/nssdb/cert9.db", stderr="", return_code=0),
        })
        mod = SubvertTrustCheck()
        result = mod.check(session)
        assert result.status == Status.VULNERABLE
        assert len(mod._findings) > 0


# ---------------------------------------------------------------------------
# 10. T1620 — Reflective Code Loading
# ---------------------------------------------------------------------------

class TestReflectiveLoadingCheck:
    def test_module_attributes(self):
        from modules.defense_evasion.T1620_reflective_loading import ReflectiveLoadingCheck
        mod = ReflectiveLoadingCheck()
        assert mod.TECHNIQUE_ID == "T1620"
        assert mod.TACTIC == Tactic.DEFENSE_EVASION
        assert mod.SAFE_MODE is True

    def test_check_finds_vulnerabilities(self):
        from modules.defense_evasion.T1620_reflective_loading import ReflectiveLoadingCheck
        session = make_session({
            "ls -la /proc/*/fd": CommandResult(stdout="lr-x------ 1 root root 64 Jan 1 00:00 3 -> memfd:payload", stderr="", return_code=0),
            "find /dev/shm -type f -executable": CommandResult(stdout="/dev/shm/malware", stderr="", return_code=0),
            "mount | grep '/dev/shm'": CommandResult(stdout="tmpfs on /dev/shm type tmpfs (rw,nosuid,nodev)", stderr="", return_code=0),
            "ls -la /proc/*/exe": CommandResult(stdout="lrwxrwxrwx 1 root root 0 Jan 1 00:00 /proc/1234/exe -> /usr/bin/evil (deleted)", stderr="", return_code=0),
            "cat /proc/sys/vm/memfd_noexec": CommandResult(stdout="0", stderr="", return_code=0),
            "for pid in": CommandResult(stdout="PID 1234: (bash)", stderr="", return_code=0),
        })
        mod = ReflectiveLoadingCheck()
        result = mod.check(session)
        assert result.status == Status.VULNERABLE
        assert len(mod._findings) > 0


# ---------------------------------------------------------------------------
# 11. T1218 — System Binary Proxy Execution
# ---------------------------------------------------------------------------

class TestProxyExecutionCheck:
    def test_module_attributes(self):
        from modules.defense_evasion.T1218_proxy_execution import ProxyExecutionCheck
        mod = ProxyExecutionCheck()
        assert mod.TECHNIQUE_ID == "T1218"
        assert mod.TACTIC == Tactic.DEFENSE_EVASION
        assert mod.SAFE_MODE is True

    def test_check_finds_vulnerabilities(self):
        from modules.defense_evasion.T1218_proxy_execution import ProxyExecutionCheck
        session = make_session({
            "find /usr/lib /usr/local/lib /opt /snap -name": CommandResult(stdout="/opt/app/electron", stderr="", return_code=0),
            "xargs file": CommandResult(stdout="/usr/bin/app: ELF 64-bit electron", stderr="", return_code=0),
            "which find": CommandResult(stdout="/usr/bin/find", stderr="", return_code=0),
            "which tar": CommandResult(stdout="/usr/bin/tar", stderr="", return_code=0),
            "which zip": CommandResult(stdout="", stderr="", return_code=1),
            "which awk": CommandResult(stdout="", stderr="", return_code=1),
            "which nmap": CommandResult(stdout="", stderr="", return_code=1),
            "which vim": CommandResult(stdout="", stderr="", return_code=1),
            "which less": CommandResult(stdout="", stderr="", return_code=1),
            "which man": CommandResult(stdout="", stderr="", return_code=1),
            "which rvim": CommandResult(stdout="", stderr="", return_code=1),
            "which python3": CommandResult(stdout="", stderr="", return_code=1),
            "which perl": CommandResult(stdout="", stderr="", return_code=1),
            "which ruby": CommandResult(stdout="", stderr="", return_code=1),
            "test -u /usr/bin/find": CommandResult(stdout="SUID", stderr="", return_code=0),
            "test -u /usr/bin/tar": CommandResult(stdout="SUID", stderr="", return_code=0),
            "find /usr/bin /usr/sbin /usr/local/bin -perm -4000": CommandResult(stdout="/usr/bin/sudo", stderr="", return_code=0),
            "getcap -r /usr/bin /usr/sbin /usr/local/bin": CommandResult(stdout="/usr/bin/python3 cap_setuid+ep", stderr="", return_code=0),
            "which env": CommandResult(stdout="/usr/bin/env", stderr="", return_code=0),
            "test -u /usr/bin/env": CommandResult(stdout="SUID", stderr="", return_code=0),
            "file /usr/bin/env": CommandResult(stdout="/usr/bin/env: ELF 64-bit", stderr="", return_code=0),
            "grep -E '(/usr/bin/rbash|/bin/rbash|/usr/sbin/nologin)'": CommandResult(stdout="nologinuser:/usr/sbin/nologin", stderr="", return_code=0),
        })
        mod = ProxyExecutionCheck()
        result = mod.check(session)
        assert result.status == Status.VULNERABLE
        assert len(mod._findings) > 0


# ---------------------------------------------------------------------------
# 12. T1497 — Virtualization/Sandbox Evasion
# ---------------------------------------------------------------------------

class TestVirtualizationEvasionCheck:
    def test_module_attributes(self):
        from modules.defense_evasion.T1497_virtualization_evasion import VirtualizationEvasionCheck
        mod = VirtualizationEvasionCheck()
        assert mod.TECHNIQUE_ID == "T1497"
        assert mod.TACTIC == Tactic.DEFENSE_EVASION
        assert mod.SAFE_MODE is True

    def test_check_finds_vulnerabilities(self):
        from modules.defense_evasion.T1497_virtualization_evasion import VirtualizationEvasionCheck
        session = make_session({
            "systemd-detect-virt": CommandResult(stdout="kvm", stderr="", return_code=0),
            "cat /sys/class/dmi/id/sys_vendor": CommandResult(stdout="QEMU\nStandard PC\nQEMU", stderr="", return_code=0),
            "lsmod": CommandResult(stdout="Module Size Used\nvirtio_pci 12345 0\nvirtio_net 23456 0", stderr="", return_code=0),
            "for h in /home/*/.bash_history": CommandResult(stdout="sparse: /home/user/.bash_history", stderr="", return_code=0),
            "last -n 5": CommandResult(stdout="", stderr="", return_code=0),
            "timedatectl show": CommandResult(stdout="NTPSynchronized=no", stderr="", return_code=0),
            "grep -c 'hypervisor' /proc/cpuinfo": CommandResult(stdout="4", stderr="", return_code=0),
            "grep 'Hypervisor vendor'": CommandResult(stdout="Hypervisor vendor: KVM", stderr="", return_code=0),
        })
        mod = VirtualizationEvasionCheck()
        result = mod.check(session)
        assert result.status == Status.VULNERABLE
        assert len(mod._findings) > 0


# ---------------------------------------------------------------------------
# 13. T1622 — Debugger Evasion
# ---------------------------------------------------------------------------

class TestDebuggerEvasionCheck:
    def test_module_attributes(self):
        from modules.defense_evasion.T1622_debugger_evasion import DebuggerEvasionCheck
        mod = DebuggerEvasionCheck()
        assert mod.TECHNIQUE_ID == "T1622"
        assert mod.TACTIC == Tactic.DEFENSE_EVASION
        assert mod.SAFE_MODE is True

    def test_check_finds_vulnerabilities(self):
        from modules.defense_evasion.T1622_debugger_evasion import DebuggerEvasionCheck
        session = make_session({
            "which gdb": CommandResult(stdout="/usr/bin/gdb", stderr="", return_code=0),
            "which strace": CommandResult(stdout="/usr/bin/strace", stderr="", return_code=0),
            "which ltrace": CommandResult(stdout="", stderr="", return_code=1),
            "which perf": CommandResult(stdout="", stderr="", return_code=1),
            "which valgrind": CommandResult(stdout="", stderr="", return_code=1),
            "which objdump": CommandResult(stdout="", stderr="", return_code=1),
            "cat /proc/sys/kernel/yama/ptrace_scope": CommandResult(stdout="0", stderr="", return_code=0),
            "ulimit -c": CommandResult(stdout="unlimited", stderr="", return_code=0),
            "cat /proc/sys/kernel/core_pattern": CommandResult(stdout="|/usr/lib/systemd/systemd-coredump", stderr="", return_code=0),
            "grep TracerPid": CommandResult(stdout="TracerPid:\t1234", stderr="", return_code=0),
            "ps -p 1234": CommandResult(stdout="gdb", stderr="", return_code=0),
            "cat /proc/sys/kernel/perf_event_paranoid": CommandResult(stdout="1", stderr="", return_code=0),
        })
        mod = DebuggerEvasionCheck()
        result = mod.check(session)
        assert result.status == Status.VULNERABLE
        assert len(mod._findings) > 0


# ---------------------------------------------------------------------------
# 14. T1678 — Delay Execution
# ---------------------------------------------------------------------------

class TestDelayExecutionCheck:
    def test_module_attributes(self):
        from modules.defense_evasion.T1678_delay_execution import DelayExecutionCheck
        mod = DelayExecutionCheck()
        assert mod.TECHNIQUE_ID == "T1678"
        assert mod.TACTIC == Tactic.DEFENSE_EVASION
        assert mod.SAFE_MODE is True

    def test_check_finds_vulnerabilities(self):
        from modules.defense_evasion.T1678_delay_execution import DelayExecutionCheck
        session = make_session({
            "atq": CommandResult(stdout="1\tThu Mar 20 10:00:00 2026 a root\n2\tFri Mar 21 10:00:00 2026 a root", stderr="", return_code=0),
            "grep -r '@reboot' /var/spool/cron/": CommandResult(stdout="/var/spool/cron/root:@reboot sleep 300 && /tmp/backdoor.sh", stderr="", return_code=0),
            "systemctl list-timers --all": CommandResult(stdout="NEXT                       LEFT       LAST PASSED UNIT ACTIVATES\nThu 2026-03-20 10:00:00 1h left  cleanup.timer cleanup.service", stderr="", return_code=0),
            "for timer in": CommandResult(stdout="OnBootSec=2h\n  -> custom.timer", stderr="", return_code=0),
            "grep -rl 'sleep [0-9]' /etc/cron.d/": CommandResult(stdout="/etc/cron.d/suspicious", stderr="", return_code=0),
            "grep 'sleep [0-9]'": CommandResult(stdout="sleep 3600", stderr="", return_code=0),
            "grep -rl 'RestartSec": CommandResult(stdout="RestartSec=300\n  -> /etc/systemd/system/evil.service", stderr="", return_code=0),
        })
        mod = DelayExecutionCheck()
        result = mod.check(session)
        assert result.status == Status.VULNERABLE
        assert len(mod._findings) > 0


# ---------------------------------------------------------------------------
# 15. T1140 — Deobfuscate/Decode Files or Information
# ---------------------------------------------------------------------------

class TestDeobfuscateCheck:
    def test_module_attributes(self):
        from modules.defense_evasion.T1140_deobfuscate import DeobfuscateCheck
        mod = DeobfuscateCheck()
        assert mod.TECHNIQUE_ID == "T1140"
        assert mod.TACTIC == Tactic.DEFENSE_EVASION
        assert mod.SAFE_MODE is True

    def test_check_finds_vulnerabilities(self):
        from modules.defense_evasion.T1140_deobfuscate import DeobfuscateCheck
        session = make_session({
            "which base64": CommandResult(stdout="/usr/bin/base64", stderr="", return_code=0),
            "which xxd": CommandResult(stdout="/usr/bin/xxd", stderr="", return_code=0),
            "which openssl": CommandResult(stdout="/usr/bin/openssl", stderr="", return_code=0),
            "which certutil": CommandResult(stdout="", stderr="", return_code=1),
            "which uudecode": CommandResult(stdout="", stderr="", return_code=1),
            "grep -h 'base64.*-d": CommandResult(stdout="echo payload | base64 -d | bash", stderr="", return_code=0),
            "find /tmp /dev/shm /var/tmp -type f -size +0 -size -10M": CommandResult(stdout="/tmp/encoded_payload", stderr="", return_code=0),
            "grep -rl 'openssl.*enc": CommandResult(stdout="/etc/cron.d/decrypt_job", stderr="", return_code=0),
            "grep -n 'openssl.*enc": CommandResult(stdout="3:openssl enc -aes-256-cbc -d -in /tmp/payload.enc", stderr="", return_code=0),
            "grep -hE '(python3?.*-c.*(decode|b64decode|base64)": CommandResult(stdout="python3 -c 'import base64; exec(base64.b64decode(\"...\"))'", stderr="", return_code=0),
        })
        mod = DeobfuscateCheck()
        result = mod.check(session)
        assert result.status == Status.VULNERABLE
        assert len(mod._findings) > 0


# ---------------------------------------------------------------------------
# 16. T1480 — Execution Guardrails
# ---------------------------------------------------------------------------

class TestExecutionGuardrailsCheck:
    def test_module_attributes(self):
        from modules.defense_evasion.T1480_execution_guardrails import ExecutionGuardrailsCheck
        mod = ExecutionGuardrailsCheck()
        assert mod.TECHNIQUE_ID == "T1480"
        assert mod.TACTIC == Tactic.DEFENSE_EVASION
        assert mod.SAFE_MODE is True

    def test_check_finds_vulnerabilities(self):
        from modules.defense_evasion.T1480_execution_guardrails import ExecutionGuardrailsCheck
        session = make_session({
            "grep -rl 'hostname": CommandResult(stdout="/tmp/payload.sh", stderr="", return_code=0),
            "grep -lE '(if.*hostname": CommandResult(stdout="/tmp/payload.sh", stderr="", return_code=0),
            "grep -rlE '(ip addr|ifconfig|hostname -I)'": CommandResult(stdout="/tmp/network_check.sh", stderr="", return_code=0),
            "grep -lE '(if.*ip addr": CommandResult(stdout="/tmp/network_check.sh", stderr="", return_code=0),
            "find /tmp /var/lock /var/run /run -name": CommandResult(stdout="/tmp/custom.lock\n/tmp/malware.pid", stderr="", return_code=0),
            "grep -r 'flock' /var/spool/cron/": CommandResult(stdout="/var/spool/cron/root:* * * * * flock -n /tmp/job.lock /usr/local/bin/task.sh", stderr="", return_code=0),
            "grep -rlE '(if.*\\$\\{?[A-Z_]+\\}?.*==|test.*\\$[A-Z_]+|": CommandResult(stdout="/tmp/gated_script.sh", stderr="", return_code=0),
            "grep -nE '(if.*\\$[A-Z_]+|test.*\\$[A-Z_]+)'": CommandResult(stdout="5:if [ \"$TARGET_ENV\" == \"production\" ]; then", stderr="", return_code=0),
            "grep -rE '(date.*\\+|\\$\\(date|if.*date)'": CommandResult(stdout="/var/spool/cron/root:0 0 * * * [ $(date +%u) -eq 5 ] && /tmp/friday.sh", stderr="", return_code=0),
            "grep -rl 'ConditionFirstBoot": CommandResult(stdout="/etc/systemd/system/firstboot.service", stderr="", return_code=0),
            "grep -E '(Condition|Assert)'": CommandResult(stdout="ConditionFirstBoot=yes", stderr="", return_code=0),
        })
        mod = ExecutionGuardrailsCheck()
        result = mod.check(session)
        assert result.status == Status.VULNERABLE
        assert len(mod._findings) > 0


# ---------------------------------------------------------------------------
# 17. T1574 — Hijack Execution Flow (Defense Evasion)
# ---------------------------------------------------------------------------

class TestHijackExecutionEvasionCheck:
    def test_module_attributes(self):
        from modules.defense_evasion.T1574_de_hijack_execution import HijackExecutionEvasionCheck
        mod = HijackExecutionEvasionCheck()
        assert mod.TECHNIQUE_ID == "T1574"
        assert mod.TACTIC == Tactic.DEFENSE_EVASION
        assert mod.SAFE_MODE is True

    def test_check_finds_vulnerabilities(self):
        from modules.defense_evasion.T1574_de_hijack_execution import HijackExecutionEvasionCheck
        session = make_session({
            "grep -rs 'LD_DEBUG'": CommandResult(stdout="/etc/profile.d/debug.sh:export LD_DEBUG=all", stderr="", return_code=0),
            "xargs -0": CommandResult(stdout="LD_DEBUG=libs", stderr="", return_code=0),
            "cat /etc/ld.so.preload": CommandResult(stdout="/lib/libhook.so", stderr="", return_code=0),
            "grep -rs 'LD_PRELOAD'": CommandResult(stdout="/etc/profile.d/preload.sh:export LD_PRELOAD=/lib/libhook.so", stderr="", return_code=0),
            "test -f '/lib/libhook.so'": CommandResult(stdout="exists", stderr="", return_code=0),
            "nm -D '/lib/libhook.so'": CommandResult(stdout="T readdir\nT stat\nT open", stderr="", return_code=0),
            "readelf -d": CommandResult(stdout="0x000000000000001d (RUNPATH) Library runpath: [/tmp/libs]", stderr="", return_code=0),
            "find /lib -maxdepth 1 -writable": CommandResult(stdout="/lib", stderr="", return_code=0),
            "find /lib64 -maxdepth 1 -writable": CommandResult(stdout="", stderr="", return_code=1),
            "find /usr/lib -maxdepth 1 -writable": CommandResult(stdout="", stderr="", return_code=1),
            "find /usr/lib64 -maxdepth 1 -writable": CommandResult(stdout="", stderr="", return_code=1),
            "cat /etc/ld.so.conf": CommandResult(stdout="/usr/local/lib\n/opt/lib", stderr="", return_code=0),
            "test -d '/usr/local/lib' && test -w": CommandResult(stdout="writable", stderr="", return_code=0),
            "test -d '/opt/lib' && test -w": CommandResult(stdout="", stderr="", return_code=1),
        })
        mod = HijackExecutionEvasionCheck()
        result = mod.check(session)
        assert result.status == Status.VULNERABLE
        assert len(mod._findings) > 0


# ---------------------------------------------------------------------------
# 18. T1556 — Modify Authentication Process (Defense Evasion)
# ---------------------------------------------------------------------------

class TestModifyAuthEvasionCheck:
    def test_module_attributes(self):
        from modules.defense_evasion.T1556_de_modify_auth import ModifyAuthEvasionCheck
        mod = ModifyAuthEvasionCheck()
        assert mod.TECHNIQUE_ID == "T1556"
        assert mod.TACTIC == Tactic.DEFENSE_EVASION
        assert mod.SAFE_MODE is True

    def test_check_finds_vulnerabilities(self):
        from modules.defense_evasion.T1556_de_modify_auth import ModifyAuthEvasionCheck
        session = make_session({
            "grep -rn 'pam_succeed_if.*quiet": CommandResult(stdout="/etc/pam.d/sshd:3:auth requisite pam_succeed_if.so quiet", stderr="", return_code=0),
            "grep -rn 'pam_nologin": CommandResult(stdout="/etc/pam.d/login:5:auth required pam_nologin.so noreply", stderr="", return_code=0),
            "grep -rn 'pam_faillock": CommandResult(stdout="", stderr="", return_code=1),
            "grep -rn 'pam_tally2'": CommandResult(stdout="", stderr="", return_code=1),
            "grep -rn 'pam_permit'": CommandResult(stdout="/etc/pam.d/test:1:auth sufficient pam_permit.so", stderr="", return_code=0),
            "grep -rn 'authpriv": CommandResult(stdout="", stderr="", return_code=1),
            "test -f /var/log/secure": CommandResult(stdout="0 1234567890", stderr="", return_code=0),
            "auditctl -l": CommandResult(stdout="", stderr="", return_code=0),
        })
        mod = ModifyAuthEvasionCheck()
        result = mod.check(session)
        assert result.status == Status.VULNERABLE
        assert len(mod._findings) > 0


# ---------------------------------------------------------------------------
# 19. T1542 — Pre-OS Boot (Defense Evasion)
# ---------------------------------------------------------------------------

class TestPreOSBootEvasionCheck:
    def test_module_attributes(self):
        from modules.defense_evasion.T1542_de_pre_os_boot import PreOSBootEvasionCheck
        mod = PreOSBootEvasionCheck()
        assert mod.TECHNIQUE_ID == "T1542"
        assert mod.TACTIC == Tactic.DEFENSE_EVASION
        assert mod.SAFE_MODE is True

    def test_check_finds_vulnerabilities(self):
        from modules.defense_evasion.T1542_de_pre_os_boot import PreOSBootEvasionCheck
        session = make_session({
            "mokutil --sb-state": CommandResult(stdout="SecureBoot disabled", stderr="", return_code=0),
            "mokutil --list-new": CommandResult(stdout="[key 1]\nSHA1 Fingerprint: ab:cd:ef", stderr="", return_code=0),
            "for mod in $(lsmod": CommandResult(stdout="evil_module\nrootkit_mod", stderr="", return_code=0),
            "cat /proc/sys/kernel/modules_disabled": CommandResult(stdout="0", stderr="", return_code=0),
            "cat /proc/sys/kernel/module_sig_enforce": CommandResult(stdout="0", stderr="", return_code=0),
            "grep -l 'password_pbkdf2": CommandResult(stdout="", stderr="", return_code=1),
            "stat -c '%a %U'": CommandResult(stdout="644 root", stderr="", return_code=0),
            "cat /proc/cmdline": CommandResult(stdout="BOOT_IMAGE=/vmlinuz root=/dev/mapper/rhel-root init=/bin/sh", stderr="", return_code=0),
            "grep -r 'sulogin'": CommandResult(stdout="", stderr="", return_code=1),
            "systemctl is-active fwupd": CommandResult(stdout="active", stderr="", return_code=0),
            "grep -r 'org.freedesktop.fwupd'": CommandResult(stdout="allow_active>yes</allow_active", stderr="", return_code=0),
            "ls /sys/firmware/efi/efivars/": CommandResult(stdout="SecureBoot-xxx\nBootOrder-xxx", stderr="", return_code=0),
            "test -w /sys/firmware/efi/efivars/": CommandResult(stdout="writable", stderr="", return_code=0),
        })
        mod = PreOSBootEvasionCheck()
        result = mod.check(session)
        assert result.status == Status.VULNERABLE
        assert len(mod._findings) > 0


# ---------------------------------------------------------------------------
# 20. T1205 — Traffic Signaling (Defense Evasion)
# ---------------------------------------------------------------------------

class TestTrafficSignalingEvasionCheck:
    def test_module_attributes(self):
        from modules.defense_evasion.T1205_de_traffic_signaling import TrafficSignalingEvasionCheck
        mod = TrafficSignalingEvasionCheck()
        assert mod.TECHNIQUE_ID == "T1205"
        assert mod.TACTIC == Tactic.DEFENSE_EVASION
        assert mod.SAFE_MODE is True

    def test_check_finds_vulnerabilities(self):
        from modules.defense_evasion.T1205_de_traffic_signaling import TrafficSignalingEvasionCheck
        session = make_session({
            "iptables -L -n -v": CommandResult(stdout="ACCEPT all -- 0.0.0.0/0 0.0.0.0/0 recent: CHECK", stderr="", return_code=0),
            "nft list ruleset": CommandResult(stdout="ct mark set 0x1", stderr="", return_code=0),
            "iptables -L -n 2>/dev/null | grep -i 'icmp.*accept'": CommandResult(stdout="ACCEPT icmp -- 0.0.0.0/0 0.0.0.0/0", stderr="", return_code=0),
            "systemctl is-active knockd": CommandResult(stdout="active", stderr="", return_code=0),
            "cat /etc/knockd.conf": CommandResult(stdout="[openSSH]\nsequence = 7000,8000,9000\ncommand = /sbin/iptables -A INPUT -s %IP% -j ACCEPT", stderr="", return_code=0),
            "ip link show type wireguard": CommandResult(stdout="3: wg0: <POINTOPOINT> mtu 1420", stderr="", return_code=0),
            "pgrep -a openvpn": CommandResult(stdout="1234 /usr/sbin/openvpn --config /etc/openvpn/client.conf", stderr="", return_code=0),
            "ip link show type tun": CommandResult(stdout="4: tun0: <POINTOPOINT> mtu 1500", stderr="", return_code=0),
            "ss -w -n -p": CommandResult(stdout="Netid State\nraw   UNCONN 0 0 *:255 *:*  users:((\"ping\",pid=1234,fd=3))", stderr="", return_code=0),
            "ss -0 -n -p": CommandResult(stdout="raw   UNCONN 0 0 *:all *:*", stderr="", return_code=0),
            "bpftool prog list": CommandResult(stdout="1: xdp tag abc123\n2: sched_cls tag def456", stderr="", return_code=0),
            "cat /proc/sys/kernel/unprivileged_bpf_disabled": CommandResult(stdout="0", stderr="", return_code=0),
            "rpm -q knockd": CommandResult(stdout="knockd-0.8-1.el8.x86_64", stderr="", return_code=0),
        })
        mod = TrafficSignalingEvasionCheck()
        result = mod.check(session)
        assert result.status == Status.VULNERABLE
        assert len(mod._findings) > 0


# ---------------------------------------------------------------------------
# 21. T1078 — Valid Accounts (Defense Evasion)
# ---------------------------------------------------------------------------

class TestValidAccountsEvasionCheck:
    def test_module_attributes(self):
        from modules.defense_evasion.T1078_de_valid_accounts import ValidAccountsEvasionCheck
        mod = ValidAccountsEvasionCheck()
        assert mod.TECHNIQUE_ID == "T1078"
        assert mod.TACTIC == Tactic.DEFENSE_EVASION
        assert mod.SAFE_MODE is True

    def test_check_finds_vulnerabilities(self):
        from modules.defense_evasion.T1078_de_valid_accounts import ValidAccountsEvasionCheck
        session = make_session({
            "getent passwd guest": CommandResult(stdout="guest:x:1001:1001::/home/guest:/bin/bash", stderr="", return_code=0),
            "getent passwd test": CommandResult(stdout="test:x:1002:1002::/home/test:/bin/bash", stderr="", return_code=0),
            "getent passwd oracle": CommandResult(stdout="", stderr="", return_code=1),
            "getent passwd postgres": CommandResult(stdout="", stderr="", return_code=1),
            "getent passwd mysql": CommandResult(stdout="", stderr="", return_code=1),
            "getent passwd ftp": CommandResult(stdout="", stderr="", return_code=1),
            "getent passwd admin": CommandResult(stdout="", stderr="", return_code=1),
            "getent passwd user": CommandResult(stdout="", stderr="", return_code=1),
            "getent passwd demo": CommandResult(stdout="", stderr="", return_code=1),
            "getent passwd nagios": CommandResult(stdout="", stderr="", return_code=1),
            "getent passwd zabbix": CommandResult(stdout="", stderr="", return_code=1),
            "getent passwd ansible": CommandResult(stdout="", stderr="", return_code=1),
            "passwd -S guest": CommandResult(stdout="guest PS 2025-01-01", stderr="", return_code=0),
            "passwd -S test": CommandResult(stdout="test PS 2025-01-01", stderr="", return_code=0),
            "last -n 50": CommandResult(stdout="root pts/0 192.168.1.1 Thu Mar 20 02:30 still logged in", stderr="", return_code=0),
            "awk -F: '$3 == 0": CommandResult(stdout="root\ntoor", stderr="", return_code=0),
            "awk -F: '$3 >= 1 && $3 < 1000": CommandResult(stdout="daemon:/bin/bash\nnobody:/bin/sh", stderr="", return_code=0),
            "grep -n 'pam_wheel'": CommandResult(stdout="#auth required pam_wheel.so use_uid", stderr="", return_code=0),
            "awk -F: '$3 >= 1000 && $7": CommandResult(stdout="testuser\nadmin_user", stderr="", return_code=0),
            "chage -l": CommandResult(stdout="Maximum number of days between password change : 99999", stderr="", return_code=0),
            "lastb -n 100 2>/dev/null | awk": CommandResult(stdout="     15 admin\n     12 root", stderr="", return_code=0),
            "lastb -n 100 2>/dev/null | grep '^root '": CommandResult(stdout="10", stderr="", return_code=0),
        })
        mod = ValidAccountsEvasionCheck()
        result = mod.check(session)
        assert result.status == Status.VULNERABLE
        assert len(mod._findings) > 0


# ---------------------------------------------------------------------------
# 22. T1211 — Exploitation for Defense Evasion
# ---------------------------------------------------------------------------

class TestExploitDefenseEvasionCheck:
    def test_module_attributes(self):
        from modules.defense_evasion.T1211_exploit_defense_evasion import ExploitDefenseEvasionCheck
        mod = ExploitDefenseEvasionCheck()
        assert mod.TECHNIQUE_ID == "T1211"
        assert mod.TACTIC == Tactic.DEFENSE_EVASION
        assert mod.SAFE_MODE is True

    def test_check_finds_vulnerabilities(self):
        from modules.defense_evasion.T1211_exploit_defense_evasion import ExploitDefenseEvasionCheck
        session = make_session({
            "uname -r": CommandResult(stdout="4.18.0-305.el8.x86_64", stderr="", return_code=0),
            "rpm -q kernel --last": CommandResult(stdout="kernel-4.18.0-500.el8.x86_64 Thu Mar 10 2026", stderr="", return_code=0),
            "rpm -q --changelog kernel-": CommandResult(stdout="CVE-2024-1234\nCVE-2024-5678", stderr="", return_code=0),
            "kpatch list": CommandResult(stdout="nothing to report", stderr="", return_code=0),
            "dnf check-update selinux-policy": CommandResult(stdout="selinux-policy.noarch 3.14.3-100.el8 baseos", stderr="", return_code=0),
            "dnf check-update audit": CommandResult(stdout="", stderr="", return_code=1),
            "dnf check-update firewalld": CommandResult(stdout="", stderr="", return_code=1),
            "dnf check-update openssl": CommandResult(stdout="openssl.x86_64 1.1.1k-8.el8 baseos", stderr="", return_code=0),
            "dnf check-update openssh": CommandResult(stdout="", stderr="", return_code=1),
            "dnf check-update sudo": CommandResult(stdout="", stderr="", return_code=1),
            "dnf check-update polkit": CommandResult(stdout="", stderr="", return_code=1),
            "dnf check-update systemd": CommandResult(stdout="", stderr="", return_code=1),
            "systemctl is-active dnf-automatic.timer": CommandResult(stdout="inactive", stderr="", return_code=0),
            "systemctl is-active dnf-automatic-install.timer": CommandResult(stdout="inactive", stderr="", return_code=0),
            "dnf updateinfo list security": CommandResult(stdout="RHSA-2026:001 Critical/Sec. kernel-4.18.0-500.el8\nRHSA-2026:002 Important/Sec. openssl-1.1.1k-8.el8", stderr="", return_code=0),
            "subscription-manager status": CommandResult(stdout="Overall Status: unknown", stderr="", return_code=0),
            "dnf updateinfo summary": CommandResult(stdout="5 Security notice(s)\n   1 Critical Security notice(s)", stderr="", return_code=0),
        })
        mod = ExploitDefenseEvasionCheck()
        result = mod.check(session)
        assert result.status == Status.VULNERABLE
        assert len(mod._findings) > 0


# ---------------------------------------------------------------------------
# 23. T1656 — Impersonation
# ---------------------------------------------------------------------------

class TestImpersonationCheck:
    def test_module_attributes(self):
        from modules.defense_evasion.T1656_impersonation import ImpersonationCheck
        mod = ImpersonationCheck()
        assert mod.TECHNIQUE_ID == "T1656"
        assert mod.TACTIC == Tactic.DEFENSE_EVASION
        assert mod.SAFE_MODE is True

    def test_check_finds_vulnerabilities(self):
        from modules.defense_evasion.T1656_impersonation import ImpersonationCheck
        session = make_session({
            "cat /proc/sys/user/max_user_namespaces": CommandResult(stdout="65536", stderr="", return_code=0),
            "cat /proc/sys/kernel/unprivileged_userns_clone": CommandResult(stdout="1", stderr="", return_code=0),
            "grep -i 'log_output": CommandResult(stdout="", stderr="", return_code=0),
            "grep 'pam_syslog": CommandResult(stdout="", stderr="", return_code=1),
            "grep 'session.*pam_unix": CommandResult(stdout="", stderr="", return_code=1),
            "grep -r 'pam_tty_audit'": CommandResult(stdout="", stderr="", return_code=1),
            "for pid in $(ls /proc/": CommandResult(stdout="PID=1234 comm=sshd exe=evil_binary", stderr="", return_code=0),
            "cat /proc/sys/fs/protected_symlinks": CommandResult(stdout="0", stderr="", return_code=0),
            "cat /proc/sys/fs/protected_hardlinks": CommandResult(stdout="0", stderr="", return_code=0),
            "stat -c '%a' /tmp": CommandResult(stdout="777", stderr="", return_code=0),
            "cat /proc/sys/dev/tty/legacy_tiocsti": CommandResult(stdout="1", stderr="", return_code=0),
        })
        mod = ImpersonationCheck()
        result = mod.check(session)
        assert result.status == Status.VULNERABLE
        assert len(mod._findings) > 0

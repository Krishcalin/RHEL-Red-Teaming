"""Tests for impact modules (TA0040)."""

from __future__ import annotations

from unittest.mock import MagicMock

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
# T1485 — Data Destruction
# ---------------------------------------------------------------------------


class TestDataDestructionCheck:
    def test_module_attributes(self):
        from modules.impact.T1485_data_destruction import DataDestructionCheck
        m = DataDestructionCheck()
        assert m.TECHNIQUE_ID == "T1485"
        assert m.TACTIC == Tactic.IMPACT
        assert m.SAFE_MODE is True

    def test_check_destructive_tools(self):
        from modules.impact.T1485_data_destruction import DataDestructionCheck
        session = make_session({
            "which shred": CommandResult("/usr/bin/shred", "", 0),
            "which wipe": CommandResult("", "", 1),
            "which srm": CommandResult("", "", 1),
            "which dd": CommandResult("/usr/bin/dd", "", 0),
            "lsattr -R /etc": CommandResult("", "", 1),
            "lsattr -R /var/log": CommandResult("", "", 1),
            "rpm -q": CommandResult("package not installed", "", 1),
            "alias rm": CommandResult("", "", 1),
        })
        m = DataDestructionCheck()
        result = m.check(session)
        assert result.status == Status.VULNERABLE
        titles = [f.title for f in result.findings]
        assert any("shred" in t for t in titles)
        assert any("dd" in t for t in titles)

    def test_check_no_backups(self):
        from modules.impact.T1485_data_destruction import DataDestructionCheck
        session = make_session({
            "which shred": CommandResult("", "", 1),
            "which wipe": CommandResult("", "", 1),
            "which srm": CommandResult("", "", 1),
            "which dd": CommandResult("", "", 1),
            "lsattr -R /etc": CommandResult("----i-------- /etc/passwd\n", "", 0),
            "lsattr -R /var/log": CommandResult("", "", 1),
            "rpm -q": CommandResult("package not installed", "", 1),
            "alias rm": CommandResult("", "", 1),
        })
        m = DataDestructionCheck()
        result = m.check(session)
        assert result.status == Status.VULNERABLE
        titles = [f.title for f in result.findings]
        assert any("backup" in t.lower() for t in titles)

    def test_check_clean(self):
        from modules.impact.T1485_data_destruction import DataDestructionCheck
        session = make_session({
            "which shred": CommandResult("", "", 1),
            "which wipe": CommandResult("", "", 1),
            "which srm": CommandResult("", "", 1),
            "which dd": CommandResult("", "", 1),
            "lsattr -R /etc": CommandResult("----i-------- /etc/passwd\n", "", 0),
            "lsattr -R /var/log": CommandResult("----i-------- /var/log/messages\n", "", 0),
            "rpm -q borgbackup": CommandResult("borgbackup-1.2.4-1.el9.x86_64", "", 0),
            "alias rm": CommandResult("alias rm='trash-put'\n", "", 0),
        })
        m = DataDestructionCheck()
        result = m.check(session)
        assert result.status == Status.NOT_VULNERABLE

    def test_mitigations_not_empty(self):
        from modules.impact.T1485_data_destruction import DataDestructionCheck
        m = DataDestructionCheck()
        assert len(m.get_mitigations()) > 0


# ---------------------------------------------------------------------------
# T1486 — Data Encrypted for Impact
# ---------------------------------------------------------------------------


class TestDataEncryptedCheck:
    def test_module_attributes(self):
        from modules.impact.T1486_data_encrypted import DataEncryptedCheck
        m = DataEncryptedCheck()
        assert m.TECHNIQUE_ID == "T1486"
        assert m.TACTIC == Tactic.IMPACT
        assert m.SEVERITY == Severity.CRITICAL

    def test_check_writable_data_dirs(self):
        from modules.impact.T1486_data_encrypted import DataEncryptedCheck
        session = make_session({
            "which openssl": CommandResult("", "", 1),
            "which gpg": CommandResult("", "", 1),
            "which ccrypt": CommandResult("", "", 1),
            "which 7z": CommandResult("", "", 1),
            "find /var/lib/mysql": CommandResult("", "", 1),
            "find /var/lib/pgsql": CommandResult("", "", 1),
            "test -d /var/www": CommandResult("/var/www", "", 0),
            "/var/www": CommandResult("/var/www", "", 0),
            "test -d /home": CommandResult("/home", "", 0),
            "/home": CommandResult("/home", "", 0),
            "find /var/backups": CommandResult("", "", 1),
            "lsblk": CommandResult("sda  ext4\n", "", 0),
        })
        m = DataEncryptedCheck()
        result = m.check(session)
        assert result.status == Status.VULNERABLE

    def test_check_clean(self):
        from modules.impact.T1486_data_encrypted import DataEncryptedCheck
        session = make_session({
            "which openssl": CommandResult("", "", 1),
            "which gpg": CommandResult("", "", 1),
            "which ccrypt": CommandResult("", "", 1),
            "which 7z": CommandResult("", "", 1),
            "lsblk": CommandResult("sda  crypt\n", "", 0),
        })
        m = DataEncryptedCheck()
        result = m.check(session)
        assert result.status == Status.NOT_VULNERABLE


# ---------------------------------------------------------------------------
# T1565 — Data Manipulation
# ---------------------------------------------------------------------------


class TestDataManipulationCheck:
    def test_module_attributes(self):
        from modules.impact.T1565_data_manipulation import DataManipulationCheck
        m = DataManipulationCheck()
        assert m.TECHNIQUE_ID == "T1565"
        assert m.TACTIC == Tactic.IMPACT

    def test_check_no_integrity_monitoring(self):
        from modules.impact.T1565_data_manipulation import DataManipulationCheck
        session = make_session({
            "rpm -q aide": CommandResult("package aide is not installed", "", 1),
            "rpm -q tripwire": CommandResult("package tripwire is not installed", "", 1),
            "update-crypto-policies --show": CommandResult("DEFAULT\n", "", 0),
            "/proc/sys/kernel/yama/ptrace_scope": CommandResult("0\n", "", 0),
        })
        m = DataManipulationCheck()
        result = m.check(session)
        assert result.status == Status.VULNERABLE
        titles = [f.title for f in result.findings]
        assert any("integrity" in t.lower() for t in titles)
        assert any("ptrace" in t.lower() for t in titles)

    def test_check_writable_configs(self):
        from modules.impact.T1565_data_manipulation import DataManipulationCheck
        session = make_session({
            "rpm -q aide": CommandResult("aide-0.16-1.el9.x86_64", "", 0),
            "test -f /var/lib/aide/aide.db.gz": CommandResult("exists", "", 0),
            "/etc/passwd": CommandResult("/etc/passwd", "", 0),
            "/etc/shadow": CommandResult("", "", 1),
            "/etc/hosts": CommandResult("", "", 1),
            "/etc/resolv.conf": CommandResult("", "", 1),
            "/etc/sudoers": CommandResult("", "", 1),
            "update-crypto-policies --show": CommandResult("FUTURE\n", "", 0),
            "/proc/sys/kernel/yama/ptrace_scope": CommandResult("1\n", "", 0),
        })
        m = DataManipulationCheck()
        result = m.check(session)
        assert result.status == Status.VULNERABLE
        titles = [f.title for f in result.findings]
        assert any("/etc/passwd" in t for t in titles)


# ---------------------------------------------------------------------------
# T1489 — Service Stop
# ---------------------------------------------------------------------------


class TestServiceStopCheck:
    def test_module_attributes(self):
        from modules.impact.T1489_service_stop import ServiceStopCheck
        m = ServiceStopCheck()
        assert m.TECHNIQUE_ID == "T1489"
        assert m.TACTIC == Tactic.IMPACT

    def test_check_no_restart_policy(self):
        from modules.impact.T1489_service_stop import ServiceStopCheck
        session = make_session({
            "systemctl is-active": CommandResult("active\n", "", 0),
            "systemctl show": CommandResult("Restart=no\n", "", 0),
            "sudo -n systemctl stop": CommandResult("a]password required", "", 1),
            "pkaction": CommandResult("auth_admin_keep\n", "", 0),
        })
        m = ServiceStopCheck()
        result = m.check(session)
        assert result.status == Status.VULNERABLE
        titles = [f.title for f in result.findings]
        assert any("restart" in t.lower() for t in titles)

    def test_check_clean(self):
        from modules.impact.T1489_service_stop import ServiceStopCheck
        session = make_session({
            "systemctl is-active": CommandResult("active\n", "", 0),
            "systemctl show": CommandResult("Restart=on-failure\n", "", 0),
            "sudo -n systemctl stop": CommandResult("password is required", "", 1),
            "pkaction": CommandResult("auth_admin\n", "", 0),
        })
        m = ServiceStopCheck()
        result = m.check(session)
        assert result.status == Status.NOT_VULNERABLE


# ---------------------------------------------------------------------------
# T1529 — System Shutdown/Reboot
# ---------------------------------------------------------------------------


class TestSystemShutdownCheck:
    def test_module_attributes(self):
        from modules.impact.T1529_system_shutdown import SystemShutdownCheck
        m = SystemShutdownCheck()
        assert m.TECHNIQUE_ID == "T1529"
        assert m.TACTIC == Tactic.IMPACT

    def test_check_ctrl_alt_del_not_masked(self):
        from modules.impact.T1529_system_shutdown import SystemShutdownCheck
        session = make_session({
            "sudo -n": CommandResult("password is required", "", 1),
            "pkaction": CommandResult("auth_admin\n", "", 0),
            "systemctl status ctrl-alt-del.target": CommandResult("loaded active\n", "", 0),
            "systemd-inhibit --list": CommandResult("", "", 0),
        })
        m = SystemShutdownCheck()
        result = m.check(session)
        assert result.status == Status.VULNERABLE
        titles = [f.title for f in result.findings]
        assert any("Ctrl-Alt-Del" in t for t in titles)


# ---------------------------------------------------------------------------
# T1490 — Inhibit System Recovery
# ---------------------------------------------------------------------------


class TestInhibitRecoveryCheck:
    def test_module_attributes(self):
        from modules.impact.T1490_inhibit_recovery import InhibitRecoveryCheck
        m = InhibitRecoveryCheck()
        assert m.TECHNIQUE_ID == "T1490"
        assert m.SEVERITY == Severity.CRITICAL

    def test_check_no_grub_password(self):
        from modules.impact.T1490_inhibit_recovery import InhibitRecoveryCheck
        session = make_session({
            "grep -c 'password_pbkdf2": CommandResult("0\n", "", 0),
            "systemctl is-enabled rescue": CommandResult("static\n", "", 0),
            "systemctl is-enabled emergency": CommandResult("static\n", "", 0),
            "grep -l 'sulogin'": CommandResult("", "", 1),
            "lvs": CommandResult("", "", 1),
            "test -d /var/backups": CommandResult("", "", 1),
            "test -d /backup": CommandResult("", "", 1),
            "test -d /mnt/backup": CommandResult("", "", 1),
            "systemctl is-active kdump": CommandResult("inactive\n", "", 0),
        })
        m = InhibitRecoveryCheck()
        result = m.check(session)
        assert result.status == Status.VULNERABLE
        titles = [f.title for f in result.findings]
        assert any("GRUB" in t for t in titles)


# ---------------------------------------------------------------------------
# T1531 — Account Access Removal
# ---------------------------------------------------------------------------


class TestAccountAccessRemovalCheck:
    def test_module_attributes(self):
        from modules.impact.T1531_account_access_removal import AccountAccessRemovalCheck
        m = AccountAccessRemovalCheck()
        assert m.TECHNIQUE_ID == "T1531"
        assert m.TACTIC == Tactic.IMPACT

    def test_check_overly_permissive_shadow(self):
        from modules.impact.T1531_account_access_removal import AccountAccessRemovalCheck
        session = make_session({
            "sudo -n": CommandResult("password is required", "", 1),
            "stat -c '%a' /etc/passwd": CommandResult("644\n", "", 0),
            "stat -c '%a' /etc/shadow": CommandResult("644\n", "", 0),
            "stat -c '%a' /etc/group": CommandResult("644\n", "", 0),
            "stat -c '%a' /etc/gshadow": CommandResult("000\n", "", 0),
            "grep -r 'pam_faillock": CommandResult("", "", 1),
            "find /home -name 'authorized_keys'": CommandResult("", "", 1),
        })
        m = AccountAccessRemovalCheck()
        result = m.check(session)
        assert result.status == Status.VULNERABLE
        titles = [f.title for f in result.findings]
        assert any("/etc/shadow" in t for t in titles)


# ---------------------------------------------------------------------------
# T1491 — Defacement
# ---------------------------------------------------------------------------


class TestDefacementCheck:
    def test_module_attributes(self):
        from modules.impact.T1491_defacement import DefacementCheck
        m = DefacementCheck()
        assert m.TECHNIQUE_ID == "T1491"
        assert m.TACTIC == Tactic.IMPACT

    def test_check_writable_web_root(self):
        from modules.impact.T1491_defacement import DefacementCheck
        session = make_session({
            "test -d /var/www/html": CommandResult("/var/www/html/index.html\n", "", 0),
            "/var/www/html": CommandResult("/var/www/html/index.html\n", "", 0),
            "test -d /var/www ": CommandResult("", "", 1),
            "test -d /usr/share/nginx/html": CommandResult("", "", 1),
            "test -d /srv/www": CommandResult("", "", 1),
            "test -d /opt/www": CommandResult("", "", 1),
            "ps -eo user,comm": CommandResult("", "", 1),
            "test -f /etc/motd": CommandResult("", "", 1),
            "test -f /etc/issue ": CommandResult("", "", 1),
            "test -f /etc/issue.net": CommandResult("", "", 1),
        })
        m = DefacementCheck()
        result = m.check(session)
        assert result.status == Status.VULNERABLE
        titles = [f.title for f in result.findings]
        assert any("web" in t.lower() or "Writable" in t for t in titles)


# ---------------------------------------------------------------------------
# T1561 — Disk Wipe
# ---------------------------------------------------------------------------


class TestDiskWipeCheck:
    def test_module_attributes(self):
        from modules.impact.T1561_disk_wipe import DiskWipeCheck
        m = DiskWipeCheck()
        assert m.TECHNIQUE_ID == "T1561"
        assert m.SEVERITY == Severity.CRITICAL

    def test_check_disk_tools(self):
        from modules.impact.T1561_disk_wipe import DiskWipeCheck
        session = make_session({
            "which dd": CommandResult("/usr/bin/dd", "", 0),
            "which shred": CommandResult("/usr/bin/shred", "", 0),
            "which wipefs": CommandResult("", "", 1),
            "which fdisk": CommandResult("", "", 1),
            "which parted": CommandResult("", "", 1),
            "which mkfs": CommandResult("", "", 1),
            "test -u": CommandResult("", "", 1),
            "ls -la /dev/sd": CommandResult("", "", 1),
            "/proc/sys/kernel/modules_disabled": CommandResult("0\n", "", 0),
            "/sys/block/sda/ro": CommandResult("0\n", "", 0),
        })
        m = DiskWipeCheck()
        result = m.check(session)
        assert result.status == Status.VULNERABLE
        titles = [f.title for f in result.findings]
        assert any("dd" in t for t in titles)


# ---------------------------------------------------------------------------
# T1499 — Endpoint Denial of Service
# ---------------------------------------------------------------------------


class TestEndpointDosCheck:
    def test_module_attributes(self):
        from modules.impact.T1499_endpoint_dos import EndpointDosCheck
        m = EndpointDosCheck()
        assert m.TECHNIQUE_ID == "T1499"
        assert m.TACTIC == Tactic.IMPACT

    def test_check_unlimited_nproc(self):
        from modules.impact.T1499_endpoint_dos import EndpointDosCheck
        session = make_session({
            "ulimit -u": CommandResult("unlimited\n", "", 0),
            "ulimit -n": CommandResult("1024\n", "", 0),
            "stat -f --format": CommandResult("cgroup2fs\n", "", 0),
            "systemctl show user": CommandResult("TasksMax=infinity\n", "", 0),
            "/proc/sys/vm/panic_on_oom": CommandResult("0\n", "", 0),
            "/proc/sys/vm/overcommit_memory": CommandResult("0\n", "", 0),
            "mount | grep ' /tmp '": CommandResult("/dev/sda1 on /tmp type ext4 (rw,nosuid,nodev,noexec)\n", "", 0),
            "sysctl -n net.core.somaxconn": CommandResult("4096\n", "", 0),
            "sysctl -n net.ipv4.tcp_max_syn_backlog": CommandResult("4096\n", "", 0),
        })
        m = EndpointDosCheck()
        result = m.check(session)
        assert result.status == Status.VULNERABLE
        titles = [f.title for f in result.findings]
        assert any("unlimited" in t.lower() or "nproc" in t.lower() or "processes" in t.lower() for t in titles)


# ---------------------------------------------------------------------------
# T1498 — Network Denial of Service
# ---------------------------------------------------------------------------


class TestNetworkDosCheck:
    def test_module_attributes(self):
        from modules.impact.T1498_network_dos import NetworkDosCheck
        m = NetworkDosCheck()
        assert m.TECHNIQUE_ID == "T1498"
        assert m.TACTIC == Tactic.IMPACT

    def test_check_syn_cookies_disabled(self):
        from modules.impact.T1498_network_dos import NetworkDosCheck
        session = make_session({
            "sysctl -n net.ipv4.tcp_syncookies": CommandResult("0\n", "", 0),
            "sysctl -n net.ipv4.icmp_echo_ignore_broadcasts": CommandResult("1\n", "", 0),
            "sysctl -n net.ipv4.icmp_ignore_bogus_error_responses": CommandResult("1\n", "", 0),
            "sysctl -n net.ipv4.conf.all.rp_filter": CommandResult("1\n", "", 0),
            "ss -tuln": CommandResult("LISTEN  0  128  0.0.0.0:22  0.0.0.0:*\n", "", 0),
            "firewall-cmd --state": CommandResult("running\n", "", 0),
            "firewall-cmd --list-rich-rules": CommandResult("", "", 0),
        })
        m = NetworkDosCheck()
        result = m.check(session)
        assert result.status == Status.VULNERABLE
        titles = [f.title for f in result.findings]
        assert any("SYN cookies" in t for t in titles)

    def test_check_clean(self):
        from modules.impact.T1498_network_dos import NetworkDosCheck
        session = make_session({
            "sysctl -n net.ipv4.tcp_syncookies": CommandResult("1\n", "", 0),
            "sysctl -n net.ipv4.icmp_echo_ignore_broadcasts": CommandResult("1\n", "", 0),
            "sysctl -n net.ipv4.icmp_ignore_bogus_error_responses": CommandResult("1\n", "", 0),
            "sysctl -n net.ipv4.conf.all.rp_filter": CommandResult("1\n", "", 0),
            "ss -tuln": CommandResult("LISTEN  0  128  0.0.0.0:22  0.0.0.0:*\n", "", 0),
            "firewall-cmd --state": CommandResult("running\n", "", 0),
            "firewall-cmd --list-rich-rules": CommandResult("rule limit value=10/m\n", "", 0),
        })
        m = NetworkDosCheck()
        result = m.check(session)
        assert result.status == Status.NOT_VULNERABLE


# ---------------------------------------------------------------------------
# T1496 — Resource Hijacking
# ---------------------------------------------------------------------------


class TestResourceHijackingCheck:
    def test_module_attributes(self):
        from modules.impact.T1496_resource_hijacking import ResourceHijackingCheck
        m = ResourceHijackingCheck()
        assert m.TECHNIQUE_ID == "T1496"
        assert m.TACTIC == Tactic.IMPACT

    def test_check_miner_detected(self):
        from modules.impact.T1496_resource_hijacking import ResourceHijackingCheck
        session = make_session({
            "xmrig": CommandResult("/tmp/xmrig", "", 0),
            "cpuminer": CommandResult("", "", 1),
            "minerd": CommandResult("", "", 1),
            "cgminer": CommandResult("", "", 1),
            "bfgminer": CommandResult("", "", 1),
            "ethminer": CommandResult("", "", 1),
            "nbminer": CommandResult("", "", 1),
            "t-rex": CommandResult("", "", 1),
            "ls /dev/nvidia": CommandResult("", "", 1),
            "systemctl show user": CommandResult("CPUQuota=\n", "", 0),
            "ps -eo pid,user,%cpu,comm": CommandResult("  PID USER     %CPU COMM\n  1 root      0.1 systemd\n", "", 0),
            "test -S /var/run/docker.sock": CommandResult("", "", 1),
        })
        m = ResourceHijackingCheck()
        result = m.check(session)
        assert result.status == Status.VULNERABLE
        titles = [f.title for f in result.findings]
        assert any("xmrig" in t.lower() for t in titles)


# ---------------------------------------------------------------------------
# T1495 — Firmware Corruption
# ---------------------------------------------------------------------------


class TestFirmwareCorruptionCheck:
    def test_module_attributes(self):
        from modules.impact.T1495_firmware_corruption import FirmwareCorruptionCheck
        m = FirmwareCorruptionCheck()
        assert m.TECHNIQUE_ID == "T1495"
        assert m.SEVERITY == Severity.CRITICAL

    def test_check_secure_boot_disabled(self):
        from modules.impact.T1495_firmware_corruption import FirmwareCorruptionCheck
        session = make_session({
            "mokutil --sb-state": CommandResult("SecureBoot disabled\n", "", 0),
            "which flashrom": CommandResult("", "", 1),
            "which dmidecode": CommandResult("/usr/sbin/dmidecode", "", 0),
            "which efibootmgr": CommandResult("", "", 1),
            "test -d /sys/firmware/efi/efivars": CommandResult("", "", 1),
            "systemctl is-active fwupd": CommandResult("inactive\n", "", 0),
        })
        m = FirmwareCorruptionCheck()
        result = m.check(session)
        assert result.status == Status.VULNERABLE
        titles = [f.title for f in result.findings]
        assert any("Secure Boot" in t for t in titles)


# ---------------------------------------------------------------------------
# T1657 — Financial Theft
# ---------------------------------------------------------------------------


class TestFinancialTheftCheck:
    def test_module_attributes(self):
        from modules.impact.T1657_financial_theft import FinancialTheftCheck
        m = FinancialTheftCheck()
        assert m.TECHNIQUE_ID == "T1657"
        assert m.SEVERITY == Severity.CRITICAL

    def test_check_db_creds_readable(self):
        from modules.impact.T1657_financial_theft import FinancialTheftCheck
        session = make_session({
            "find /etc /opt": CommandResult("", "", 1),
            ".pgpass": CommandResult("/home/admin/.pgpass\n", "", 0),
            ".my.cnf": CommandResult("", "", 1),
            ".dbshell": CommandResult("", "", 1),
            "ss -tuln": CommandResult("LISTEN  0  128  127.0.0.1:5432  0.0.0.0:*\n", "", 0),
            "env": CommandResult("HOME=/home/admin\nPATH=/usr/bin\n", "", 0),
        })
        m = FinancialTheftCheck()
        result = m.check(session)
        assert result.status == Status.VULNERABLE
        titles = [f.title for f in result.findings]
        assert any(".pgpass" in t for t in titles)

    def test_check_clean(self):
        from modules.impact.T1657_financial_theft import FinancialTheftCheck
        session = make_session({
            "ss -tuln": CommandResult("LISTEN  0  128  127.0.0.1:22  0.0.0.0:*\n", "", 0),
            "env": CommandResult("HOME=/home/admin\n", "", 0),
        })
        m = FinancialTheftCheck()
        result = m.check(session)
        assert result.status == Status.NOT_VULNERABLE


# ---------------------------------------------------------------------------
# T1667 — Email Bombing
# ---------------------------------------------------------------------------


class TestEmailBombingCheck:
    def test_module_attributes(self):
        from modules.impact.T1667_email_bombing import EmailBombingCheck
        m = EmailBombingCheck()
        assert m.TECHNIQUE_ID == "T1667"
        assert m.TACTIC == Tactic.IMPACT

    def test_check_open_smtp(self):
        from modules.impact.T1667_email_bombing import EmailBombingCheck
        session = make_session({
            "systemctl is-active postfix": CommandResult("active\n", "", 0),
            "systemctl is-active sendmail": CommandResult("inactive\n", "", 0),
            "systemctl is-active exim": CommandResult("inactive\n", "", 0),
            "ss -tuln": CommandResult("LISTEN  0  100  0.0.0.0:25  0.0.0.0:*\n", "", 0),
            "postconf inet_interfaces mynetworks": CommandResult(
                "inet_interfaces = all\nmynetworks = 127.0.0.0/8\n", "", 0,
            ),
            "grep -i 'relay'": CommandResult("", "", 1),
            "postconf smtpd_client_message_rate_limit": CommandResult(
                "smtpd_client_message_rate_limit = 0\nsmtpd_client_connection_rate_limit = 0\n", "", 0,
            ),
            "mailq": CommandResult("Mail queue is empty\n", "", 0),
        })
        m = EmailBombingCheck()
        result = m.check(session)
        assert result.status == Status.VULNERABLE
        titles = [f.title for f in result.findings]
        assert any("all interfaces" in t.lower() or "inet_interfaces" in t for t in titles)

    def test_check_clean(self):
        from modules.impact.T1667_email_bombing import EmailBombingCheck
        session = make_session({
            "systemctl is-active postfix": CommandResult("inactive\n", "", 0),
            "systemctl is-active sendmail": CommandResult("inactive\n", "", 0),
            "systemctl is-active exim": CommandResult("inactive\n", "", 0),
        })
        m = EmailBombingCheck()
        result = m.check(session)
        assert result.status == Status.NOT_VULNERABLE


# ---------------------------------------------------------------------------
# Cross-module: simulate delegates to check, mitigations non-empty
# ---------------------------------------------------------------------------


class TestImpactModulesCommon:
    MODULE_CLASSES = [
        ("modules.impact.T1485_data_destruction", "DataDestructionCheck"),
        ("modules.impact.T1486_data_encrypted", "DataEncryptedCheck"),
        ("modules.impact.T1565_data_manipulation", "DataManipulationCheck"),
        ("modules.impact.T1489_service_stop", "ServiceStopCheck"),
        ("modules.impact.T1529_system_shutdown", "SystemShutdownCheck"),
        ("modules.impact.T1490_inhibit_recovery", "InhibitRecoveryCheck"),
        ("modules.impact.T1531_account_access_removal", "AccountAccessRemovalCheck"),
        ("modules.impact.T1491_defacement", "DefacementCheck"),
        ("modules.impact.T1561_disk_wipe", "DiskWipeCheck"),
        ("modules.impact.T1499_endpoint_dos", "EndpointDosCheck"),
        ("modules.impact.T1498_network_dos", "NetworkDosCheck"),
        ("modules.impact.T1496_resource_hijacking", "ResourceHijackingCheck"),
        ("modules.impact.T1495_firmware_corruption", "FirmwareCorruptionCheck"),
        ("modules.impact.T1657_financial_theft", "FinancialTheftCheck"),
        ("modules.impact.T1667_email_bombing", "EmailBombingCheck"),
    ]

    def test_all_modules_have_mitigations(self):
        import importlib
        for mod_path, cls_name in self.MODULE_CLASSES:
            mod = importlib.import_module(mod_path)
            cls = getattr(mod, cls_name)
            instance = cls()
            mitigations = instance.get_mitigations()
            assert len(mitigations) > 0, f"{cls_name} has no mitigations"

    def test_all_modules_tactic_is_impact(self):
        import importlib
        for mod_path, cls_name in self.MODULE_CLASSES:
            mod = importlib.import_module(mod_path)
            cls = getattr(mod, cls_name)
            instance = cls()
            assert instance.TACTIC == Tactic.IMPACT, f"{cls_name} tactic is not IMPACT"

    def test_all_modules_safe_mode(self):
        import importlib
        for mod_path, cls_name in self.MODULE_CLASSES:
            mod = importlib.import_module(mod_path)
            cls = getattr(mod, cls_name)
            instance = cls()
            assert instance.SAFE_MODE is True, f"{cls_name} SAFE_MODE is not True"

    def test_simulate_delegates_to_check(self):
        import importlib
        for mod_path, cls_name in self.MODULE_CLASSES:
            mod = importlib.import_module(mod_path)
            cls = getattr(mod, cls_name)
            instance = cls()
            session = make_session({})
            check_result = instance.check(session)
            simulate_result = instance.simulate(session)
            assert check_result.status == simulate_result.status, (
                f"{cls_name} simulate() does not delegate to check()"
            )

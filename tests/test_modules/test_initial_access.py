"""Tests for initial access modules (TA0001)."""

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


class TestContentInjectionCheck:
    def test_attributes(self):
        from modules.initial_access.T1659_content_injection import ContentInjectionCheck
        m = ContentInjectionCheck()
        assert m.TECHNIQUE_ID == "T1659"
        assert m.TACTIC == Tactic.INITIAL_ACCESS

    def test_writable_web_content(self):
        from modules.initial_access.T1659_content_injection import ContentInjectionCheck
        session = make_session({
            "test -d /var/www/html": CommandResult("/var/www/html/index.html\n", "", 0),
            "/var/www/html": CommandResult("/var/www/html/index.html\n", "", 0),
            "Content-Security-Policy": CommandResult("", "", 1),
            "cgi-bin": CommandResult("", "", 1),
        })
        m = ContentInjectionCheck()
        result = m.check(session)
        assert result.status == Status.VULNERABLE

    def test_clean(self):
        from modules.initial_access.T1659_content_injection import ContentInjectionCheck
        m = ContentInjectionCheck()
        result = m.check(make_session({}))
        assert result.status == Status.NOT_VULNERABLE


class TestDrivebyCompromiseCheck:
    def test_attributes(self):
        from modules.initial_access.T1189_driveby_compromise import DrivebyCompromiseCheck
        m = DrivebyCompromiseCheck()
        assert m.TECHNIQUE_ID == "T1189"
        assert m.TACTIC == Tactic.INITIAL_ACCESS

    def test_outdated_web_server(self):
        from modules.initial_access.T1189_driveby_compromise import DrivebyCompromiseCheck
        session = make_session({
            "rpm -q httpd": CommandResult("httpd-2.4.37-47.el8.x86_64\n", "", 0),
            "rpm -q nginx": CommandResult("package nginx is not installed\n", "", 1),
            "dnf check-update httpd": CommandResult("httpd.x86_64  2.4.37-51.el8  baseos\n", "", 0),
            "ss -tuln": CommandResult("", "", 1),
            "grep -ri 'Options.*Indexes'": CommandResult("", "", 1),
        })
        m = DrivebyCompromiseCheck()
        result = m.check(session)
        assert result.status == Status.VULNERABLE
        assert any("updates" in f.title.lower() for f in result.findings)


class TestExploitPublicAppCheck:
    def test_attributes(self):
        from modules.initial_access.T1190_exploit_public_app import ExploitPublicAppCheck
        m = ExploitPublicAppCheck()
        assert m.TECHNIQUE_ID == "T1190"
        assert m.SEVERITY == Severity.CRITICAL

    def test_pending_security_advisories(self):
        from modules.initial_access.T1190_exploit_public_app import ExploitPublicAppCheck
        session = make_session({
            "dnf updateinfo": CommandResult("5\n", "", 0),
            "ss -tuln": CommandResult("", "", 1),
            "getenforce": CommandResult("Enforcing\n", "", 0),
        })
        m = ExploitPublicAppCheck()
        result = m.check(session)
        assert result.status == Status.VULNERABLE

    def test_selinux_disabled(self):
        from modules.initial_access.T1190_exploit_public_app import ExploitPublicAppCheck
        session = make_session({
            "dnf updateinfo": CommandResult("0\n", "", 0),
            "ss -tuln": CommandResult("", "", 1),
            "getenforce": CommandResult("Permissive\n", "", 0),
        })
        m = ExploitPublicAppCheck()
        result = m.check(session)
        assert result.status == Status.VULNERABLE


class TestExternalRemoteServicesCheck:
    def test_attributes(self):
        from modules.initial_access.T1133_external_remote_services import ExternalRemoteServicesCheck
        m = ExternalRemoteServicesCheck()
        assert m.TECHNIQUE_ID == "T1133"

    def test_ssh_root_login(self):
        from modules.initial_access.T1133_external_remote_services import ExternalRemoteServicesCheck
        session = make_session({
            "PermitRootLogin": CommandResult("PermitRootLogin yes\n", "", 0),
            "PasswordAuthentication": CommandResult("PasswordAuthentication no\n", "", 0),
            "^Port": CommandResult("Port 22\n", "", 0),
            "systemctl is-active openvpn": CommandResult("inactive\n", "", 0),
            "systemctl is-active wireguard": CommandResult("inactive\n", "", 0),
            "systemctl is-active strongswan": CommandResult("inactive\n", "", 0),
            "ss -tuln": CommandResult("", "", 1),
        })
        m = ExternalRemoteServicesCheck()
        result = m.check(session)
        assert result.status == Status.VULNERABLE
        assert any("root login" in f.title.lower() for f in result.findings)


class TestHardwareAdditionsCheck:
    def test_attributes(self):
        from modules.initial_access.T1200_hardware_additions import HardwareAdditionsCheck
        m = HardwareAdditionsCheck()
        assert m.TECHNIQUE_ID == "T1200"

    def test_no_usbguard(self):
        from modules.initial_access.T1200_hardware_additions import HardwareAdditionsCheck
        session = make_session({
            "systemctl is-active usbguard": CommandResult("inactive\n", "", 0),
            "authorized_default": CommandResult("1\n", "", 0),
            "thunderbolt": CommandResult("", "", 1),
        })
        m = HardwareAdditionsCheck()
        result = m.check(session)
        assert result.status == Status.VULNERABLE


class TestPhishingCheck:
    def test_attributes(self):
        from modules.initial_access.T1566_phishing import PhishingCheck
        m = PhishingCheck()
        assert m.TECHNIQUE_ID == "T1566"

    def test_no_content_filter(self):
        from modules.initial_access.T1566_phishing import PhishingCheck
        session = make_session({
            "postconf content_filter": CommandResult("content_filter =\n", "", 0),
            "systemctl is-active opendkim": CommandResult("inactive\n", "", 0),
            "systemctl is-active opendmarc": CommandResult("inactive\n", "", 0),
            "systemctl is-active postfix": CommandResult("active\n", "", 0),
            "systemctl is-active sendmail": CommandResult("inactive\n", "", 0),
            "systemctl is-active clamav-milter": CommandResult("inactive\n", "", 0),
            "systemctl is-active clamd": CommandResult("inactive\n", "", 0),
        })
        m = PhishingCheck()
        result = m.check(session)
        assert result.status == Status.VULNERABLE


class TestSupplyChainCheck:
    def test_attributes(self):
        from modules.initial_access.T1195_supply_chain import SupplyChainCheck
        m = SupplyChainCheck()
        assert m.TECHNIQUE_ID == "T1195"
        assert m.SEVERITY == Severity.CRITICAL

    def test_gpgcheck_disabled(self):
        from modules.initial_access.T1195_supply_chain import SupplyChainCheck
        session = make_session({
            "grep -r 'gpgcheck'": CommandResult("epel.repo:gpgcheck=0\n", "", 0),
            "grep 'gpgcheck' /etc/dnf/dnf.conf": CommandResult("", "", 1),
            "dnf repolist": CommandResult("", "", 1),
            "rpm -qa": CommandResult("", "", 1),
        })
        m = SupplyChainCheck()
        result = m.check(session)
        assert result.status == Status.VULNERABLE
        assert any("GPG" in f.title for f in result.findings)


class TestTrustedRelationshipCheck:
    def test_attributes(self):
        from modules.initial_access.T1199_trusted_relationship import TrustedRelationshipCheck
        m = TrustedRelationshipCheck()
        assert m.TECHNIQUE_ID == "T1199"

    def test_rhosts_found(self):
        from modules.initial_access.T1199_trusted_relationship import TrustedRelationshipCheck
        session = make_session({
            "find /home /root -name 'authorized_keys'": CommandResult("", "", 1),
            "cat /etc/exports": CommandResult("", "", 1),
            "grep -i 'subdomains_provider": CommandResult("", "", 1),
            ".rhosts": CommandResult("/home/admin/.rhosts\n", "", 0),
        })
        m = TrustedRelationshipCheck()
        result = m.check(session)
        assert result.status == Status.VULNERABLE
        assert any("rhosts" in f.title.lower() for f in result.findings)


class TestValidAccountsCheck:
    def test_attributes(self):
        from modules.initial_access.T1078_valid_accounts import ValidAccountsCheck
        m = ValidAccountsCheck()
        assert m.TECHNIQUE_ID == "T1078"

    def test_default_account_with_shell(self):
        from modules.initial_access.T1078_valid_accounts import ValidAccountsCheck
        session = make_session({
            "id admin": CommandResult("uid=1001(admin) gid=1001(admin)\n", "", 0),
            "id guest": CommandResult("", "", 1),
            "id test": CommandResult("", "", 1),
            "id user": CommandResult("", "", 1),
            "id oracle": CommandResult("", "", 1),
            "id postgres": CommandResult("", "", 1),
            "id mysql": CommandResult("", "", 1),
            "id ftp": CommandResult("", "", 1),
            "id operator": CommandResult("", "", 1),
            "getent passwd admin": CommandResult("admin:x:1001:1001::/home/admin:/bin/bash\n", "", 0),
            "PASS_MAX_DAYS": CommandResult("PASS_MAX_DAYS 99999\n", "", 0),
            "lastlog": CommandResult("", "", 1),
            "awk -F:": CommandResult("", "", 1),
        })
        m = ValidAccountsCheck()
        result = m.check(session)
        assert result.status == Status.VULNERABLE


class TestWifiNetworksCheck:
    def test_attributes(self):
        from modules.initial_access.T1669_wifi_networks import WifiNetworksCheck
        m = WifiNetworksCheck()
        assert m.TECHNIQUE_ID == "T1669"

    def test_clean_no_wifi(self):
        from modules.initial_access.T1669_wifi_networks import WifiNetworksCheck
        m = WifiNetworksCheck()
        result = m.check(make_session({}))
        assert result.status == Status.NOT_VULNERABLE


class TestInitialAccessCommon:
    MODULE_CLASSES = [
        ("modules.initial_access.T1659_content_injection", "ContentInjectionCheck"),
        ("modules.initial_access.T1189_driveby_compromise", "DrivebyCompromiseCheck"),
        ("modules.initial_access.T1190_exploit_public_app", "ExploitPublicAppCheck"),
        ("modules.initial_access.T1133_external_remote_services", "ExternalRemoteServicesCheck"),
        ("modules.initial_access.T1200_hardware_additions", "HardwareAdditionsCheck"),
        ("modules.initial_access.T1566_phishing", "PhishingCheck"),
        ("modules.initial_access.T1195_supply_chain", "SupplyChainCheck"),
        ("modules.initial_access.T1199_trusted_relationship", "TrustedRelationshipCheck"),
        ("modules.initial_access.T1078_valid_accounts", "ValidAccountsCheck"),
        ("modules.initial_access.T1669_wifi_networks", "WifiNetworksCheck"),
    ]

    def test_all_tactic_is_initial_access(self):
        for mod_path, cls_name in self.MODULE_CLASSES:
            mod = importlib.import_module(mod_path)
            cls = getattr(mod, cls_name)
            assert cls().TACTIC == Tactic.INITIAL_ACCESS, f"{cls_name} tactic wrong"

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

    def test_simulate_delegates(self):
        for mod_path, cls_name in self.MODULE_CLASSES:
            mod = importlib.import_module(mod_path)
            cls = getattr(mod, cls_name)
            instance = cls()
            session = make_session({})
            assert instance.check(session).status == instance.simulate(session).status

"""Tests for credential access modules."""

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


class TestCredentialDumping:
    def test_module_attributes(self):
        from modules.credential_access.T1003_credential_dumping import CredentialDumpingCheck
        m = CredentialDumpingCheck()
        assert m.TECHNIQUE_ID == "T1003"
        assert m.TACTIC == Tactic.CREDENTIAL_ACCESS
        assert m.SEVERITY == Severity.CRITICAL
        assert m.SAFE_MODE is True

    def test_detects_readable_shadow(self):
        from modules.credential_access.T1003_credential_dumping import CredentialDumpingCheck
        session = make_session({
            "test -r /etc/shadow": CommandResult("readable", "", 0),
            "head -3 /etc/shadow": CommandResult("$6$salt$hash", "", 0),
            "test -r /etc/gshadow": CommandResult("", "", 1),
            "test -r /proc/1/maps": CommandResult("", "", 1),
            "cat /proc/self/environ": CommandResult("", "", 1),
            "find /var/lib/sss": CommandResult("", "", 1),
            "find /tmp -name": CommandResult("", "", 1),
            "grep": CommandResult("", "", 1),
        })
        m = CredentialDumpingCheck()
        result = m.check(session)
        critical = [f for f in result.findings if f.severity == Severity.CRITICAL]
        assert len(critical) >= 1
        assert any("/etc/shadow" in f.title for f in critical)

    def test_detects_md5_hashes(self):
        from modules.credential_access.T1003_credential_dumping import CredentialDumpingCheck
        session = make_session({
            "test -r /etc/shadow": CommandResult("readable", "", 0),
            "head -3 /etc/shadow": CommandResult("$1$salt$hash", "", 0),
            "test -r /etc/gshadow": CommandResult("", "", 1),
            "test -r /proc/1/maps": CommandResult("", "", 1),
            "cat /proc/self/environ": CommandResult("", "", 1),
            "find /var/lib/sss": CommandResult("", "", 1),
            "find /tmp -name": CommandResult("", "", 1),
            "grep": CommandResult("", "", 1),
        })
        m = CredentialDumpingCheck()
        result = m.check(session)
        md5 = [f for f in result.findings if "MD5" in f.title]
        assert len(md5) >= 1


class TestUnsecuredCredentials:
    def test_module_attributes(self):
        from modules.credential_access.T1552_unsecured_credentials import UnsecuredCredentialsCheck
        m = UnsecuredCredentialsCheck()
        assert m.TECHNIQUE_ID == "T1552"
        assert m.TACTIC == Tactic.CREDENTIAL_ACCESS


class TestBruteForce:
    def test_module_attributes(self):
        from modules.credential_access.T1110_brute_force import BruteForceCheck
        m = BruteForceCheck()
        assert m.TECHNIQUE_ID == "T1110"

    def test_detects_no_lockout(self):
        from modules.credential_access.T1110_brute_force import BruteForceCheck
        session = make_session({
            "grep -r 'pam_faillock'": CommandResult("", "", 1),
            "grep -r 'pam_tally2'": CommandResult("", "", 1),
            "grep -i 'MaxAuthTries'": CommandResult("", "", 1),
            "systemctl is-active fail2ban": CommandResult("inactive", "", 1),
            "grep -r 'pam_faildelay'": CommandResult("", "", 1),
        })
        m = BruteForceCheck()
        result = m.check(session)
        lockout = [f for f in result.findings if "lockout" in f.title.lower()]
        assert len(lockout) >= 1


class TestModifyAuth:
    def test_module_attributes(self):
        from modules.credential_access.T1556_modify_auth import ModifyAuthCheck
        m = ModifyAuthCheck()
        assert m.TECHNIQUE_ID == "T1556"
        assert m.SEVERITY == Severity.CRITICAL

    def test_detects_pam_permit(self):
        from modules.credential_access.T1556_modify_auth import ModifyAuthCheck
        session = make_session({
            "grep -rh 'pam_.*\\.so'": CommandResult("pam_unix.so\npam_permit.so", "", 0),
            "grep -rn 'auth.*sufficient.*pam_permit'": CommandResult(
                "/etc/pam.d/test:3:auth sufficient pam_permit.so", "", 0
            ),
            "find /etc/pam.d -writable": CommandResult("", "", 1),
            "rpm -V pam": CommandResult("", "", 0),
            "grep -rn 'auth.*sufficient.*pam_rootok'": CommandResult("", "", 1),
            "grep -n 'pam_wheel'": CommandResult("", "", 1),
        })
        m = ModifyAuthCheck()
        result = m.check(session)
        critical = [f for f in result.findings if f.severity == Severity.CRITICAL]
        assert len(critical) >= 1


class TestAiTM:
    def test_module_attributes(self):
        from modules.credential_access.T1557_aitm import AiTMCheck
        m = AiTMCheck()
        assert m.TECHNIQUE_ID == "T1557"


class TestCredentialStores:
    def test_module_attributes(self):
        from modules.credential_access.T1555_credential_stores import CredentialStoresCheck
        m = CredentialStoresCheck()
        assert m.TECHNIQUE_ID == "T1555"


class TestKerberosTickets:
    def test_module_attributes(self):
        from modules.credential_access.T1558_kerberos_tickets import KerberosTicketsCheck
        m = KerberosTicketsCheck()
        assert m.TECHNIQUE_ID == "T1558"

    def test_detects_file_ccache(self):
        from modules.credential_access.T1558_kerberos_tickets import KerberosTicketsCheck
        session = make_session({
            "find /tmp -name 'krb5cc_*'": CommandResult("/tmp/krb5cc_1000\n/tmp/krb5cc_0", "", 0),
            "grep -i 'default_ccache_name'": CommandResult("default_ccache_name = FILE:/tmp/krb5cc_%{uid}", "", 0),
            "test -r /etc/krb5.keytab": CommandResult("", "", 1),
            "klist": CommandResult("No credentials cache", "", 1),
        })
        m = KerberosTicketsCheck()
        result = m.check(session)
        assert result.finding_count >= 2


class TestInputCapture:
    def test_module_attributes(self):
        from modules.credential_access.T1056_input_capture import InputCaptureCheck
        m = InputCaptureCheck()
        assert m.TECHNIQUE_ID == "T1056"


class TestExploitCredAccess:
    def test_module_attributes(self):
        from modules.credential_access.T1212_exploit_cred_access import ExploitCredAccessCheck
        m = ExploitCredAccessCheck()
        assert m.TECHNIQUE_ID == "T1212"


class TestForgeCredentials:
    def test_module_attributes(self):
        from modules.credential_access.T1606_forge_credentials import ForgeCredentialsCheck
        m = ForgeCredentialsCheck()
        assert m.TECHNIQUE_ID == "T1606"


class TestAuthCertificates:
    def test_module_attributes(self):
        from modules.credential_access.T1649_auth_certificates import AuthCertificatesCheck
        m = AuthCertificatesCheck()
        assert m.TECHNIQUE_ID == "T1649"


class TestWebSessionCookie:
    def test_module_attributes(self):
        from modules.credential_access.T1539_web_session_cookie import WebSessionCookieCheck
        m = WebSessionCookieCheck()
        assert m.TECHNIQUE_ID == "T1539"


class TestMFAInterception:
    def test_module_attributes(self):
        from modules.credential_access.T1111_mfa_interception import MFAInterceptionCheck
        m = MFAInterceptionCheck()
        assert m.TECHNIQUE_ID == "T1111"


class TestMFARequestGen:
    def test_module_attributes(self):
        from modules.credential_access.T1621_mfa_request_gen import MFARequestGenCheck
        m = MFARequestGenCheck()
        assert m.TECHNIQUE_ID == "T1621"

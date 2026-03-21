"""Tests for lateral movement modules."""

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
# T1021 — Remote Services
# ---------------------------------------------------------------------------


class TestRemoteServicesCheck:
    def test_module_attributes(self):
        from modules.lateral_movement.T1021_remote_services import RemoteServicesCheck
        m = RemoteServicesCheck()
        assert m.TECHNIQUE_ID == "T1021"
        assert m.TACTIC == Tactic.LATERAL_MOVEMENT
        assert m.SAFE_MODE is True

    def test_check_ssh_root_login(self):
        from modules.lateral_movement.T1021_remote_services import RemoteServicesCheck
        session = make_session({
            "cat /etc/ssh/sshd_config": CommandResult(
                "PermitRootLogin yes\nPasswordAuthentication yes\n"
                "AllowAgentForwarding yes\nX11Forwarding yes\n",
                "", 0,
            ),
            "grep -i '^Ciphers'": CommandResult("", "", 1),
            "find /home -name 'authorized_keys'": CommandResult("", "", 1),
            "testparm": CommandResult("", "", 1),
            "cat /etc/exports": CommandResult("", "", 1),
            "systemctl is-active vncserver": CommandResult("inactive", "", 3),
            "systemctl is-active xrdp": CommandResult("inactive", "", 3),
            "systemctl is-active xvnc": CommandResult("inactive", "", 3),
            "systemctl is-active rsh": CommandResult("inactive", "", 3),
            "systemctl is-active rlogin": CommandResult("inactive", "", 3),
            "systemctl is-active rexec": CommandResult("inactive", "", 3),
            "find /home -name '.vnc'": CommandResult("", "", 1),
            "find /home -name '.rhosts'": CommandResult("", "", 1),
        })
        m = RemoteServicesCheck()
        result = m.check(session)
        assert result.status == Status.VULNERABLE
        titles = [f.title for f in result.findings]
        assert any("root login" in t for t in titles)
        assert any("password authentication" in t.lower() for t in titles)
        assert any("agent forwarding" in t.lower() for t in titles)

    def test_check_nfs_no_root_squash(self):
        from modules.lateral_movement.T1021_remote_services import RemoteServicesCheck
        session = make_session({
            "cat /etc/ssh/sshd_config": CommandResult("PermitRootLogin no\n", "", 0),
            "grep -i '^Ciphers'": CommandResult("", "", 1),
            "find /home -name 'authorized_keys'": CommandResult("", "", 1),
            "testparm": CommandResult("", "", 1),
            "cat /etc/exports": CommandResult(
                "/data *(rw,no_root_squash)\n/shared 10.0.0.0/24(rw)\n",
                "", 0,
            ),
            "systemctl is-active vncserver": CommandResult("inactive", "", 3),
            "systemctl is-active xrdp": CommandResult("inactive", "", 3),
            "systemctl is-active xvnc": CommandResult("inactive", "", 3),
            "systemctl is-active rsh": CommandResult("inactive", "", 3),
            "systemctl is-active rlogin": CommandResult("inactive", "", 3),
            "systemctl is-active rexec": CommandResult("inactive", "", 3),
            "find /home -name '.vnc'": CommandResult("", "", 1),
            "find /home -name '.rhosts'": CommandResult("", "", 1),
        })
        m = RemoteServicesCheck()
        result = m.check(session)
        assert result.status == Status.VULNERABLE
        titles = [f.title for f in result.findings]
        assert any("NFS export" in t for t in titles)
        assert any("dangerous options" in t.lower() for t in titles)

    def test_check_legacy_rsh(self):
        from modules.lateral_movement.T1021_remote_services import RemoteServicesCheck
        session = make_session({
            "cat /etc/ssh/sshd_config": CommandResult("PermitRootLogin no\n", "", 0),
            "grep -i '^Ciphers'": CommandResult("", "", 1),
            "find /home -name 'authorized_keys'": CommandResult("", "", 1),
            "testparm": CommandResult("", "", 1),
            "cat /etc/exports": CommandResult("", "", 1),
            "systemctl is-active vncserver": CommandResult("inactive", "", 3),
            "systemctl is-active xrdp": CommandResult("inactive", "", 3),
            "systemctl is-active xvnc": CommandResult("inactive", "", 3),
            "systemctl is-active rsh": CommandResult("active", "", 0),
            "systemctl is-active rlogin": CommandResult("inactive", "", 3),
            "systemctl is-active rexec": CommandResult("inactive", "", 3),
            "find /home -name '.vnc'": CommandResult("", "", 1),
            "find /home -name '.rhosts'": CommandResult(
                "/home/admin/.rhosts\n", "", 0,
            ),
        })
        m = RemoteServicesCheck()
        result = m.check(session)
        assert result.status == Status.VULNERABLE
        titles = [f.title for f in result.findings]
        assert any("Legacy remote service" in t for t in titles)
        assert any(".rhosts" in t for t in titles)

    def test_check_secure_config(self):
        from modules.lateral_movement.T1021_remote_services import RemoteServicesCheck
        session = make_session({
            "cat /etc/ssh/sshd_config": CommandResult(
                "PermitRootLogin no\nPasswordAuthentication no\n"
                "AllowAgentForwarding no\nX11Forwarding no\n",
                "", 0,
            ),
            "grep -i '^Ciphers'": CommandResult("", "", 1),
            "find /home -name 'authorized_keys'": CommandResult("", "", 1),
            "testparm": CommandResult("", "", 1),
            "cat /etc/exports": CommandResult("", "", 1),
            "systemctl is-active vncserver": CommandResult("inactive", "", 3),
            "systemctl is-active xrdp": CommandResult("inactive", "", 3),
            "systemctl is-active xvnc": CommandResult("inactive", "", 3),
            "systemctl is-active rsh": CommandResult("inactive", "", 3),
            "systemctl is-active rlogin": CommandResult("inactive", "", 3),
            "systemctl is-active rexec": CommandResult("inactive", "", 3),
            "find /home -name '.vnc'": CommandResult("", "", 1),
            "find /home -name '.rhosts'": CommandResult("", "", 1),
        })
        m = RemoteServicesCheck()
        result = m.check(session)
        assert result.status == Status.NOT_VULNERABLE


# ---------------------------------------------------------------------------
# T1550 — Use Alternate Authentication Material
# ---------------------------------------------------------------------------


class TestUseAlternateAuthCheck:
    def test_module_attributes(self):
        from modules.lateral_movement.T1550_use_alternate_auth import UseAlternateAuthCheck
        m = UseAlternateAuthCheck()
        assert m.TECHNIQUE_ID == "T1550"
        assert m.TACTIC == Tactic.LATERAL_MOVEMENT
        assert m.SAFE_MODE is True

    def test_check_pass_the_hash(self):
        from modules.lateral_movement.T1550_use_alternate_auth import UseAlternateAuthCheck
        session = make_session({
            "test -f /var/lib/samba/private/passdb.tdb": CommandResult("exists", "", 0),
            "test -r /var/lib/samba/private/passdb.tdb": CommandResult("readable", "", 0),
            "grep -r 'auth_provider": CommandResult("", "", 1),
            "find /tmp -name 'krb5cc_*'": CommandResult(
                "/tmp/krb5cc_1000\n/tmp/krb5cc_0\n", "", 0,
            ),
            "grep -i 'default_ccache_name'": CommandResult(
                "default_ccache_name = FILE:/tmp/krb5cc_%{uid}", "", 0,
            ),
            "find / -name '*.keytab'": CommandResult("", "", 1),
            "find /home -name 'id_*' -not -name '*.pub' -perm": CommandResult(
                "/home/user/.ssh/id_rsa\n", "", 0,
            ),
            "find /home -name 'id_*' -not -name '*.pub' -exec": CommandResult("", "", 1),
            "find /home -path '*/.docker/config.json'": CommandResult("", "", 1),
            "find /var/run/secrets": CommandResult("", "", 1),
        })
        m = UseAlternateAuthCheck()
        result = m.check(session)
        assert result.status == Status.VULNERABLE
        titles = [f.title for f in result.findings]
        assert any("Samba password database" in t for t in titles)
        assert any("Kerberos ticket" in t for t in titles)

    def test_check_keytab_accessible(self):
        from modules.lateral_movement.T1550_use_alternate_auth import UseAlternateAuthCheck
        session = make_session({
            "test -f /var/lib/samba/private/passdb.tdb": CommandResult("", "", 1),
            "grep -r 'auth_provider": CommandResult("", "", 1),
            "find /tmp -name 'krb5cc_*'": CommandResult("", "", 1),
            "grep -i 'default_ccache_name'": CommandResult("", "", 1),
            "test -f /etc/krb5.conf": CommandResult("", "", 1),
            "find / -name '*.keytab'": CommandResult(
                "/opt/app/service.keytab\n", "", 0,
            ),
            "find /home -name 'id_*' -not -name '*.pub' -perm": CommandResult("", "", 1),
            "find /home -name 'id_*' -not -name '*.pub' -exec": CommandResult("", "", 1),
            "find /home -path '*/.docker/config.json'": CommandResult("", "", 1),
            "find /var/run/secrets": CommandResult("", "", 1),
        })
        m = UseAlternateAuthCheck()
        result = m.check(session)
        assert result.status == Status.VULNERABLE
        titles = [f.title for f in result.findings]
        assert any("keytab" in t.lower() for t in titles)


# ---------------------------------------------------------------------------
# T1570 — Lateral Tool Transfer
# ---------------------------------------------------------------------------


class TestLateralToolTransferCheck:
    def test_module_attributes(self):
        from modules.lateral_movement.T1570_lateral_tool_transfer import LateralToolTransferCheck
        m = LateralToolTransferCheck()
        assert m.TECHNIQUE_ID == "T1570"
        assert m.TACTIC == Tactic.LATERAL_MOVEMENT
        assert m.SAFE_MODE is True

    def test_check_finds_transfer_tools(self):
        from modules.lateral_movement.T1570_lateral_tool_transfer import LateralToolTransferCheck
        session = make_session({
            "which scp": CommandResult("/usr/bin/scp", "", 0),
            "which rsync": CommandResult("/usr/bin/rsync", "", 0),
            "which curl": CommandResult("/usr/bin/curl", "", 0),
            "which wget": CommandResult("/usr/bin/wget", "", 0),
            "which nc": CommandResult("/usr/bin/nc", "", 0),
            "which ncat": CommandResult("/usr/bin/ncat", "", 0),
            "which socat": CommandResult("/usr/bin/socat", "", 0),
            "which ftp": CommandResult("", "", 1),
            "which tftp": CommandResult("", "", 1),
            "which sftp": CommandResult("/usr/bin/sftp", "", 0),
            "test -d /srv/samba": CommandResult("", "", 1),
            "test -d /srv/nfs": CommandResult("", "", 1),
            "test -d /export": CommandResult("", "", 1),
            "test -d /shared": CommandResult("", "", 1),
            "grep -i 'Subsystem.*sftp'": CommandResult(
                "Subsystem sftp /usr/libexec/openssh/sftp-server", "", 0,
            ),
        })
        m = LateralToolTransferCheck()
        result = m.check(session)
        assert result.status == Status.VULNERABLE
        titles = [f.title for f in result.findings]
        assert any("transfer tools available" in t.lower() for t in titles)
        assert any("High-risk" in t for t in titles)

    def test_check_clean_system(self):
        from modules.lateral_movement.T1570_lateral_tool_transfer import LateralToolTransferCheck
        session = make_session({})  # all commands return failure
        m = LateralToolTransferCheck()
        result = m.check(session)
        assert result.status == Status.NOT_VULNERABLE


# ---------------------------------------------------------------------------
# T1210 — Exploitation of Remote Services
# ---------------------------------------------------------------------------


class TestExploitRemoteServicesCheck:
    def test_attributes(self):
        from modules.lateral_movement.T1210_exploit_remote import ExploitRemoteServicesCheck
        m = ExploitRemoteServicesCheck()
        assert m.TECHNIQUE_ID == "T1210"
        assert m.TACTIC == Tactic.LATERAL_MOVEMENT

    def test_exposed_management(self):
        from modules.lateral_movement.T1210_exploit_remote import ExploitRemoteServicesCheck
        session = make_session({
            "pgrep -x sshd": CommandResult("", "", 1),
            "pgrep -x httpd": CommandResult("", "", 1),
            "pgrep -x smbd": CommandResult("", "", 1),
            "pgrep -x named": CommandResult("", "", 1),
            "ss -tuln": CommandResult("LISTEN 0 5 0.0.0.0:9090 0.0.0.0:*\n", "", 0),
            "firewall-cmd --get-active-zones": CommandResult("public\n  interfaces: eth0\n", "", 0),
        })
        m = ExploitRemoteServicesCheck()
        result = m.check(session)
        assert result.status == Status.VULNERABLE


# ---------------------------------------------------------------------------
# T1534 — Internal Spearphishing
# ---------------------------------------------------------------------------


class TestInternalSpearphishingCheck:
    def test_attributes(self):
        from modules.lateral_movement.T1534_internal_spearphishing import InternalSpearphishingCheck
        m = InternalSpearphishingCheck()
        assert m.TECHNIQUE_ID == "T1534"

    def test_mail_client_available(self):
        from modules.lateral_movement.T1534_internal_spearphishing import InternalSpearphishingCheck
        session = make_session({
            "postconf mynetworks": CommandResult("", "", 1),
            "which mail": CommandResult("/usr/bin/mail\n", "", 0),
            "which sendmail": CommandResult("", "", 1),
            "which mutt": CommandResult("", "", 1),
            "getent passwd": CommandResult("3\n", "", 0),
            "'/bin/bash": CommandResult("root\nadmin\nuser\n", "", 0),
        })
        m = InternalSpearphishingCheck()
        result = m.check(session)
        assert result.status == Status.VULNERABLE


# ---------------------------------------------------------------------------
# T1563 — Remote Service Session Hijacking
# ---------------------------------------------------------------------------


class TestSessionHijackingCheck:
    def test_attributes(self):
        from modules.lateral_movement.T1563_session_hijacking import SessionHijackingCheck
        m = SessionHijackingCheck()
        assert m.TECHNIQUE_ID == "T1563"

    def test_agent_forwarding_enabled(self):
        from modules.lateral_movement.T1563_session_hijacking import SessionHijackingCheck
        session = make_session({
            "AllowAgentForwarding": CommandResult("AllowAgentForwarding yes\n", "", 0),
            "find /home /root -name 'config'": CommandResult("", "", 1),
            "find /tmp -name 'tmux": CommandResult("", "", 1),
            "find /tmp -name 'screen": CommandResult("", "", 1),
            "find /tmp -name 'ssh-": CommandResult("", "", 1),
        })
        m = SessionHijackingCheck()
        result = m.check(session)
        assert result.status == Status.VULNERABLE


# ---------------------------------------------------------------------------
# T1072 — Software Deployment Tools
# ---------------------------------------------------------------------------


class TestSoftwareDeploymentCheck:
    def test_attributes(self):
        from modules.lateral_movement.T1072_software_deployment import SoftwareDeploymentCheck
        m = SoftwareDeploymentCheck()
        assert m.TECHNIQUE_ID == "T1072"

    def test_ansible_with_inventory(self):
        from modules.lateral_movement.T1072_software_deployment import SoftwareDeploymentCheck
        session = make_session({
            "which ansible": CommandResult("/usr/bin/ansible\n", "", 0),
            "find /etc/ansible /home": CommandResult("/etc/ansible/hosts\n", "", 0),
            "head -5": CommandResult("[webservers]\n192.168.1.10\n", "", 0),
            "systemctl is-active puppet": CommandResult("inactive\n", "", 0),
            "systemctl is-active salt-minion": CommandResult("inactive\n", "", 0),
            "which chef-client": CommandResult("", "", 1),
        })
        m = SoftwareDeploymentCheck()
        result = m.check(session)
        assert result.status == Status.VULNERABLE


# ---------------------------------------------------------------------------
# T1080 — Taint Shared Content
# ---------------------------------------------------------------------------


class TestTaintSharedContentCheck:
    def test_attributes(self):
        from modules.lateral_movement.T1080_taint_shared_content import TaintSharedContentCheck
        m = TaintSharedContentCheck()
        assert m.TECHNIQUE_ID == "T1080"

    def test_nfs_no_root_squash(self):
        from modules.lateral_movement.T1080_taint_shared_content import TaintSharedContentCheck
        session = make_session({
            "cat /etc/exports": CommandResult("/export *(rw,no_root_squash)\n", "", 0),
            "testparm -s": CommandResult("", "", 1),
            "mount -t nfs": CommandResult("", "", 1),
        })
        m = TaintSharedContentCheck()
        result = m.check(session)
        assert result.status == Status.VULNERABLE
        assert any("no_root_squash" in f.title for f in result.findings)

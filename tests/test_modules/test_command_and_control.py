"""Tests for command and control modules."""

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
# T1071 — Application Layer Protocol
# ---------------------------------------------------------------------------


class TestApplicationLayerProtocolCheck:
    def test_module_attributes(self):
        from modules.command_and_control.T1071_application_layer_protocol import (
            ApplicationLayerProtocolCheck,
        )
        m = ApplicationLayerProtocolCheck()
        assert m.TECHNIQUE_ID == "T1071"
        assert m.TACTIC == Tactic.COMMAND_AND_CONTROL
        assert m.SAFE_MODE is True

    def test_check_unrestricted_egress(self):
        from modules.command_and_control.T1071_application_layer_protocol import (
            ApplicationLayerProtocolCheck,
        )
        session = make_session({
            "firewall-cmd": CommandResult("", "", 1),
            "iptables -L OUTPUT -n": CommandResult(
                "Chain OUTPUT (policy ACCEPT)\n"
                "target     prot opt source               destination\n"
                "ACCEPT     all  --  0.0.0.0/0            0.0.0.0/0\n",
                "", 0,
            ),
            "which curl": CommandResult("/usr/bin/curl", "", 0),
            "which wget": CommandResult("/usr/bin/wget", "", 0),
            "which openssl": CommandResult("/usr/bin/openssl", "", 0),
            "which dig": CommandResult("/usr/bin/dig", "", 0),
            "which nslookup": CommandResult("/usr/bin/nslookup", "", 0),
            "which dnscat2": CommandResult("", "", 1),
            "which iodine": CommandResult("", "", 1),
            "which host": CommandResult("/usr/bin/host", "", 0),
            "grep -r 'log-queries": CommandResult("", "", 1),
            "cat /etc/resolv.conf": CommandResult(
                "nameserver 8.8.8.8\nnameserver 8.8.4.4\n", "", 0,
            ),
            "systemctl is-active postfix": CommandResult("active", "", 0),
            "systemctl is-active sendmail": CommandResult("inactive", "", 3),
            "systemctl is-active exim": CommandResult("inactive", "", 3),
            "which mail": CommandResult("/usr/bin/mail", "", 0),
            "ss -tnp state established": CommandResult(
                "ESTAB  0  0  10.0.0.5:43210  203.0.113.5:4444  users:((\"suspicious\",pid=1234))\n",
                "", 0,
            ),
            "env | grep": CommandResult("", "", 1),
        })
        m = ApplicationLayerProtocolCheck()
        result = m.check(session)
        assert result.status == Status.VULNERABLE
        titles = [f.title for f in result.findings]
        assert any("Unrestricted outbound" in t for t in titles)
        assert any("HTTP client" in t for t in titles)
        assert any("non-standard ports" in t.lower() for t in titles)

    def test_check_dns_tunneling_tools(self):
        from modules.command_and_control.T1071_application_layer_protocol import (
            ApplicationLayerProtocolCheck,
        )
        session = make_session({
            "iptables -L OUTPUT -n": CommandResult("", "", 1),
            "which curl": CommandResult("", "", 1),
            "which wget": CommandResult("", "", 1),
            "which openssl": CommandResult("", "", 1),
            "which dig": CommandResult("", "", 1),
            "which nslookup": CommandResult("", "", 1),
            "which host": CommandResult("", "", 1),
            "which dnscat2": CommandResult("/usr/local/bin/dnscat2", "", 0),
            "which iodine": CommandResult("/usr/local/bin/iodine", "", 0),
            "grep -r 'log-queries": CommandResult("", "", 1),
            "cat /etc/resolv.conf": CommandResult("nameserver 127.0.0.1\n", "", 0),
            "systemctl is-active postfix": CommandResult("inactive", "", 3),
            "systemctl is-active sendmail": CommandResult("inactive", "", 3),
            "systemctl is-active exim": CommandResult("inactive", "", 3),
            "which mail": CommandResult("", "", 1),
            "ss -tnp state established": CommandResult("", "", 0),
            "env | grep": CommandResult("", "", 1),
        })
        m = ApplicationLayerProtocolCheck()
        result = m.check(session)
        assert result.status == Status.VULNERABLE
        titles = [f.title for f in result.findings]
        assert any("DNS tunneling" in t for t in titles)
        # DNS tunneling tools should be CRITICAL
        critical = [f for f in result.findings if f.severity == Severity.CRITICAL]
        assert len(critical) >= 1


# ---------------------------------------------------------------------------
# T1573 — Encrypted Channel
# ---------------------------------------------------------------------------


class TestEncryptedChannelCheck:
    def test_module_attributes(self):
        from modules.command_and_control.T1573_encrypted_channel import EncryptedChannelCheck
        m = EncryptedChannelCheck()
        assert m.TECHNIQUE_ID == "T1573"
        assert m.TACTIC == Tactic.COMMAND_AND_CONTROL
        assert m.SAFE_MODE is True

    def test_check_vpn_and_tunnels(self):
        from modules.command_and_control.T1573_encrypted_channel import EncryptedChannelCheck
        session = make_session({
            "which stunnel": CommandResult("/usr/bin/stunnel", "", 0),
            "which openssl": CommandResult("/usr/bin/openssl", "", 0),
            "ncat --help": CommandResult("ssl", "", 0),
            "which openvpn": CommandResult("/usr/sbin/openvpn", "", 0),
            "systemctl is-active openvpn": CommandResult("active", "", 0),
            "which wireguard": CommandResult("", "", 1),
            "which wg-quick": CommandResult("", "", 1),
            "ip link show type tun": CommandResult(
                "4: tun0: <POINTOPOINT,MULTICAST,NOARP,UP> mtu 1500\n", "", 0,
            ),
            "ps aux": CommandResult(
                "root  1234  0.0  ssh -L 8080:internal:80 user@remote\n", "", 0,
            ),
            "grep -i 'GatewayPorts yes'": CommandResult(
                "GatewayPorts yes", "", 0,
            ),
            "python3 -c": CommandResult("", "", 1),
        })
        m = EncryptedChannelCheck()
        result = m.check(session)
        assert result.status == Status.VULNERABLE
        titles = [f.title for f in result.findings]
        assert any("stunnel" in t for t in titles)
        assert any("TUN/TAP" in t for t in titles)
        assert any("SSH tunnels" in t for t in titles)
        assert any("GatewayPorts" in t for t in titles)

    def test_check_clean_system(self):
        from modules.command_and_control.T1573_encrypted_channel import EncryptedChannelCheck
        session = make_session({
            "which stunnel": CommandResult("", "", 1),
            "which openssl": CommandResult("", "", 1),
            "ncat --help": CommandResult("", "", 1),
            "which openvpn": CommandResult("", "", 1),
            "which wireguard": CommandResult("", "", 1),
            "which wg-quick": CommandResult("", "", 1),
            "ip link show type tun": CommandResult("", "", 0),
            "ps aux": CommandResult("", "", 0),
            "grep -i 'GatewayPorts yes'": CommandResult("", "", 1),
            "python3 -c": CommandResult("", "", 1),
        })
        m = EncryptedChannelCheck()
        result = m.check(session)
        assert result.status == Status.NOT_VULNERABLE


# ---------------------------------------------------------------------------
# T1090 — Proxy
# ---------------------------------------------------------------------------


class TestProxyCheck:
    def test_module_attributes(self):
        from modules.command_and_control.T1090_proxy import ProxyCheck
        m = ProxyCheck()
        assert m.TECHNIQUE_ID == "T1090"
        assert m.TACTIC == Tactic.COMMAND_AND_CONTROL
        assert m.SAFE_MODE is True

    def test_check_proxy_tools(self):
        from modules.command_and_control.T1090_proxy import ProxyCheck
        session = make_session({
            "which proxychains": CommandResult("/usr/bin/proxychains", "", 0),
            "which proxychains4": CommandResult("", "", 1),
            "which tsocks": CommandResult("", "", 1),
            "which redsocks": CommandResult("", "", 1),
            "which 3proxy": CommandResult("", "", 1),
            "which chisel": CommandResult("/usr/local/bin/chisel", "", 0),
            "which ligolo": CommandResult("", "", 1),
            "test -f /etc/proxychains.conf": CommandResult("exists", "", 0),
            "test -f /etc/proxychains4.conf": CommandResult("", "", 1),
            "grep -v '^#' /etc/proxychains.conf": CommandResult(
                "socks4 127.0.0.1 9050\n", "", 0,
            ),
            "ss -tlnp": CommandResult("", "", 1),
            "systemctl is-active tor": CommandResult("inactive", "", 3),
            "sysctl net.ipv4.ip_forward": CommandResult(
                "net.ipv4.ip_forward = 1", "", 0,
            ),
            "iptables -t nat -L": CommandResult(
                "MASQUERADE  all  --  10.0.0.0/24  0.0.0.0/0\n", "", 0,
            ),
            "systemctl is-active nginx": CommandResult("inactive", "", 3),
            "systemctl is-active haproxy": CommandResult("inactive", "", 3),
            "systemctl is-active squid": CommandResult("inactive", "", 3),
            "systemctl is-active apache2": CommandResult("inactive", "", 3),
            "systemctl is-active httpd": CommandResult("inactive", "", 3),
        })
        m = ProxyCheck()
        result = m.check(session)
        assert result.status == Status.VULNERABLE
        titles = [f.title for f in result.findings]
        assert any("proxychains" in t.lower() for t in titles)
        assert any("chisel" in t.lower() for t in titles)
        assert any("IP forwarding" in t for t in titles)
        assert any("NAT" in t for t in titles)

    def test_check_tor_active(self):
        from modules.command_and_control.T1090_proxy import ProxyCheck
        session = make_session({
            "which proxychains": CommandResult("", "", 1),
            "which proxychains4": CommandResult("", "", 1),
            "which tsocks": CommandResult("", "", 1),
            "which redsocks": CommandResult("", "", 1),
            "which 3proxy": CommandResult("", "", 1),
            "which chisel": CommandResult("", "", 1),
            "which ligolo": CommandResult("", "", 1),
            "test -f /etc/proxychains.conf": CommandResult("", "", 1),
            "test -f /etc/proxychains4.conf": CommandResult("", "", 1),
            "ss -tlnp": CommandResult("", "", 1),
            "systemctl is-active tor": CommandResult("active", "", 0),
            "sysctl net.ipv4.ip_forward": CommandResult(
                "net.ipv4.ip_forward = 0", "", 0,
            ),
            "iptables -t nat -L": CommandResult("", "", 1),
            "systemctl is-active nginx": CommandResult("inactive", "", 3),
            "systemctl is-active haproxy": CommandResult("inactive", "", 3),
            "systemctl is-active squid": CommandResult("inactive", "", 3),
            "systemctl is-active apache2": CommandResult("inactive", "", 3),
            "systemctl is-active httpd": CommandResult("inactive", "", 3),
        })
        m = ProxyCheck()
        result = m.check(session)
        assert result.status == Status.VULNERABLE
        titles = [f.title for f in result.findings]
        assert any("Tor" in t for t in titles)
        critical = [f for f in result.findings if f.severity == Severity.CRITICAL]
        assert len(critical) >= 1

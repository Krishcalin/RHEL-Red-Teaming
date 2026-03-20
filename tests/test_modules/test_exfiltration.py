"""Tests for exfiltration modules."""

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
# T1048 — Exfiltration Over Alternative Protocol
# ---------------------------------------------------------------------------


class TestExfiltrationAltProtocolCheck:
    def test_module_attributes(self):
        from modules.exfiltration.T1048_exfiltration_over_alternative_protocol import (
            ExfiltrationAltProtocolCheck,
        )
        m = ExfiltrationAltProtocolCheck()
        assert m.TECHNIQUE_ID == "T1048"
        assert m.TACTIC == Tactic.EXFILTRATION
        assert m.SAFE_MODE is True

    def test_check_dns_tunneling_tools(self):
        from modules.exfiltration.T1048_exfiltration_over_alternative_protocol import (
            ExfiltrationAltProtocolCheck,
        )
        session = make_session({
            "which iodine": CommandResult("/usr/local/bin/iodine", "", 0),
            "which dnscat2": CommandResult("", "", 1),
            "which dns2tcp": CommandResult("", "", 1),
            "which dig": CommandResult("/usr/bin/dig", "", 0),
            "which ping": CommandResult("/usr/bin/ping", "", 0),
            "iptables -L OUTPUT": CommandResult("", "", 1),
            "which ptunnel": CommandResult("", "", 1),
            "which icmpsh": CommandResult("", "", 1),
            "which hans": CommandResult("", "", 1),
            "which ftp": CommandResult("", "", 1),
            "which lftp": CommandResult("", "", 1),
            "which tftp": CommandResult("", "", 1),
            "which tar": CommandResult("/usr/bin/tar", "", 0),
            "which gzip": CommandResult("/usr/bin/gzip", "", 0),
            "which bzip2": CommandResult("", "", 1),
            "which xz": CommandResult("", "", 1),
            "which zip": CommandResult("", "", 1),
            "which 7z": CommandResult("", "", 1),
            "which base64": CommandResult("/usr/bin/base64", "", 0),
            "which xxd": CommandResult("", "", 1),
            "which ntpdate": CommandResult("", "", 1),
            "which chronyc": CommandResult("", "", 1),
        })
        m = ExfiltrationAltProtocolCheck()
        result = m.check(session)
        assert result.status == Status.VULNERABLE
        titles = [f.title for f in result.findings]
        assert any("iodine" in t for t in titles)
        critical = [f for f in result.findings if f.severity == Severity.CRITICAL]
        assert len(critical) >= 1

    def test_check_icmp_tunneling(self):
        from modules.exfiltration.T1048_exfiltration_over_alternative_protocol import (
            ExfiltrationAltProtocolCheck,
        )
        session = make_session({
            "which iodine": CommandResult("", "", 1),
            "which dnscat2": CommandResult("", "", 1),
            "which dns2tcp": CommandResult("", "", 1),
            "which dig": CommandResult("", "", 1),
            "which ping": CommandResult("/usr/bin/ping", "", 0),
            "iptables -L OUTPUT": CommandResult("", "", 1),
            "which ptunnel": CommandResult("/usr/local/bin/ptunnel", "", 0),
            "which icmpsh": CommandResult("", "", 1),
            "which hans": CommandResult("", "", 1),
            "which ftp": CommandResult("", "", 1),
            "which lftp": CommandResult("", "", 1),
            "which tftp": CommandResult("", "", 1),
            "which tar": CommandResult("", "", 1),
            "which gzip": CommandResult("", "", 1),
            "which bzip2": CommandResult("", "", 1),
            "which xz": CommandResult("", "", 1),
            "which zip": CommandResult("", "", 1),
            "which 7z": CommandResult("", "", 1),
            "which base64": CommandResult("", "", 1),
            "which xxd": CommandResult("", "", 1),
            "which ntpdate": CommandResult("", "", 1),
            "which chronyc": CommandResult("", "", 1),
        })
        m = ExfiltrationAltProtocolCheck()
        result = m.check(session)
        assert result.status == Status.VULNERABLE
        titles = [f.title for f in result.findings]
        assert any("ICMP tunneling" in t for t in titles)

    def test_check_clean_system(self):
        from modules.exfiltration.T1048_exfiltration_over_alternative_protocol import (
            ExfiltrationAltProtocolCheck,
        )
        session = make_session({})
        m = ExfiltrationAltProtocolCheck()
        result = m.check(session)
        assert result.status == Status.NOT_VULNERABLE


# ---------------------------------------------------------------------------
# T1041 — Exfiltration Over C2 Channel
# ---------------------------------------------------------------------------


class TestExfiltrationOverC2Check:
    def test_module_attributes(self):
        from modules.exfiltration.T1041_exfiltration_over_c2 import ExfiltrationOverC2Check
        m = ExfiltrationOverC2Check()
        assert m.TECHNIQUE_ID == "T1041"
        assert m.TACTIC == Tactic.EXFILTRATION
        assert m.SAFE_MODE is True

    def test_check_http_tools_and_staging(self):
        from modules.exfiltration.T1041_exfiltration_over_c2 import ExfiltrationOverC2Check
        session = make_session({
            "which curl": CommandResult("/usr/bin/curl", "", 0),
            "which wget": CommandResult("/usr/bin/wget", "", 0),
            "python3 -c": CommandResult("2.31.0", "", 0),
            "which scp": CommandResult("/usr/bin/scp", "", 0),
            "which ssh": CommandResult("/usr/bin/ssh", "", 0),
            "grep -i 'AllowTcpForwarding no'": CommandResult("", "", 1),
            "find /tmp -type f -size": CommandResult(
                "/tmp/database_dump.sql\n", "", 0,
            ),
            "find /var/tmp -type f -size": CommandResult("", "", 1),
            "find /dev/shm -type f -size": CommandResult("", "", 1),
            "find /tmp /var/tmp /dev/shm -type f": CommandResult(
                "/tmp/backup.tar.gz\n/tmp/data.zip\n", "", 0,
            ),
            "tc qdisc show": CommandResult("", "", 1),
            "auditctl -l": CommandResult(
                "No rules\n", "", 0,
            ),
        })
        m = ExfiltrationOverC2Check()
        result = m.check(session)
        assert result.status == Status.VULNERABLE
        titles = [f.title for f in result.findings]
        assert any("curl" in t for t in titles)
        assert any("wget" in t for t in titles)
        assert any("TCP forwarding" in t.lower() for t in titles)
        assert any("Large files" in t or "Archive files" in t for t in titles)

    def test_check_no_auditd(self):
        from modules.exfiltration.T1041_exfiltration_over_c2 import ExfiltrationOverC2Check
        session = make_session({
            "which curl": CommandResult("", "", 1),
            "which wget": CommandResult("", "", 1),
            "python3 -c": CommandResult("", "", 1),
            "which scp": CommandResult("", "", 1),
            "which ssh": CommandResult("", "", 1),
            "grep -i 'AllowTcpForwarding no'": CommandResult("", "", 1),
            "find /tmp -type f -size": CommandResult("", "", 1),
            "find /var/tmp -type f -size": CommandResult("", "", 1),
            "find /dev/shm -type f -size": CommandResult("", "", 1),
            "find /tmp /var/tmp /dev/shm -type f": CommandResult("", "", 1),
            "tc qdisc show": CommandResult("", "", 1),
            "auditctl -l": CommandResult("", "", 1),
        })
        m = ExfiltrationOverC2Check()
        result = m.check(session)
        assert result.status == Status.VULNERABLE
        titles = [f.title for f in result.findings]
        assert any("Auditd" in t or "auditd" in t for t in titles)

    def test_check_secure_config(self):
        from modules.exfiltration.T1041_exfiltration_over_c2 import ExfiltrationOverC2Check
        session = make_session({
            "which curl": CommandResult("", "", 1),
            "which wget": CommandResult("", "", 1),
            "python3 -c": CommandResult("", "", 1),
            "which scp": CommandResult("", "", 1),
            "which ssh": CommandResult("", "", 1),
            "find /tmp -type f -size": CommandResult("", "", 1),
            "find /var/tmp -type f -size": CommandResult("", "", 1),
            "find /dev/shm -type f -size": CommandResult("", "", 1),
            "find /tmp /var/tmp /dev/shm -type f": CommandResult("", "", 1),
            "tc qdisc show": CommandResult("qdisc fq 0: root\n", "", 0),
            "auditctl -l": CommandResult(
                "-w /etc/shadow -p r -k cred_access\n"
                "-w /etc/passwd -p wa -k identity\n",
                "", 0,
            ),
        })
        m = ExfiltrationOverC2Check()
        result = m.check(session)
        assert result.status == Status.NOT_VULNERABLE

"""T1041 — Exfiltration Over C2 Channel.

Checks for conditions that enable data exfiltration over the same channel
used for command and control — typically HTTP/S, SSH, or DNS.
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class ExfiltrationOverC2Check(BaseModule):
    TECHNIQUE_ID = "T1041"
    TECHNIQUE_NAME = "Exfiltration Over C2 Channel"
    TACTIC = Tactic.EXFILTRATION
    SEVERITY = Severity.HIGH
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        self._check_http_exfil(session)
        self._check_ssh_exfil(session)
        self._check_data_staging(session)
        self._check_egress_controls(session)
        self._check_dlp(session)

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def _check_http_exfil(self, session: Session) -> None:
        """Check HTTP/S exfiltration capabilities over C2 channel."""
        # curl with POST capability (data upload)
        curl = session.execute("which curl 2>/dev/null")
        if curl.success and curl.output.strip():
            self.add_finding(
                title="curl available for HTTP data exfiltration",
                description="curl can POST arbitrary data to external HTTP/S endpoints",
                severity=Severity.MEDIUM,
                evidence=curl.output.strip(),
                remediation="Remove curl if not required; monitor outbound HTTP POST requests",
            )

        # wget with POST
        wget = session.execute("which wget 2>/dev/null")
        if wget.success and wget.output.strip():
            self.add_finding(
                title="wget available for HTTP data exfiltration",
                description="wget can upload files via HTTP POST",
                severity=Severity.MEDIUM,
                evidence=wget.output.strip(),
                remediation="Remove wget if not required",
            )

        # Python requests-style upload
        py_requests = session.execute(
            "python3 -c 'import requests; print(requests.__version__)' 2>/dev/null"
        )
        if py_requests.success and py_requests.output.strip():
            self.add_finding(
                title=f"Python requests library: v{py_requests.output.strip()}",
                description="Python requests enables scripted HTTP data exfiltration",
                severity=Severity.LOW,
                evidence=f"requests {py_requests.output.strip()}",
            )

    def _check_ssh_exfil(self, session: Session) -> None:
        """Check SSH-based exfiltration capabilities."""
        # SCP/SFTP for file transfer
        scp = session.execute("which scp 2>/dev/null")
        if scp.success and scp.output.strip():
            self.add_finding(
                title="SCP available for SSH-based file exfiltration",
                description="SCP can transfer files over existing SSH connections",
                severity=Severity.LOW,
                evidence=scp.output.strip(),
            )

        # Reverse SSH tunnel capability
        ssh = session.execute("which ssh 2>/dev/null")
        if ssh.success and ssh.output.strip():
            # Check if AllowTcpForwarding is restricted
            tcp_fwd = session.execute(
                "grep -i 'AllowTcpForwarding no' /etc/ssh/sshd_config 2>/dev/null"
            )
            if not tcp_fwd.success or not tcp_fwd.output.strip():
                self.add_finding(
                    title="SSH TCP forwarding not disabled",
                    description="SSH tunnels can exfiltrate data through the C2 channel",
                    severity=Severity.MEDIUM,
                    evidence="AllowTcpForwarding is not set to 'no'",
                    remediation="Set 'AllowTcpForwarding no' in /etc/ssh/sshd_config",
                )

    def _check_data_staging(self, session: Session) -> None:
        """Check for data staging areas that precede exfiltration."""
        staging_dirs = ["/tmp", "/var/tmp", "/dev/shm"]
        for d in staging_dirs:
            # Check for large files that could be staged data
            large_files = session.execute(
                f"find {d} -type f -size +10M -newer /etc/hostname 2>/dev/null | head -5"
            )
            if large_files.success and large_files.output.strip():
                count = len(large_files.output.strip().splitlines())
                self.add_finding(
                    title=f"Large files in staging directory {d}: {count}",
                    description=f"Large recently-created files in {d} may indicate data staging",
                    severity=Severity.MEDIUM,
                    evidence=large_files.output.strip(),
                    remediation=f"Investigate files in {d}; apply noexec and size quotas",
                )

        # Check for archives in temp directories
        archives = session.execute(
            "find /tmp /var/tmp /dev/shm -type f \\( "
            "-name '*.tar*' -o -name '*.zip' -o -name '*.7z' "
            "-o -name '*.gz' -o -name '*.bz2' -o -name '*.xz' "
            "\\) 2>/dev/null | head -10"
        )
        if archives.success and archives.output.strip():
            self.add_finding(
                title="Archive files found in temporary directories",
                description="Compressed archives in temp dirs may indicate data staging for exfiltration",
                severity=Severity.MEDIUM,
                evidence=archives.output.strip(),
                remediation="Investigate archive contents; implement tmpwatch/systemd-tmpfiles cleanup",
            )

    def _check_egress_controls(self, session: Session) -> None:
        """Check if egress controls limit data exfiltration volume."""
        # Check outbound bandwidth limits
        tc_rules = session.execute("tc qdisc show 2>/dev/null | grep -v 'noqueue'")
        if not tc_rules.success or not tc_rules.output.strip():
            self.add_finding(
                title="No outbound traffic shaping configured",
                description="No bandwidth limits on outbound traffic — large exfiltration goes unthrottled",
                severity=Severity.LOW,
                evidence="No tc qdisc rules found",
                remediation="Implement egress traffic shaping with tc or firewall rules",
            )

    def _check_dlp(self, session: Session) -> None:
        """Check for DLP (Data Loss Prevention) controls."""
        # Check auditd for file access monitoring
        audit_rules = session.execute("auditctl -l 2>/dev/null")
        if audit_rules.success and audit_rules.output.strip():
            rules = audit_rules.output.strip()
            if "watch" not in rules.lower() and "-w" not in rules:
                self.add_finding(
                    title="Auditd has no file watch rules",
                    description="No file access monitoring — exfiltration of sensitive files goes undetected",
                    severity=Severity.MEDIUM,
                    evidence="No -w (watch) rules in auditctl -l",
                    remediation="Add audit watches on sensitive directories: "
                                "auditctl -w /etc/shadow -p r -k cred_access",
                )
        else:
            self.add_finding(
                title="Auditd not running or no rules configured",
                description="Without auditd, file access and data movement is not monitored",
                severity=Severity.HIGH,
                evidence="auditctl -l returned no output",
                remediation="Enable auditd and configure file access rules",
            )

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Remove unnecessary HTTP clients (curl, wget) from production servers",
            "Disable SSH TCP forwarding: AllowTcpForwarding no",
            "Monitor temporary directories for data staging (large files, archives)",
            "Implement egress traffic shaping and bandwidth limits",
            "Deploy auditd file watch rules on sensitive directories",
            "Use outbound proxy with content inspection",
            "Implement DLP controls to detect sensitive data leaving the network",
        ]

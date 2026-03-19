"""T1046 — Network Service Discovery.

Checks for exposed network services and open ports.
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule

HIGH_RISK_PORTS = {
    "21": "FTP",
    "23": "Telnet",
    "25": "SMTP",
    "53": "DNS",
    "80": "HTTP",
    "110": "POP3",
    "111": "RPCbind",
    "135": "MSRPC",
    "139": "NetBIOS",
    "143": "IMAP",
    "389": "LDAP",
    "443": "HTTPS",
    "445": "SMB",
    "513": "rlogin",
    "514": "rsh",
    "873": "rsync",
    "1433": "MSSQL",
    "1521": "Oracle",
    "2049": "NFS",
    "3306": "MySQL",
    "3389": "RDP",
    "5432": "PostgreSQL",
    "5900": "VNC",
    "6379": "Redis",
    "8080": "HTTP-Alt",
    "8443": "HTTPS-Alt",
    "9200": "Elasticsearch",
    "27017": "MongoDB",
}


class NetworkServiceDiscoveryCheck(BaseModule):
    TECHNIQUE_ID = "T1046"
    TECHNIQUE_NAME = "Network Service Discovery"
    TACTIC = Tactic.DISCOVERY
    SEVERITY = Severity.MEDIUM
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        # Check listening services with ss
        ss_result = session.execute("ss -tulnp 2>/dev/null")
        if ss_result.success and ss_result.output:
            listeners = []
            for line in ss_result.output.splitlines()[1:]:  # skip header
                parts = line.split()
                if len(parts) >= 5:
                    proto = parts[0]
                    local_addr = parts[4]
                    process = parts[6] if len(parts) > 6 else ""
                    listeners.append(f"{proto} {local_addr} {process}")

            if listeners:
                self.add_finding(
                    title=f"Listening services discovered: {len(listeners)}",
                    description="Network services are active and listening",
                    severity=Severity.INFO,
                    evidence="\n".join(listeners[:30]),
                )

            # Check for services on all interfaces (0.0.0.0 or *)
            exposed = []
            for line in ss_result.output.splitlines()[1:]:
                parts = line.split()
                if len(parts) >= 5:
                    addr = parts[4]
                    if addr.startswith("0.0.0.0:") or addr.startswith("*:") or addr.startswith(":::"):
                        port = addr.rsplit(":", 1)[-1]
                        svc = HIGH_RISK_PORTS.get(port, "Unknown")
                        exposed.append(f"Port {port} ({svc}) — {addr}")

            if exposed:
                self.add_finding(
                    title=f"Services exposed on all interfaces: {len(exposed)}",
                    description="Services bound to 0.0.0.0 or :: are reachable from any network",
                    severity=Severity.MEDIUM,
                    evidence="\n".join(exposed),
                    remediation="Bind services to specific interfaces; use firewalld to restrict access",
                )

        # Check for high-risk services
        risky_services = ["telnet", "rsh", "rlogin", "rexec", "ftp"]
        for svc in risky_services:
            check = session.execute(f"ss -tlnp 2>/dev/null | grep -i {svc}")
            if check.success and check.output.strip():
                self.add_finding(
                    title=f"Insecure service running: {svc}",
                    description=f"{svc} is a legacy insecure protocol that should be replaced",
                    severity=Severity.HIGH,
                    evidence=check.output.strip(),
                    remediation=f"Disable {svc} and use SSH instead",
                )

        # Check if nmap is available (tool availability for attackers)
        nmap = session.execute("which nmap 2>/dev/null")
        if nmap.success and nmap.output.strip():
            self.add_finding(
                title="nmap is installed",
                description="Network scanning tool is available on this system",
                severity=Severity.LOW,
                evidence=nmap.output.strip(),
                remediation="Remove nmap unless required for operations",
            )

        # Check firewall status
        fw = session.execute("firewall-cmd --state 2>/dev/null")
        if fw.success and fw.output.strip() == "running":
            zones = session.execute("firewall-cmd --list-all 2>/dev/null")
            if zones.success:
                self.add_finding(
                    title="Firewalld active — zone configuration",
                    description="Firewall is running; zone details collected",
                    severity=Severity.INFO,
                    evidence=zones.output[:800],
                )
        else:
            self.add_finding(
                title="Firewall is not running",
                description="firewalld is not active — no host-level firewall protection",
                severity=Severity.HIGH,
                evidence=fw.output.strip() if fw.output else "firewall-cmd not found or not running",
                remediation="Enable and configure firewalld: systemctl enable --now firewalld",
            )

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Enable and configure firewalld with restrictive default zone",
            "Disable legacy services (telnet, rsh, ftp) and use SSH",
            "Bind services to specific interfaces instead of 0.0.0.0",
            "Remove unnecessary network scanning tools (nmap, masscan)",
            "Use SELinux to confine network-facing services",
        ]

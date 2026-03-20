"""T1071 — Application Layer Protocol.

Checks for outbound communication channels that could be used for C2:
- T1071.001 Web Protocols (HTTP/HTTPS)
- T1071.002 File Transfer Protocols
- T1071.003 Mail Protocols
- T1071.004 DNS
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class ApplicationLayerProtocolCheck(BaseModule):
    TECHNIQUE_ID = "T1071"
    TECHNIQUE_NAME = "Application Layer Protocol"
    TACTIC = Tactic.COMMAND_AND_CONTROL
    SEVERITY = Severity.HIGH
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        self._check_web_protocols(session)
        self._check_dns_exfil(session)
        self._check_mail_protocols(session)
        self._check_outbound_connections(session)
        self._check_proxy_config(session)

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def _check_web_protocols(self, session: Session) -> None:
        """T1071.001 — Check outbound HTTP/HTTPS capabilities."""
        # Check for unrestricted outbound HTTP/HTTPS
        fw_http = session.execute(
            "firewall-cmd --list-rich-rules 2>/dev/null; "
            "iptables -L OUTPUT -n 2>/dev/null | grep -E '(80|443|8080|8443)'"
        )

        # Check if outbound 80/443 is unrestricted
        iptables_out = session.execute(
            "iptables -L OUTPUT -n 2>/dev/null | head -5"
        )
        if iptables_out.success:
            output = iptables_out.output
            if "ACCEPT" in output and "policy ACCEPT" in output:
                self.add_finding(
                    title="Unrestricted outbound traffic (OUTPUT policy ACCEPT)",
                    description="No egress filtering — any process can reach external C2 servers",
                    severity=Severity.HIGH,
                    evidence=output[:300],
                    remediation="Implement egress firewall rules; whitelist required destinations only",
                )

        # Check HTTP tools available
        http_tools = []
        for tool in ("curl", "wget", "python3 -c 'import urllib'", "openssl s_client"):
            binary = tool.split()[0]
            result = session.execute(f"which {binary} 2>/dev/null")
            if result.success and result.output.strip():
                http_tools.append(binary)

        if http_tools:
            self.add_finding(
                title=f"HTTP client tools available: {', '.join(http_tools)}",
                description="HTTP clients enable C2 communication over web protocols",
                severity=Severity.INFO,
                evidence=", ".join(http_tools),
            )

    def _check_dns_exfil(self, session: Session) -> None:
        """T1071.004 — DNS as C2 channel."""
        # Check for DNS tools that enable DNS tunneling
        dns_tools = []
        for tool in ("dig", "nslookup", "host", "dnscat2", "iodine"):
            result = session.execute(f"which {tool} 2>/dev/null")
            if result.success and result.output.strip():
                dns_tools.append(tool)

        # High-risk DNS tunneling tools
        tunneling_tools = [t for t in dns_tools if t in ("dnscat2", "iodine")]
        if tunneling_tools:
            self.add_finding(
                title=f"DNS tunneling tools installed: {', '.join(tunneling_tools)}",
                description="These tools are designed for C2 over DNS",
                severity=Severity.CRITICAL,
                evidence=", ".join(tunneling_tools),
                remediation=f"Remove immediately: dnf remove {' '.join(tunneling_tools)}",
            )

        # Check if DNS queries are logged/monitored
        dns_logging = session.execute(
            "grep -r 'log-queries\\|query-log' /etc/named.conf /etc/unbound/ 2>/dev/null"
        )
        resolv = session.execute("cat /etc/resolv.conf 2>/dev/null")
        if resolv.success and resolv.output.strip():
            nameservers = [
                line.split()[1]
                for line in resolv.output.splitlines()
                if line.strip().startswith("nameserver")
            ]
            if nameservers:
                self.add_finding(
                    title=f"DNS resolvers configured: {', '.join(nameservers)}",
                    description="DNS queries to external resolvers can carry covert C2 data",
                    severity=Severity.INFO,
                    evidence="\n".join(nameservers),
                )

    def _check_mail_protocols(self, session: Session) -> None:
        """T1071.003 — Mail protocols for C2."""
        for svc in ("postfix", "sendmail", "exim"):
            result = session.execute(f"systemctl is-active {svc} 2>/dev/null")
            if result.success and result.output.strip() == "active":
                self.add_finding(
                    title=f"Mail service running: {svc}",
                    description="Mail services can be abused for C2 communication via SMTP",
                    severity=Severity.LOW,
                    evidence=f"{svc} is active",
                    remediation=f"Disable {svc} if outbound mail is not required",
                )

        # Check if mail command is available
        mail_cmd = session.execute("which mail 2>/dev/null || which mailx 2>/dev/null")
        if mail_cmd.success and mail_cmd.output.strip():
            self.add_finding(
                title="Mail command available for scripted email",
                description="mail/mailx can send data out via SMTP from scripts",
                severity=Severity.LOW,
                evidence=mail_cmd.output.strip(),
            )

    def _check_outbound_connections(self, session: Session) -> None:
        """Check for active outbound connections to unusual ports."""
        # Established outbound connections
        conns = session.execute(
            "ss -tnp state established 2>/dev/null | "
            "awk '$4 !~ /:22$|:80$|:443$|:53$/ {print}' | head -20"
        )
        if conns.success and conns.output.strip():
            lines = [l for l in conns.output.strip().splitlines() if l.strip()]
            if lines:
                self.add_finding(
                    title=f"Outbound connections on non-standard ports: {len(lines)}",
                    description="Connections on unusual ports may indicate C2 traffic",
                    severity=Severity.MEDIUM,
                    evidence="\n".join(lines[:10]),
                    remediation="Investigate and whitelist legitimate connections; block others",
                )

    def _check_proxy_config(self, session: Session) -> None:
        """Check proxy configuration that C2 could leverage."""
        proxy_vars = session.execute(
            "env | grep -iE '(http_proxy|https_proxy|all_proxy|no_proxy)' 2>/dev/null"
        )
        if proxy_vars.success and proxy_vars.output.strip():
            self.add_finding(
                title="HTTP proxy configured in environment",
                description="Proxy configuration may be leveraged by C2 to blend with legitimate traffic",
                severity=Severity.INFO,
                evidence=proxy_vars.output.strip(),
            )

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Implement egress firewall rules — whitelist outbound destinations",
            "Block outbound traffic on non-essential ports",
            "Remove unnecessary HTTP clients and DNS tools from production systems",
            "Monitor DNS query logs for tunneling indicators (long hostnames, high volume)",
            "Disable mail services on systems that don't require outbound email",
            "Use a forward proxy with TLS inspection for outbound web traffic",
            "Deploy network IDS/IPS to detect C2 patterns",
        ]

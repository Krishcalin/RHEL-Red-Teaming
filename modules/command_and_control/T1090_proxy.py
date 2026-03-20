"""T1090 — Proxy.

Checks for proxy tools and configurations that could relay C2 traffic:
- T1090.001 Internal Proxy
- T1090.002 External Proxy
- T1090.003 Multi-hop Proxy
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class ProxyCheck(BaseModule):
    TECHNIQUE_ID = "T1090"
    TECHNIQUE_NAME = "Proxy"
    TACTIC = Tactic.COMMAND_AND_CONTROL
    SEVERITY = Severity.MEDIUM
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        self._check_proxy_tools(session)
        self._check_socks_proxy(session)
        self._check_port_forwarding(session)
        self._check_reverse_proxies(session)

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def _check_proxy_tools(self, session: Session) -> None:
        """Check for proxy/tunneling tools."""
        proxy_tools = [
            ("proxychains", "ProxyChains — force TCP through proxy", Severity.HIGH),
            ("proxychains4", "ProxyChains-NG — updated proxy forcer", Severity.HIGH),
            ("tsocks", "tsocks — transparent SOCKS proxy", Severity.MEDIUM),
            ("redsocks", "redsocks — transparent TCP-to-proxy redirector", Severity.HIGH),
            ("3proxy", "3proxy — universal proxy server", Severity.HIGH),
            ("chisel", "chisel — HTTP tunnel / SOCKS proxy", Severity.CRITICAL),
            ("ligolo", "Ligolo — reverse tunneling framework", Severity.CRITICAL),
        ]

        for binary, desc, severity in proxy_tools:
            result = session.execute(f"which {binary} 2>/dev/null")
            if result.success and result.output.strip():
                self.add_finding(
                    title=f"Proxy tool installed: {binary}",
                    description=f"{desc} — commonly used for C2 relay and pivoting",
                    severity=severity,
                    evidence=result.output.strip(),
                    remediation=f"Remove {binary} unless authorized: dnf remove {binary}",
                )

        # Check proxychains config
        for cfg in ("/etc/proxychains.conf", "/etc/proxychains4.conf"):
            result = session.execute(f"test -f {cfg} && echo exists")
            if result.success and result.output.strip() == "exists":
                chains = session.execute(f"grep -v '^#' {cfg} 2>/dev/null | grep -E 'socks|http' | head -5")
                if chains.success and chains.output.strip():
                    self.add_finding(
                        title=f"ProxyChains configured: {cfg}",
                        description="ProxyChains configuration defines proxy endpoints for traffic relay",
                        severity=Severity.HIGH,
                        evidence=chains.output.strip(),
                        remediation="Remove proxychains configuration if not authorized",
                    )

    def _check_socks_proxy(self, session: Session) -> None:
        """Check for active SOCKS proxy listeners."""
        # Look for common SOCKS ports
        socks_ports = ["1080", "9050", "9150", "8080"]
        for port in socks_ports:
            result = session.execute(f"ss -tlnp 2>/dev/null | grep ':{port} '")
            if result.success and result.output.strip():
                self.add_finding(
                    title=f"Possible SOCKS proxy listener on port {port}",
                    description=f"Port {port} is commonly used for SOCKS proxies",
                    severity=Severity.MEDIUM,
                    evidence=result.output.strip(),
                    remediation="Investigate the listening process; disable if unauthorized",
                )

        # Tor SOCKS proxy
        tor_check = session.execute("systemctl is-active tor 2>/dev/null")
        if tor_check.success and tor_check.output.strip() == "active":
            self.add_finding(
                title="Tor service active — anonymous SOCKS proxy",
                description="Tor provides anonymous communication and is frequently used for C2",
                severity=Severity.CRITICAL,
                evidence="tor.service is active",
                remediation="Disable Tor: systemctl disable --now tor",
            )

    def _check_port_forwarding(self, session: Session) -> None:
        """Check for IP forwarding and NAT rules enabling traffic relay."""
        # IP forwarding
        ip_fwd = session.execute("sysctl net.ipv4.ip_forward 2>/dev/null")
        if ip_fwd.success and "= 1" in ip_fwd.output:
            self.add_finding(
                title="IP forwarding enabled",
                description="IP forwarding allows this host to relay traffic between networks",
                severity=Severity.MEDIUM,
                evidence=ip_fwd.output.strip(),
                remediation="Disable if not needed: sysctl -w net.ipv4.ip_forward=0",
            )

        # NAT/MASQUERADE rules
        nat_rules = session.execute("iptables -t nat -L -n 2>/dev/null | grep -i 'MASQUERADE\\|DNAT\\|SNAT'")
        if nat_rules.success and nat_rules.output.strip():
            self.add_finding(
                title="NAT rules configured",
                description="NAT rules enable traffic relaying through this host",
                severity=Severity.MEDIUM,
                evidence=nat_rules.output.strip()[:500],
                remediation="Review and remove unnecessary NAT rules",
            )

    def _check_reverse_proxies(self, session: Session) -> None:
        """Check for reverse proxy services."""
        for svc in ("nginx", "haproxy", "squid", "apache2", "httpd"):
            result = session.execute(f"systemctl is-active {svc} 2>/dev/null")
            if result.success and result.output.strip() == "active":
                # Check if configured as reverse proxy
                if svc in ("nginx", "httpd", "apache2"):
                    proxy_cfg = session.execute(
                        f"grep -r 'proxy_pass\\|ProxyPass' /etc/{svc}/ 2>/dev/null | head -5"
                    )
                    if proxy_cfg.success and proxy_cfg.output.strip():
                        self.add_finding(
                            title=f"Reverse proxy configured: {svc}",
                            description=f"{svc} is configured as a reverse proxy — could relay C2",
                            severity=Severity.LOW,
                            evidence=proxy_cfg.output.strip()[:300],
                            remediation="Audit proxy destinations; restrict to known backends",
                        )
                elif svc == "squid":
                    self.add_finding(
                        title="Squid proxy active",
                        description="Squid forward proxy could be used to relay C2 traffic",
                        severity=Severity.MEDIUM,
                        evidence="squid.service is active",
                        remediation="Restrict Squid ACLs to authorized destinations only",
                    )

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Remove proxy/tunneling tools (proxychains, chisel, ligolo, redsocks)",
            "Disable Tor and other anonymizing proxies",
            "Disable IP forwarding unless required for routing",
            "Audit and restrict NAT/MASQUERADE rules",
            "Monitor for SOCKS proxy listeners on common ports",
            "Restrict reverse proxy destinations to known backends",
            "Use auditd rules to detect proxy tool execution",
        ]

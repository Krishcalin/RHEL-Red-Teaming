"""T1571 — Non-Standard Port.

Checks outbound port filtering policy and services on non-standard ports
on RHEL systems.
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class NonStandardPortCheck(BaseModule):
    TECHNIQUE_ID = "T1571"
    TECHNIQUE_NAME = "Non-Standard Port"
    TACTIC = Tactic.COMMAND_AND_CONTROL
    SEVERITY = Severity.MEDIUM
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        self._check_egress_filtering(session)
        self._check_high_port_listeners(session)

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def _check_egress_filtering(self, session: Session) -> None:
        result = session.execute("iptables -L OUTPUT -n 2>/dev/null | grep -c 'REJECT\\|DROP'")
        if result.success and result.output.strip():
            try:
                drop_rules = int(result.output.strip())
                if drop_rules == 0:
                    self.add_finding(
                        title="No outbound port filtering (iptables)",
                        description="No OUTPUT DROP/REJECT rules — C2 on any port is unrestricted",
                        severity=Severity.HIGH,
                        evidence=f"OUTPUT chain DROP/REJECT rules: {drop_rules}",
                        remediation="Implement egress filtering: allow only required outbound ports",
                    )
            except ValueError:
                pass

        fw = session.execute("firewall-cmd --list-ports 2>/dev/null")
        if fw.success and fw.output.strip():
            ports = fw.output.strip().split()
            high_ports = [p for p in ports if "/" in p and int(p.split("/")[0]) > 10000]
            if len(high_ports) > 5:
                self.add_finding(
                    title=f"Many high ports allowed in firewall ({len(high_ports)})",
                    description="Excessive high port allowances enable non-standard port C2",
                    severity=Severity.MEDIUM,
                    evidence=", ".join(high_ports[:10]),
                    remediation="Restrict firewall to only operationally required ports",
                )

    def _check_high_port_listeners(self, session: Session) -> None:
        result = session.execute("ss -tuln 2>/dev/null | awk '$5 ~ /:[0-9]+$/ {print $5}' | awk -F: '{print $NF}' | sort -n")
        if result.success and result.output.strip():
            standard = {"22", "25", "53", "80", "443", "110", "143", "993", "995", "3306", "5432"}
            non_standard = []
            for port in result.output.strip().splitlines():
                port = port.strip()
                if port and port not in standard:
                    try:
                        if int(port) > 10000:
                            non_standard.append(port)
                    except ValueError:
                        pass
            if len(non_standard) > 3:
                self.add_finding(
                    title=f"Services on {len(non_standard)} non-standard high ports",
                    description="Multiple services on high non-standard ports could mask C2",
                    severity=Severity.LOW,
                    evidence="Ports: " + ", ".join(non_standard[:15]),
                    remediation="Audit services on non-standard ports; move to standard ports where possible",
                )

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Implement egress filtering allowing only required outbound ports",
            "Audit services on non-standard ports regularly",
            "Use firewalld with strict zone policies",
            "Monitor for outbound connections on unusual ports",
        ]

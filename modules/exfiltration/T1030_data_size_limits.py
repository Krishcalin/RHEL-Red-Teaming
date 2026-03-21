"""T1030 — Data Transfer Size Limits.

Checks data transfer throttling and monitoring capabilities on RHEL systems.
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class DataSizeLimitsCheck(BaseModule):
    TECHNIQUE_ID = "T1030"
    TECHNIQUE_NAME = "Data Transfer Size Limits"
    TACTIC = Tactic.EXFILTRATION
    SEVERITY = Severity.MEDIUM
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        self._check_bandwidth_controls(session)
        self._check_disk_quotas(session)
        self._check_network_monitoring(session)

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def _check_bandwidth_controls(self, session: Session) -> None:
        result = session.execute("tc qdisc show 2>/dev/null | grep -v 'noqueue\\|pfifo_fast'")
        if not result.success or not result.output.strip():
            self.add_finding(
                title="No traffic shaping/bandwidth controls",
                description="No tc qdisc rules — large data exfiltration transfers are unrestricted",
                severity=Severity.MEDIUM,
                evidence="No custom qdisc rules found",
                remediation="Implement tc bandwidth limits on outbound interfaces",
            )

    def _check_disk_quotas(self, session: Session) -> None:
        result = session.execute("repquota -a 2>/dev/null | head -5")
        if not result.success or not result.output.strip():
            self.add_finding(
                title="No disk quotas configured",
                description="Without quotas, users can stage unlimited data for exfiltration",
                severity=Severity.LOW,
                evidence="repquota returned no data",
                remediation="Configure disk quotas to limit data staging: edquota -u <user>",
            )

    def _check_network_monitoring(self, session: Session) -> None:
        tools = {"nethogs": "per-process bandwidth", "iftop": "interface traffic",
                 "vnstat": "traffic accounting", "ntopng": "deep traffic analysis"}
        installed = []
        for tool, desc in tools.items():
            result = session.execute(f"which {tool} 2>/dev/null || rpm -q {tool} 2>/dev/null")
            if result.success and result.output.strip() and "not installed" not in result.output:
                installed.append(tool)

        if not installed:
            self.add_finding(
                title="No network traffic monitoring tools installed",
                description="Cannot detect large data transfers without traffic monitoring",
                severity=Severity.MEDIUM,
                evidence="None of: " + ", ".join(tools.keys()),
                remediation="Install vnstat or nethogs for traffic monitoring",
            )

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Implement bandwidth controls with tc qdisc on outbound interfaces",
            "Deploy network traffic monitoring (vnstat, nethogs)",
            "Configure disk quotas to limit data staging",
            "Alert on anomalous outbound data volume thresholds",
        ]

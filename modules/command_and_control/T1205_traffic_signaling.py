"""T1205 — Traffic Signaling.

Checks for port knocking and covert signaling mechanisms on RHEL systems.
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class TrafficSignalingCheck(BaseModule):
    TECHNIQUE_ID = "T1205"
    TECHNIQUE_NAME = "Traffic Signaling"
    TACTIC = Tactic.COMMAND_AND_CONTROL
    SEVERITY = Severity.MEDIUM
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        self._check_port_knocking(session)
        self._check_bpf_filters(session)
        self._check_nftables_signaling(session)

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def _check_port_knocking(self, session: Session) -> None:
        knockd = session.execute("which knockd 2>/dev/null || systemctl is-active knockd 2>/dev/null")
        if knockd.success and knockd.output.strip() and "inactive" not in knockd.output:
            self.add_finding(
                title="Port knocking daemon (knockd) detected",
                description="knockd enables covert signaling to open firewall ports",
                severity=Severity.MEDIUM,
                evidence=knockd.output.strip(),
                remediation="Review knockd configuration; remove if not authorized",
            )

        fwknop = session.execute("which fwknop 2>/dev/null || which fwknopd 2>/dev/null")
        if fwknop.success and fwknop.output.strip():
            self.add_finding(
                title="fwknop Single Packet Authorization detected",
                description="fwknop enables covert single-packet authentication signaling",
                severity=Severity.MEDIUM,
                evidence=fwknop.output.strip(),
                remediation="Verify fwknop is authorized; audit configuration",
            )

    def _check_bpf_filters(self, session: Session) -> None:
        result = session.execute("cat /proc/sys/net/core/bpf_jit_enable 2>/dev/null")
        if result.success and result.output.strip() == "1":
            self.add_finding(
                title="BPF JIT compilation is enabled",
                description="BPF JIT enables custom packet filters that could implement covert signaling",
                severity=Severity.LOW,
                evidence="net.core.bpf_jit_enable = 1",
                remediation="Set bpf_jit_harden=2 for hardened BPF if JIT is required",
            )

    def _check_nftables_signaling(self, session: Session) -> None:
        result = session.execute("nft list ruleset 2>/dev/null | grep -i 'mark\\|ct mark\\|meta mark'")
        if result.success and result.output.strip():
            self.add_finding(
                title="nftables packet marking rules detected",
                description="Packet marking can be used for traffic signaling and covert channels",
                severity=Severity.LOW,
                evidence=result.output.strip()[:300],
                remediation="Audit nftables mark rules; ensure they serve legitimate purposes",
            )

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Remove port knocking tools (knockd, fwknop) if not authorized",
            "Harden BPF: set bpf_jit_harden=2",
            "Audit nftables/iptables for suspicious marking rules",
            "Monitor for covert channel patterns in network traffic",
        ]

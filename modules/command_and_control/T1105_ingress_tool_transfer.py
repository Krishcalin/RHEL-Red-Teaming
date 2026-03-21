"""T1105 — Ingress Tool Transfer.

Checks for download tool availability and controls on ingress file
transfers on RHEL systems.
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class IngressToolTransferCheck(BaseModule):
    TECHNIQUE_ID = "T1105"
    TECHNIQUE_NAME = "Ingress Tool Transfer"
    TACTIC = Tactic.COMMAND_AND_CONTROL
    SEVERITY = Severity.MEDIUM
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        self._check_download_tools(session)
        self._check_writable_exec_dirs(session)
        self._check_fapolicyd(session)

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def _check_download_tools(self, session: Session) -> None:
        tools = {"curl": "HTTP client", "wget": "file downloader",
                 "scp": "secure copy", "rsync": "file sync",
                 "nc": "netcat", "ncat": "nmap netcat",
                 "socat": "socket relay", "fetch": "URL fetcher"}
        for tool, desc in tools.items():
            result = session.execute(f"which {tool} 2>/dev/null")
            if result.success and result.output.strip():
                self.add_finding(
                    title=f"Download tool available: {tool}",
                    description=f"{tool} ({desc}) can transfer tools onto the system",
                    severity=Severity.LOW,
                    evidence=result.output.strip(),
                    remediation=f"Remove {tool} if not operationally required; monitor with auditd",
                )

    def _check_writable_exec_dirs(self, session: Session) -> None:
        dirs = ["/tmp", "/var/tmp", "/dev/shm"]
        for d in dirs:
            mount = session.execute(f"mount 2>/dev/null | grep ' {d} '")
            if mount.success and mount.output.strip():
                if "noexec" not in mount.output:
                    self.add_finding(
                        title=f"{d} allows execution",
                        description=f"{d} is mounted without noexec — downloaded tools can be executed",
                        severity=Severity.MEDIUM,
                        evidence=mount.output.strip()[:300],
                        remediation=f"Mount {d} with noexec: mount -o remount,noexec {d}",
                    )

    def _check_fapolicyd(self, session: Session) -> None:
        result = session.execute("systemctl is-active fapolicyd 2>/dev/null")
        if not result.success or result.output.strip() != "active":
            self.add_finding(
                title="fapolicyd application allow-listing not active",
                description="No application execution policy — downloaded tools can run freely",
                severity=Severity.MEDIUM,
                evidence=f"fapolicyd: {result.output.strip() if result.success else 'not installed'}",
                remediation="Install fapolicyd for application allow-listing: dnf install fapolicyd",
            )

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Remove unnecessary download tools from production systems",
            "Mount /tmp, /var/tmp, /dev/shm with noexec",
            "Deploy fapolicyd for application allow-listing",
            "Monitor file downloads with auditd rules on curl/wget",
        ]

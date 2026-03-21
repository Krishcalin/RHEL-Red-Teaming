"""T1219 — Remote Access Tools.

Checks for remote access tool installations on RHEL systems.
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class RemoteAccessToolsCheck(BaseModule):
    TECHNIQUE_ID = "T1219"
    TECHNIQUE_NAME = "Remote Access Tools"
    TACTIC = Tactic.COMMAND_AND_CONTROL
    SEVERITY = Severity.HIGH
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        self._check_rat_processes(session)
        self._check_rat_packages(session)
        self._check_vnc_exposure(session)

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def _check_rat_processes(self, session: Session) -> None:
        rats = {
            "teamviewerd": "TeamViewer", "anydesk": "AnyDesk",
            "rustdesk": "RustDesk", "xrdp": "XRDP",
            "x11vnc": "X11VNC", "meshagent": "MeshCentral",
        }
        for proc, name in rats.items():
            result = session.execute(f"pgrep -x {proc} >/dev/null 2>&1; echo $?")
            if result.success and result.output.strip() == "0":
                self.add_finding(
                    title=f"Remote access tool running: {name}",
                    description=f"{name} ({proc}) is an active remote access tool — potential C2 channel",
                    severity=Severity.HIGH,
                    evidence=f"Process {proc} is running",
                    remediation=f"Verify {name} is authorized; remove if not: systemctl disable --now {proc}",
                )

    def _check_rat_packages(self, session: Session) -> None:
        packages = ["tigervnc-server", "xrdp", "x11vnc", "remmina"]
        for pkg in packages:
            result = session.execute(f"rpm -q {pkg} 2>/dev/null")
            if result.success and "not installed" not in result.output:
                self.add_finding(
                    title=f"Remote access package installed: {pkg}",
                    description=f"{pkg} is installed and could be activated for remote access",
                    severity=Severity.MEDIUM,
                    evidence=result.output.strip(),
                    remediation=f"Remove if not needed: dnf remove {pkg}",
                )

    def _check_vnc_exposure(self, session: Session) -> None:
        result = session.execute("ss -tuln 2>/dev/null | grep -E ':590[0-9] '")
        if result.success and result.output.strip():
            if "0.0.0.0" in result.output:
                self.add_finding(
                    title="VNC listening on all interfaces",
                    description="VNC server exposed on 0.0.0.0 — remote access without proper authentication",
                    severity=Severity.HIGH,
                    evidence=result.output.strip()[:300],
                    remediation="Bind VNC to localhost and tunnel through SSH",
                )

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Remove unauthorized remote access tools",
            "Bind VNC/XRDP to localhost and require SSH tunneling",
            "Monitor for RAT process creation with auditd",
            "Use application allow-listing to block unauthorized RATs",
        ]

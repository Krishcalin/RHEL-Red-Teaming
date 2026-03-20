"""T1570 — Lateral Tool Transfer.

Checks for tools and configurations that facilitate transferring
files between systems for lateral movement.
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class LateralToolTransferCheck(BaseModule):
    TECHNIQUE_ID = "T1570"
    TECHNIQUE_NAME = "Lateral Tool Transfer"
    TACTIC = Tactic.LATERAL_MOVEMENT
    SEVERITY = Severity.MEDIUM
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    TRANSFER_TOOLS = [
        ("scp", "SCP file transfer (SSH-based)"),
        ("rsync", "rsync synchronization tool"),
        ("curl", "curl HTTP client"),
        ("wget", "wget HTTP client"),
        ("nc", "netcat — raw TCP/UDP transfer"),
        ("ncat", "nmap netcat variant"),
        ("socat", "multipurpose relay tool"),
        ("ftp", "FTP client"),
        ("tftp", "TFTP client"),
        ("sftp", "SFTP client"),
    ]

    def check(self, session: Session) -> ModuleResult:
        self._check_transfer_tools(session)
        self._check_writable_share_dirs(session)
        self._check_scp_config(session)

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def _check_transfer_tools(self, session: Session) -> None:
        """Check availability of file transfer tools."""
        found = []
        high_risk = []

        for binary, desc in self.TRANSFER_TOOLS:
            result = session.execute(f"which {binary} 2>/dev/null")
            if result.success and result.output.strip():
                found.append(f"{binary}: {result.output.strip()}")
                if binary in ("nc", "ncat", "socat", "ftp", "tftp"):
                    high_risk.append(binary)

        if found:
            self.add_finding(
                title=f"File transfer tools available: {len(found)}",
                description="Transfer tools can be used to move payloads between compromised hosts",
                severity=Severity.INFO,
                evidence="\n".join(found),
            )

        if high_risk:
            self.add_finding(
                title=f"High-risk transfer tools installed: {', '.join(high_risk)}",
                description="These tools are commonly abused for lateral tool transfer",
                severity=Severity.MEDIUM,
                evidence=", ".join(high_risk),
                remediation=f"Remove unless required: dnf remove {' '.join(high_risk)}",
            )

    def _check_writable_share_dirs(self, session: Session) -> None:
        """Check for world-writable directories in network share paths."""
        share_dirs = ["/srv/samba", "/srv/nfs", "/export", "/shared"]
        for d in share_dirs:
            result = session.execute(f"test -d {d} && find {d} -maxdepth 1 -writable 2>/dev/null | head -5")
            if result.success and result.output.strip():
                self.add_finding(
                    title=f"Writable network share directory: {d}",
                    description="Writable share directories enable tool staging for lateral movement",
                    severity=Severity.MEDIUM,
                    evidence=result.output.strip(),
                    remediation=f"Restrict write access to {d} to authorized users only",
                )

    def _check_scp_config(self, session: Session) -> None:
        """Check if SCP subsystem is enabled and unrestricted."""
        sftp_subsystem = session.execute(
            "grep -i 'Subsystem.*sftp' /etc/ssh/sshd_config 2>/dev/null"
        )
        if sftp_subsystem.success and sftp_subsystem.output.strip():
            # Check if internal-sftp is used with chroot
            if "internal-sftp" not in sftp_subsystem.output:
                self.add_finding(
                    title="SFTP subsystem uses external binary",
                    description="External sftp-server binary is harder to confine than internal-sftp",
                    severity=Severity.LOW,
                    evidence=sftp_subsystem.output.strip(),
                    remediation="Use 'Subsystem sftp internal-sftp' with ChrootDirectory",
                )

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Remove unnecessary transfer tools (nc, socat, ftp, tftp)",
            "Use internal-sftp with ChrootDirectory for SFTP access",
            "Restrict write access to network share directories",
            "Monitor file transfer activity with auditd rules",
            "Use fapolicyd to restrict execution of transferred binaries",
        ]

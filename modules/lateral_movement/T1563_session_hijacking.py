"""T1563 — Remote Service Session Hijacking.

Checks SSH agent forwarding, ControlMaster, and screen/tmux session
hijacking risks on RHEL systems.
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class SessionHijackingCheck(BaseModule):
    TECHNIQUE_ID = "T1563"
    TECHNIQUE_NAME = "Remote Service Session Hijacking"
    TACTIC = Tactic.LATERAL_MOVEMENT
    SEVERITY = Severity.HIGH
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        self._check_ssh_agent_forwarding(session)
        self._check_controlmaster(session)
        self._check_tmux_screen(session)
        self._check_ssh_sockets(session)

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def _check_ssh_agent_forwarding(self, session: Session) -> None:
        result = session.execute("grep -i 'AllowAgentForwarding' /etc/ssh/sshd_config 2>/dev/null")
        if result.success and result.output.strip():
            if "yes" in result.output.lower() and not result.output.strip().startswith("#"):
                self.add_finding(
                    title="SSH agent forwarding is enabled",
                    description="AllowAgentForwarding=yes allows hijacking of forwarded SSH agent sockets",
                    severity=Severity.HIGH,
                    evidence=result.output.strip(),
                    remediation="Set AllowAgentForwarding no in /etc/ssh/sshd_config",
                )
        else:
            self.add_finding(
                title="SSH agent forwarding not explicitly disabled",
                description="AllowAgentForwarding defaults to yes — forwarded agents can be hijacked",
                severity=Severity.MEDIUM,
                evidence="AllowAgentForwarding not set (defaults to yes)",
                remediation="Explicitly set AllowAgentForwarding no in /etc/ssh/sshd_config",
            )

    def _check_controlmaster(self, session: Session) -> None:
        result = session.execute("find /home /root -name 'config' -path '*/.ssh/config' 2>/dev/null -exec grep -li 'ControlMaster' {} +")
        if result.success and result.output.strip():
            self.add_finding(
                title="SSH ControlMaster configured",
                description="SSH multiplexing sockets can be hijacked by other users with access",
                severity=Severity.MEDIUM,
                evidence=result.output.strip()[:300],
                remediation="Use ControlPath in user-only directories with 700 permissions",
            )

    def _check_tmux_screen(self, session: Session) -> None:
        for tool in ["tmux", "screen"]:
            sockets = session.execute(f"find /tmp -name '{tool}*' -type s -o -name '{tool}*' -type d 2>/dev/null | head -10")
            if sockets.success and sockets.output.strip():
                self.add_finding(
                    title=f"Active {tool} sessions detected",
                    description=f"{tool} session sockets found — may be accessible by other users",
                    severity=Severity.MEDIUM,
                    evidence=sockets.output.strip()[:300],
                    remediation=f"Set strict permissions on {tool} sockets; use per-user socket directories",
                )

    def _check_ssh_sockets(self, session: Session) -> None:
        result = session.execute("find /tmp -name 'ssh-*' -type s 2>/dev/null | head -10")
        if result.success and result.output.strip():
            self.add_finding(
                title="SSH agent sockets found in /tmp",
                description="SSH agent sockets in /tmp may be accessible to other users on the system",
                severity=Severity.MEDIUM,
                evidence=result.output.strip()[:300],
                remediation="Use SSH_AUTH_SOCK in user-owned directories; disable agent forwarding",
            )

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Disable SSH agent forwarding: AllowAgentForwarding no",
            "Use ProxyJump instead of agent forwarding for multi-hop SSH",
            "Set strict permissions on SSH ControlMaster socket paths",
            "Restrict tmux/screen socket directory permissions",
            "Monitor for unauthorized access to SSH agent sockets",
        ]

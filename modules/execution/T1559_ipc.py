"""T1559 — Inter-Process Communication.

Checks IPC mechanisms on RHEL systems for security weaknesses,
including D-Bus policies, Unix sockets, shared memory, message queues,
named pipes, and POSIX mqueue settings.
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class IPCCheck(BaseModule):
    TECHNIQUE_ID = "T1559"
    TECHNIQUE_NAME = "Inter-Process Communication"
    TACTIC = Tactic.EXECUTION
    SEVERITY = Severity.LOW
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        self._check_dbus_policy(session)
        self._check_world_writable_sockets(session)
        self._check_shared_memory(session)
        self._check_message_queues(session)
        self._check_named_pipes(session)
        self._check_mqueue_settings(session)

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def _check_dbus_policy(self, session: Session) -> None:
        """Check D-Bus system bus policy for overly permissive rules."""
        result = session.execute(
            "ls /etc/dbus-1/system.d/ 2>/dev/null"
        )
        if not result.success or not result.output.strip():
            return

        policy_files = result.output.strip().splitlines()

        # Check for policies that allow any user to own or send
        permissive_policies = []
        for pf in policy_files[:20]:
            pf = pf.strip()
            if not pf:
                continue
            content = session.execute(
                f"grep -l 'allow.*send_destination\\|allow.*own' "
                f"'/etc/dbus-1/system.d/{pf}' 2>/dev/null"
            )
            if content.success and content.output.strip():
                # Check if any policy allows all users (no user= restriction)
                permissive = session.execute(
                    f"grep -n '<allow' '/etc/dbus-1/system.d/{pf}' 2>/dev/null "
                    f"| grep -v 'user=\\|group=\\|context='"
                )
                if permissive.success and permissive.output.strip():
                    permissive_policies.append(
                        f"{pf}: {permissive.output.strip().splitlines()[0]}"
                    )

        if permissive_policies:
            self.add_finding(
                title="D-Bus system policies with unrestricted allow rules",
                description=(
                    f"{len(permissive_policies)} D-Bus policy file(s) contain allow rules "
                    "without user/group restrictions, potentially granting any user "
                    "access to privileged D-Bus interfaces."
                ),
                severity=Severity.MEDIUM,
                evidence="\n".join(permissive_policies[:10]),
                remediation=(
                    "Review D-Bus policies in /etc/dbus-1/system.d/ and restrict "
                    "allow rules to specific users or groups. Use 'deny' as default policy."
                ),
            )

    def _check_world_writable_sockets(self, session: Session) -> None:
        """Check for world-writable Unix domain sockets."""
        result = session.execute(
            "find /tmp /var/run /run -type s -perm -o+w 2>/dev/null | head -20"
        )
        if result.success and result.output.strip():
            sockets = result.output.strip().splitlines()
            self.add_finding(
                title="World-writable Unix domain sockets found",
                description=(
                    f"{len(sockets)} Unix socket(s) are world-writable, allowing any "
                    "user to connect and potentially inject or intercept IPC messages."
                ),
                severity=Severity.MEDIUM,
                evidence="\n".join(sockets[:10]),
                remediation=(
                    "Restrict Unix socket permissions to the owning user/group. "
                    "Use filesystem ACLs or socket directory permissions to control access."
                ),
            )

    def _check_shared_memory(self, session: Session) -> None:
        """Check shared memory segments for insecure permissions."""
        result = session.execute("ipcs -m 2>/dev/null")
        if not result.success or not result.output.strip():
            return

        lines = result.output.strip().splitlines()
        insecure_segments = []

        for line in lines:
            parts = line.split()
            if len(parts) < 5:
                continue
            # Skip header lines
            if parts[0] in ("key", "------", ""):
                continue
            try:
                # ipcs -m output: key shmid owner perms bytes ...
                perms = parts[3]
                if perms.endswith("6") or perms.endswith("7"):
                    # World-readable or world-writable
                    insecure_segments.append(
                        f"shmid={parts[1]} owner={parts[2]} perms={perms}"
                    )
            except (IndexError, ValueError):
                continue

        if insecure_segments:
            self.add_finding(
                title="Shared memory segments with world-accessible permissions",
                description=(
                    f"{len(insecure_segments)} shared memory segment(s) have permissions "
                    "allowing world read/write access, which could be exploited for "
                    "data exfiltration or injection between processes."
                ),
                severity=Severity.LOW,
                evidence="\n".join(insecure_segments[:10]),
                remediation=(
                    "Review shared memory segments with 'ipcs -m' and remove unnecessary ones. "
                    "Applications should create shared memory with restrictive permissions (0600)."
                ),
            )

    def _check_message_queues(self, session: Session) -> None:
        """Check System V message queues for insecure permissions."""
        result = session.execute("ipcs -q 2>/dev/null")
        if not result.success or not result.output.strip():
            return

        lines = result.output.strip().splitlines()
        insecure_queues = []

        for line in lines:
            parts = line.split()
            if len(parts) < 4:
                continue
            if parts[0] in ("key", "------", ""):
                continue
            try:
                perms = parts[3]
                if perms.endswith("6") or perms.endswith("7"):
                    insecure_queues.append(
                        f"msqid={parts[1]} owner={parts[2]} perms={perms}"
                    )
            except (IndexError, ValueError):
                continue

        if insecure_queues:
            self.add_finding(
                title="Message queues with world-accessible permissions",
                description=(
                    f"{len(insecure_queues)} message queue(s) have overly permissive "
                    "access, allowing unauthorized processes to read or write messages."
                ),
                severity=Severity.LOW,
                evidence="\n".join(insecure_queues[:10]),
                remediation=(
                    "Review message queues with 'ipcs -q' and remove stale entries. "
                    "Set appropriate permissions when creating message queues."
                ),
            )

    def _check_named_pipes(self, session: Session) -> None:
        """Check named pipe permissions in /tmp and /var."""
        result = session.execute(
            "find /tmp /var -type p -perm -o+w 2>/dev/null | head -20"
        )
        if result.success and result.output.strip():
            pipes = result.output.strip().splitlines()
            self.add_finding(
                title="World-writable named pipes found",
                description=(
                    f"{len(pipes)} named pipe(s) in /tmp or /var are world-writable, "
                    "allowing any user to write data that could be read by "
                    "privileged processes, enabling IPC injection attacks."
                ),
                severity=Severity.MEDIUM,
                evidence="\n".join(pipes[:10]),
                remediation=(
                    "Restrict named pipe permissions to the owning user/group (e.g., 0600). "
                    "Avoid creating named pipes in world-writable directories."
                ),
            )

    def _check_mqueue_settings(self, session: Session) -> None:
        """Check POSIX message queue kernel settings."""
        settings = {
            "fs.mqueue.msg_max": 10,
            "fs.mqueue.msgsize_max": 8192,
            "fs.mqueue.queues_max": 256,
        }
        high_values = []

        for param, default in settings.items():
            result = session.execute(f"sysctl -n {param} 2>/dev/null")
            if result.success and result.output.strip():
                try:
                    value = int(result.output.strip())
                    # Flag if significantly higher than defaults
                    if value > default * 10:
                        high_values.append(f"{param} = {value} (default: {default})")
                except ValueError:
                    continue

        if high_values:
            self.add_finding(
                title="POSIX message queue limits set unusually high",
                description=(
                    "POSIX message queue kernel parameters are set significantly "
                    "above defaults, which could facilitate abuse of IPC for "
                    "covert data transfer or denial of service."
                ),
                severity=Severity.LOW,
                evidence="\n".join(high_values),
                remediation=(
                    "Review and restrict mqueue settings in /etc/sysctl.d/. "
                    "Set fs.mqueue.msg_max, fs.mqueue.msgsize_max, and "
                    "fs.mqueue.queues_max to appropriate values."
                ),
            )

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Audit D-Bus system policies in /etc/dbus-1/system.d/ and restrict allow rules to specific users/groups.",
            "Remove stale shared memory segments and message queues using ipcrm; enforce restrictive permissions in applications.",
            "Restrict POSIX mqueue kernel parameters in /etc/sysctl.d/ to prevent abuse as covert IPC channels.",
            "Avoid creating named pipes in world-writable directories; set permissions to 0600 or 0660.",
            "Use SELinux to enforce mandatory access controls on IPC mechanisms and confine inter-process communication.",
        ]

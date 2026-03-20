"""T1668 — Exclusive Control.

Checks for processes maintaining exclusive control over resources via file locks,
PID files preventing service restart, bind mounts hiding content, and mount
namespace isolation on RHEL systems.
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class ExclusiveControlCheck(BaseModule):
    TECHNIQUE_ID = "T1668"
    TECHNIQUE_NAME = "Exclusive Control"
    TACTIC = Tactic.PERSISTENCE
    SEVERITY = Severity.MEDIUM
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = True
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        # Check for processes holding exclusive file locks (flock)
        flock_holders = session.execute(
            "find /proc/*/fd -type l 2>/dev/null "
            "| while read fd; do "
            "target=$(readlink \"$fd\" 2>/dev/null); "
            "pid=$(echo \"$fd\" | cut -d/ -f3); "
            "if [ -f \"/proc/$pid/fdinfo/$(basename $fd)\" ]; then "
            "lock_info=$(grep 'lock:' \"/proc/$pid/fdinfo/$(basename $fd)\" 2>/dev/null); "
            "if [ -n \"$lock_info\" ]; then "
            "cmd=$(cat /proc/$pid/comm 2>/dev/null); "
            "echo \"PID=$pid CMD=$cmd FILE=$target LOCK=$lock_info\"; "
            "fi; fi; done 2>/dev/null | head -15"
        )
        if flock_holders.success and flock_holders.output.strip():
            self.add_finding(
                title="Processes holding exclusive file locks detected",
                description="Exclusive file locks can prevent legitimate services from accessing critical files or restarting",
                severity=Severity.MEDIUM,
                evidence=flock_holders.output.strip(),
                remediation="Investigate locked files and the processes holding them; terminate unauthorized lock holders",
            )

        # Alternative: check via /proc/locks for FLOCK exclusive locks
        proc_locks = session.execute(
            "cat /proc/locks 2>/dev/null | grep 'FLOCK.*WRITE' | head -15"
        )
        if proc_locks.success and proc_locks.output.strip():
            # Get details on the locking processes
            lock_details = session.execute(
                "cat /proc/locks 2>/dev/null | grep 'FLOCK.*WRITE' "
                "| awk '{print $5}' | while read pid; do "
                "echo \"PID=$pid CMD=$(cat /proc/$pid/comm 2>/dev/null) "
                "CMDLINE=$(cat /proc/$pid/cmdline 2>/dev/null | tr '\\0' ' ')\"; "
                "done | head -10"
            )
            self.add_finding(
                title="Exclusive FLOCK write locks active",
                description="Processes holding exclusive write locks can prevent services from accessing configuration or data files",
                severity=Severity.MEDIUM,
                evidence=lock_details.output.strip() if lock_details.success else proc_locks.output.strip(),
                remediation="Audit processes with exclusive locks; ensure no malicious process is blocking service access",
            )

        # Check for PID files that prevent service restart
        stale_pids = session.execute(
            "find /run /var/run -name '*.pid' -type f 2>/dev/null "
            "| while read pf; do "
            "pid=$(cat \"$pf\" 2>/dev/null); "
            "if [ -n \"$pid\" ] && ! kill -0 \"$pid\" 2>/dev/null; then "
            "echo \"STALE: $pf (PID=$pid — process not running)\"; "
            "fi; done | head -15"
        )
        if stale_pids.success and stale_pids.output.strip():
            self.add_finding(
                title="Stale PID files preventing service restart",
                description="PID files referencing dead processes can prevent services from starting, causing denial of service",
                severity=Severity.MEDIUM,
                evidence=stale_pids.output.strip(),
                remediation="Remove stale PID files and restart affected services; investigate why PID files were not cleaned up",
            )

        # Check for PID files with PIDs matching unexpected processes
        pid_mismatch = session.execute(
            "find /run /var/run -name '*.pid' -type f 2>/dev/null "
            "| while read pf; do "
            "pid=$(cat \"$pf\" 2>/dev/null); "
            "svc_name=$(basename \"$pf\" .pid); "
            "if [ -n \"$pid\" ] && kill -0 \"$pid\" 2>/dev/null; then "
            "actual_cmd=$(cat /proc/$pid/comm 2>/dev/null); "
            "if ! echo \"$actual_cmd\" | grep -qi \"$svc_name\"; then "
            "echo \"MISMATCH: $pf PID=$pid expected=$svc_name actual=$actual_cmd\"; "
            "fi; fi; done | head -10"
        )
        if pid_mismatch.success and pid_mismatch.output.strip():
            self.add_finding(
                title="PID files pointing to mismatched processes",
                description="PID files pointing to a different process than expected may indicate PID hijacking",
                severity=Severity.HIGH,
                evidence=pid_mismatch.output.strip(),
                remediation="Investigate mismatched PID files; verify the actual process and restart the legitimate service",
            )

        # Check for bind mounts hiding original content
        bind_mounts = session.execute(
            "findmnt -n -l -t none 2>/dev/null | grep '\\[' | head -10; "
            "mount 2>/dev/null | grep 'bind' | head -10"
        )
        if bind_mounts.success and bind_mounts.output.strip():
            # Focus on bind mounts over sensitive directories
            suspicious_binds = session.execute(
                "mount 2>/dev/null | grep 'bind' "
                "| grep -E '/etc/|/var/log|/usr/bin|/usr/sbin|/usr/lib' | head -10"
            )
            if suspicious_binds.success and suspicious_binds.output.strip():
                self.add_finding(
                    title="Bind mounts hiding content in sensitive directories",
                    description="Bind mounts over /etc, /var/log, or binary directories can hide tampered files or logs",
                    severity=Severity.CRITICAL,
                    evidence=suspicious_binds.output.strip(),
                    remediation="Unmount suspicious bind mounts; compare hidden content with the overlay using nsenter or umount",
                )
            else:
                self.add_finding(
                    title="Bind mounts detected on the system",
                    description="Bind mounts can overlay directories to hide malicious content from administrators",
                    severity=Severity.LOW,
                    evidence=bind_mounts.output.strip(),
                    remediation="Audit all bind mounts; verify they are legitimate and documented",
                )

        # Check for mount namespaces isolation
        mount_ns = session.execute(
            "ls -la /proc/*/ns/mnt 2>/dev/null | awk '{print $NF}' | sort -u | wc -l"
        )
        if mount_ns.success and mount_ns.output.strip():
            ns_count = 0
            try:
                ns_count = int(mount_ns.output.strip())
            except ValueError:
                pass
            if ns_count > 1:
                # Get details on processes with unique mount namespaces
                ns_details = session.execute(
                    "ls -la /proc/*/ns/mnt 2>/dev/null "
                    "| awk '{print $NF, $9}' | sort | uniq -f0 -D "
                    "| while read ns path; do "
                    "pid=$(echo \"$path\" | cut -d/ -f3); "
                    "echo \"NS=$ns PID=$pid CMD=$(cat /proc/$pid/comm 2>/dev/null)\"; "
                    "done 2>/dev/null | sort -u | head -15"
                )
                self.add_finding(
                    title=f"Multiple mount namespaces detected ({ns_count} unique)",
                    description="Processes in separate mount namespaces have isolated filesystem views, potentially hiding activity",
                    severity=Severity.MEDIUM,
                    evidence=ns_details.output.strip() if ns_details.success else f"Unique mount namespaces: {ns_count}",
                    remediation="Audit processes with non-default mount namespaces; use nsenter to inspect their filesystem views",
                )

        # Check for processes using CLONE_NEWNS (unshare)
        unshare_procs = session.execute(
            "ps aux 2>/dev/null | grep -E 'unshare.*--mount|unshare.*-m' | grep -v grep | head -10"
        )
        if unshare_procs.success and unshare_procs.output.strip():
            self.add_finding(
                title="Processes running with unshare mount namespace isolation",
                description="unshare --mount creates isolated mount namespaces that can hide filesystem modifications",
                severity=Severity.HIGH,
                evidence=unshare_procs.output.strip(),
                remediation="Investigate processes using unshare; ensure only authorized containers/sandboxes use mount namespaces",
            )

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Monitor for unauthorized bind mounts with auditd: -a always,exit -F arch=b64 -S mount -k mount_activity",
            "Restrict unshare(2) and mount namespace creation via SELinux or seccomp profiles",
            "Implement systemd service hardening with ProtectSystem=strict and ProtectHome=yes",
            "Configure tmpfiles.d to clean stale PID files at boot: /run/*.pid",
            "Use findmnt and nsenter regularly to audit mount namespaces and detect hidden filesystem overlays",
        ]

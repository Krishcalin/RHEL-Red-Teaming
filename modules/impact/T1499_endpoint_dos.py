"""T1499 — Endpoint Denial of Service.

Checks resource limits (cgroups, ulimits), fork bomb protection,
and service exhaustion controls on RHEL systems.
Sub-techniques: OS Exhaustion (T1499.001), Service Exhaustion (T1499.002),
Application Exhaustion (T1499.003).
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class EndpointDosCheck(BaseModule):
    TECHNIQUE_ID = "T1499"
    TECHNIQUE_NAME = "Endpoint Denial of Service"
    TACTIC = Tactic.IMPACT
    SEVERITY = Severity.HIGH
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        self._check_ulimits(session)
        self._check_cgroups(session)
        self._check_oom_settings(session)
        self._check_tmp_noexec(session)
        self._check_sysctl_limits(session)

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def _check_ulimits(self, session: Session) -> None:
        nproc = session.execute("ulimit -u 2>/dev/null")
        if nproc.success and nproc.output.strip():
            val = nproc.output.strip()
            if val == "unlimited":
                self.add_finding(
                    title="Max user processes is unlimited",
                    description="No process limit — fork bombs can exhaust system resources",
                    severity=Severity.HIGH,
                    evidence=f"ulimit -u: {val}",
                    remediation="Set limits in /etc/security/limits.conf: * hard nproc 4096",
                )

        nofile = session.execute("ulimit -n 2>/dev/null")
        if nofile.success and nofile.output.strip():
            val = nofile.output.strip()
            if val == "unlimited":
                self.add_finding(
                    title="Max open files is unlimited",
                    description="No file descriptor limit — file descriptor exhaustion is possible",
                    severity=Severity.MEDIUM,
                    evidence=f"ulimit -n: {val}",
                    remediation="Set limits in /etc/security/limits.conf: * hard nofile 65536",
                )

    def _check_cgroups(self, session: Session) -> None:
        cgroup_ver = session.execute("stat -f --format='%T' /sys/fs/cgroup 2>/dev/null")
        if cgroup_ver.success:
            ver = "v2" if "cgroup2" in cgroup_ver.output else "v1"
            result = session.execute(
                "systemctl show user-*.slice --property=TasksMax 2>/dev/null | head -3"
            )
            if result.success and result.output.strip():
                for line in result.output.strip().splitlines():
                    if "infinity" in line.lower():
                        self.add_finding(
                            title="User slice has unlimited tasks",
                            description=f"cgroups {ver} user slice has TasksMax=infinity — no per-user task limit",
                            severity=Severity.MEDIUM,
                            evidence=line.strip(),
                            remediation="Set TasksMax=256 in user slice: systemctl set-property user-.slice TasksMax=256",
                        )

    def _check_oom_settings(self, session: Session) -> None:
        panic = session.execute("cat /proc/sys/vm/panic_on_oom 2>/dev/null")
        if panic.success and panic.output.strip() == "1":
            self.add_finding(
                title="System will panic on OOM",
                description="vm.panic_on_oom=1 — out-of-memory triggers kernel panic instead of OOM killer",
                severity=Severity.MEDIUM,
                evidence="vm.panic_on_oom = 1",
                remediation="Set vm.panic_on_oom=0 to allow OOM killer to recover",
            )

        overcommit = session.execute("cat /proc/sys/vm/overcommit_memory 2>/dev/null")
        if overcommit.success and overcommit.output.strip() == "1":
            self.add_finding(
                title="Memory overcommit is always allowed",
                description="vm.overcommit_memory=1 — kernel never refuses memory allocations, increasing OOM risk",
                severity=Severity.MEDIUM,
                evidence="vm.overcommit_memory = 1",
                remediation="Set vm.overcommit_memory=2 for strict accounting, or 0 for heuristic",
            )

    def _check_tmp_noexec(self, session: Session) -> None:
        result = session.execute("mount | grep ' /tmp ' 2>/dev/null")
        if result.success and result.output.strip():
            if "noexec" not in result.output:
                self.add_finding(
                    title="/tmp is mounted without noexec",
                    description="Executables can be run from /tmp — common staging area for DoS tools",
                    severity=Severity.MEDIUM,
                    evidence=result.output.strip(),
                    remediation="Mount /tmp with noexec,nosuid,nodev options",
                )

    def _check_sysctl_limits(self, session: Session) -> None:
        checks = {
            "net.core.somaxconn": (128, "Low socket backlog — SYN flood exhaustion risk"),
            "net.ipv4.tcp_max_syn_backlog": (256, "Low SYN backlog"),
        }
        for key, (threshold, desc) in checks.items():
            result = session.execute(f"sysctl -n {key} 2>/dev/null")
            if result.success and result.output.strip():
                try:
                    val = int(result.output.strip())
                    if val <= threshold:
                        self.add_finding(
                            title=f"{key} is low ({val})",
                            description=f"{desc} — current value {val} <= {threshold}",
                            severity=Severity.LOW,
                            evidence=f"{key} = {val}",
                            remediation=f"Increase: sysctl -w {key}=4096",
                        )
                except ValueError:
                    pass

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Set process limits via /etc/security/limits.conf (nproc, nofile)",
            "Configure cgroups TasksMax and MemoryMax for user slices",
            "Mount /tmp with noexec,nosuid,nodev options",
            "Tune sysctl network parameters for SYN flood resilience",
            "Set vm.overcommit_memory=2 for strict memory accounting",
        ]

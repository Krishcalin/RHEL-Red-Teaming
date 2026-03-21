"""T1496 — Resource Hijacking.

Checks for cryptomining feasibility, GPU/compute access, CPU resource
controls, and unauthorized process detection on RHEL systems.
Sub-techniques: Compute Hijacking (T1496.001), Bandwidth Hijacking (T1496.002).
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class ResourceHijackingCheck(BaseModule):
    TECHNIQUE_ID = "T1496"
    TECHNIQUE_NAME = "Resource Hijacking"
    TACTIC = Tactic.IMPACT
    SEVERITY = Severity.HIGH
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        self._check_mining_tools(session)
        self._check_gpu_access(session)
        self._check_cpu_controls(session)
        self._check_suspicious_processes(session)
        self._check_container_escape(session)

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def _check_mining_tools(self, session: Session) -> None:
        miners = ["xmrig", "cpuminer", "minerd", "cgminer", "bfgminer",
                  "ethminer", "nbminer", "t-rex"]
        for miner in miners:
            result = session.execute(f"which {miner} 2>/dev/null || find /tmp /var/tmp /dev/shm -name '{miner}' 2>/dev/null")
            if result.success and result.output.strip():
                self.add_finding(
                    title=f"Cryptominer detected: {miner}",
                    description=f"Mining tool {miner} found at {result.output.strip()}",
                    severity=Severity.CRITICAL,
                    evidence=result.output.strip(),
                    remediation=f"Remove {miner} immediately; investigate how it was installed",
                )

    def _check_gpu_access(self, session: Session) -> None:
        nvidia = session.execute("ls /dev/nvidia* 2>/dev/null")
        if nvidia.success and nvidia.output.strip():
            self.add_finding(
                title="GPU devices accessible",
                description="NVIDIA GPU devices are available — can be used for compute hijacking",
                severity=Severity.MEDIUM,
                evidence=nvidia.output.strip()[:300],
                remediation="Restrict GPU device access via udev rules or cgroups device controller",
            )

    def _check_cpu_controls(self, session: Session) -> None:
        cpu_quota = session.execute(
            "systemctl show user-*.slice --property=CPUQuota 2>/dev/null | head -3"
        )
        if cpu_quota.success and cpu_quota.output.strip():
            for line in cpu_quota.output.strip().splitlines():
                if "infinity" in line.lower() or line.endswith("="):
                    self.add_finding(
                        title="No CPU quota on user slices",
                        description="User processes have no CPU quota — can consume all CPU for mining",
                        severity=Severity.MEDIUM,
                        evidence=line.strip(),
                        remediation="Set CPU quota: systemctl set-property user-.slice CPUQuota=80%",
                    )
                    break

    def _check_suspicious_processes(self, session: Session) -> None:
        result = session.execute(
            "ps -eo pid,user,%cpu,comm --sort=-%cpu 2>/dev/null | head -6"
        )
        if result.success and result.output.strip():
            for line in result.output.strip().splitlines()[1:]:
                parts = line.split()
                if len(parts) >= 4:
                    try:
                        cpu = float(parts[2])
                        proc = parts[3]
                        if cpu > 90.0:
                            self.add_finding(
                                title=f"High CPU process: {proc} ({cpu}%)",
                                description=f"Process {proc} is consuming {cpu}% CPU — potential resource hijacking",
                                severity=Severity.HIGH,
                                evidence=line.strip(),
                                remediation=f"Investigate process {proc} (PID {parts[0]}); kill if unauthorized",
                            )
                    except ValueError:
                        pass

    def _check_container_escape(self, session: Session) -> None:
        docker_sock = session.execute("test -S /var/run/docker.sock && ls -la /var/run/docker.sock 2>/dev/null")
        if docker_sock.success and docker_sock.output.strip():
            if "rw" in docker_sock.output:
                self.add_finding(
                    title="Docker socket is accessible",
                    description="Access to Docker socket enables container-based crypto mining",
                    severity=Severity.HIGH,
                    evidence=docker_sock.output.strip(),
                    remediation="Restrict Docker socket access; use rootless Docker or Podman",
                )

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Set CPU quotas on user slices via cgroups to limit compute abuse",
            "Monitor for known cryptominer binaries and high-CPU processes",
            "Restrict GPU and Docker socket access to authorised users only",
            "Mount /tmp, /var/tmp, /dev/shm with noexec to prevent miner staging",
            "Deploy process allow-listing (fapolicyd) to block unauthorized executables",
        ]

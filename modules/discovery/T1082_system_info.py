"""T1082 — System Information Discovery.

Checks what system information is accessible to unprivileged users.
Maps: uname, /etc/os-release, /proc/cpuinfo, /proc/meminfo, dmidecode.
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class SystemInfoCheck(BaseModule):
    TECHNIQUE_ID = "T1082"
    TECHNIQUE_NAME = "System Information Discovery"
    TACTIC = Tactic.DISCOVERY
    SEVERITY = Severity.INFO
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    INFO_COMMANDS = [
        ("uname -a", "Kernel and OS details"),
        ("cat /etc/os-release", "OS release information"),
        ("cat /proc/cpuinfo | head -20", "CPU information"),
        ("cat /proc/meminfo | head -5", "Memory information"),
        ("df -h", "Disk usage"),
        ("lscpu", "CPU architecture details"),
        ("hostnamectl", "Hostname and OS metadata"),
    ]

    RESTRICTED_COMMANDS = [
        ("dmidecode 2>/dev/null", "Hardware/BIOS details (dmidecode)"),
        ("cat /proc/version_signature 2>/dev/null", "Kernel version signature"),
    ]

    def check(self, session: Session) -> ModuleResult:
        exposed = []

        for cmd, desc in self.INFO_COMMANDS:
            result = session.execute(cmd)
            if result.success and result.output:
                exposed.append((desc, result.output[:500]))

        if exposed:
            for desc, output in exposed:
                self.add_finding(
                    title=f"System info exposed: {desc}",
                    description=f"{desc} is readable by the current user",
                    severity=Severity.INFO,
                    evidence=output,
                    remediation="Consider restricting with hidepid=2 on /proc or limiting shell access",
                )

        # Check kernel hardening parameters
        dmesg = session.execute("dmesg 2>&1; echo $?")
        if dmesg.output and not dmesg.output.strip().endswith("1"):
            self.add_finding(
                title="dmesg accessible to unprivileged users",
                description="kernel.dmesg_restrict is not set — kernel ring buffer is readable",
                severity=Severity.LOW,
                evidence=dmesg.output[:300],
                remediation="Set kernel.dmesg_restrict = 1 in /etc/sysctl.d/",
            )

        # Check /proc hidepid
        mount_info = session.execute("mount | grep 'proc.*hidepid'")
        if not mount_info.success or not mount_info.output:
            self.add_finding(
                title="/proc not mounted with hidepid",
                description="Other users' process information is visible via /proc",
                severity=Severity.LOW,
                evidence="hidepid not set on /proc",
                remediation="Mount /proc with hidepid=2 in /etc/fstab",
            )

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Set kernel.dmesg_restrict = 1",
            "Mount /proc with hidepid=2 or hidepid=invisible",
            "Restrict shell access for service accounts",
            "Use SELinux to confine process information access",
        ]

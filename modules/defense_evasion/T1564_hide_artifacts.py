"""T1564 — Hide Artifacts.

Checks for hidden files in temp/web directories, hidden/loop-mounted
filesystems, running VMs and containers, nohup processes, bind mounts
over system directories, and extended attributes on RHEL systems.
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class HideArtifactsCheck(BaseModule):
    TECHNIQUE_ID = "T1564"
    TECHNIQUE_NAME = "Hide Artifacts"
    TACTIC = Tactic.DEFENSE_EVASION
    SEVERITY = Severity.HIGH
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        self._check_hidden_files(session)
        self._check_hidden_filesystem(session)
        self._check_virtual_instances(session)
        self._check_ignore_interrupts(session)
        self._check_bind_mounts(session)
        self._check_extended_attributes(session)

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    # -- T1564.001 Hidden Files and Directories ----------------------------

    def _check_hidden_files(self, session: Session) -> None:
        search_dirs = ["/tmp", "/var/tmp", "/dev/shm"]
        # Also check common web roots
        web_roots = session.execute(
            "ls -d /var/www /srv/www /opt/www 2>/dev/null"
        )
        if web_roots.success and web_roots.output.strip():
            search_dirs.extend(web_roots.output.strip().splitlines())

        for directory in search_dirs:
            result = session.execute(
                f"find {directory} -maxdepth 3 -name '.*' -not -name '.' -not -name '..' 2>/dev/null | head -15"
            )
            if result.success and result.output.strip():
                files = result.output.strip().splitlines()
                self.add_finding(
                    title=f"Hidden files/dirs in {directory} ({len(files)} found)",
                    description=f"Hidden (dot-prefixed) files in {directory} may conceal malicious content",
                    severity=Severity.MEDIUM,
                    evidence="\n".join(files[:10]),
                    remediation=f"Investigate hidden files in {directory}; consider mounting with noexec",
                )

    # -- T1564.005 Hidden File System --------------------------------------

    def _check_hidden_filesystem(self, session: Session) -> None:
        # Loop-mounted filesystems
        result = session.execute("losetup -a 2>/dev/null")
        if result.success and result.output.strip():
            self.add_finding(
                title="Loop-mounted filesystems detected",
                description="Loop devices can hide encrypted or concealed filesystems",
                severity=Severity.HIGH,
                evidence=result.output.strip()[:500],
                remediation="Investigate loop mounts: losetup -a; unmount and examine backing files",
            )

        # Unexpected device-mapper entries
        result = session.execute(
            "ls -la /dev/mapper/ 2>/dev/null | grep -vE '(control|rhel|vg|lv|luks|swap)'"
        )
        if result.success and result.output.strip():
            lines = [l for l in result.output.strip().splitlines() if l.strip() and "total" not in l]
            if lines:
                self.add_finding(
                    title="Unexpected device-mapper entries",
                    description="Unknown entries in /dev/mapper/ may indicate hidden encrypted volumes",
                    severity=Severity.MEDIUM,
                    evidence="\n".join(lines[:10]),
                    remediation="Investigate unknown device-mapper entries with dmsetup info",
                )

    # -- T1564.006 Run Virtual Instance ------------------------------------

    def _check_virtual_instances(self, session: Session) -> None:
        # VMs
        vm_checks = [
            ("virsh list --all 2>/dev/null", "libvirt/KVM VMs"),
            ("VBoxManage list vms 2>/dev/null", "VirtualBox VMs"),
            ("pgrep -a qemu 2>/dev/null", "QEMU processes"),
        ]
        for cmd, desc in vm_checks:
            result = session.execute(cmd)
            if result.success and result.output.strip():
                self.add_finding(
                    title=f"Virtual machines detected: {desc}",
                    description=f"{desc} are running or configured on this host",
                    severity=Severity.MEDIUM,
                    evidence=result.output.strip()[:500],
                    remediation="Verify all VMs are authorized; disable virtualization if not needed on this host",
                )

        # Containers
        container_checks = [
            ("docker ps -a 2>/dev/null", "Docker containers"),
            ("podman ps -a 2>/dev/null", "Podman containers"),
        ]
        for cmd, desc in container_checks:
            result = session.execute(cmd)
            if result.success and result.output.strip():
                lines = result.output.strip().splitlines()
                if len(lines) > 1:  # Header + at least one container
                    self.add_finding(
                        title=f"Containers detected: {desc}",
                        description=f"{desc} are present on this host and could hide malicious workloads",
                        severity=Severity.MEDIUM,
                        evidence="\n".join(lines[:10]),
                        remediation="Audit all containers; enforce image signing and registry whitelisting",
                    )

    # -- T1564.011 Ignore Process Interrupts -------------------------------

    def _check_ignore_interrupts(self, session: Session) -> None:
        result = session.execute(
            "ps -eo pid,user,comm,args --no-headers 2>/dev/null | grep -i nohup | head -10"
        )
        if result.success and result.output.strip():
            self.add_finding(
                title="Processes launched with nohup detected",
                description="nohup processes ignore SIGHUP and persist after session logout",
                severity=Severity.LOW,
                evidence=result.output.strip()[:500],
                remediation="Investigate nohup processes; use systemd services for legitimate background tasks",
            )

        # Check for processes ignoring SIGHUP via /proc
        result = session.execute(
            "for pid in $(ls /proc/ 2>/dev/null | grep '^[0-9]' | head -100); do "
            "sig=$(cat /proc/$pid/status 2>/dev/null | grep SigIgn); "
            "if [ -n \"$sig\" ]; then "
            "val=$(echo $sig | awk '{print $2}'); "
            "if [ \"$((0x$val & 1))\" -eq 1 ]; then "
            "comm=$(cat /proc/$pid/comm 2>/dev/null); "
            "echo \"PID=$pid comm=$comm SigIgn=$val\"; fi; fi; done 2>/dev/null | head -10"
        )
        if result.success and result.output.strip():
            lines = result.output.strip().splitlines()
            if len(lines) > 3:
                self.add_finding(
                    title=f"Processes ignoring SIGHUP ({len(lines)} found)",
                    description="Multiple processes have SIGHUP in their signal ignore mask",
                    severity=Severity.LOW,
                    evidence="\n".join(lines[:10]),
                    remediation="Review processes ignoring signals; ensure they are legitimate daemons",
                )

    # -- T1564.013 Bind Mounts ---------------------------------------------

    def _check_bind_mounts(self, session: Session) -> None:
        result = session.execute("findmnt -t none -o TARGET,SOURCE,OPTIONS 2>/dev/null | grep bind")
        if result.success and result.output.strip():
            for line in result.output.strip().splitlines():
                target = line.split()[0] if line.split() else "unknown"
                if any(sys_dir in target for sys_dir in ("/usr", "/etc", "/bin", "/sbin", "/lib")):
                    self.add_finding(
                        title=f"Bind mount over system directory: {target}",
                        description="A bind mount over a system directory can hide or replace system files",
                        severity=Severity.CRITICAL,
                        evidence=line.strip(),
                        remediation="Investigate bind mounts over system directories; unmount if unauthorized",
                    )
                else:
                    self.add_finding(
                        title=f"Bind mount detected: {target}",
                        description="Bind mounts can be used to overlay directories and hide content",
                        severity=Severity.MEDIUM,
                        evidence=line.strip(),
                        remediation="Verify bind mount is authorized and documented",
                    )

    # -- T1564.014 Extended Attributes -------------------------------------

    def _check_extended_attributes(self, session: Session) -> None:
        for directory in ("/usr/bin", "/usr/sbin", "/usr/local/bin"):
            result = session.execute(
                f"find {directory} -maxdepth 1 -type f -executable 2>/dev/null | "
                "while read f; do "
                "attrs=$(getfattr -d \"$f\" 2>/dev/null | grep -v '^#' | grep -v '^$'); "
                "[ -n \"$attrs\" ] && echo \"$f: $attrs\"; done | head -10"
            )
            if result.success and result.output.strip():
                self.add_finding(
                    title=f"Extended attributes found on binaries in {directory}",
                    description="Extended attributes on executables could hide data or metadata",
                    severity=Severity.MEDIUM,
                    evidence=result.output.strip()[:500],
                    remediation=f"Review extended attributes with getfattr -d on binaries in {directory}",
                )

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Mount /tmp, /var/tmp, and /dev/shm with noexec,nosuid,nodev to limit hidden file execution",
            "Monitor bind mounts and loop devices with auditd watches on mount syscalls",
            "Restrict container and VM usage to authorized administrators only",
            "Use AIDE or rpm -Va to detect unexpected files and extended attributes",
            "Enable SELinux to prevent unauthorized filesystem operations and overlays",
        ]

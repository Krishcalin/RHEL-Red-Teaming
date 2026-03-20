"""T1027 — Obfuscated Files or Information.

Checks for packed binaries, compiler availability in temp paths,
base64-encoded commands in scheduled tasks, fileless storage in
environment variables and /dev/shm, and encoded files in temp
directories on RHEL systems.
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class ObfuscatedFilesCheck(BaseModule):
    TECHNIQUE_ID = "T1027"
    TECHNIQUE_NAME = "Obfuscated Files or Information"
    TACTIC = Tactic.DEFENSE_EVASION
    SEVERITY = Severity.MEDIUM
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        self._check_software_packing(session)
        self._check_compile_after_delivery(session)
        self._check_command_obfuscation(session)
        self._check_fileless_storage(session)
        self._check_encoded_files(session)

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    # -- T1027.002 Software Packing ----------------------------------------

    def _check_software_packing(self, session: Session) -> None:
        # Check for UPX-packed binaries in unusual locations
        upx_available = session.execute("which upx 2>/dev/null")
        if upx_available.success and upx_available.output.strip():
            self.add_finding(
                title="UPX packer is installed",
                description="UPX can be used to pack binaries, hiding their true contents",
                severity=Severity.MEDIUM,
                evidence=upx_available.output.strip(),
                remediation="Remove UPX if not needed: yum remove upx",
            )

        # Check for stripped binaries in unusual locations
        result = session.execute(
            "find /tmp /var/tmp /dev/shm -type f -executable 2>/dev/null | "
            "while read f; do file \"$f\" 2>/dev/null | grep -q 'stripped' && echo \"$f\"; done | head -10"
        )
        if result.success and result.output.strip():
            self.add_finding(
                title="Stripped executables found in temp directories",
                description="Stripped binaries in temporary locations may indicate packed or obfuscated malware",
                severity=Severity.HIGH,
                evidence=result.output.strip()[:500],
                remediation="Investigate stripped binaries in /tmp, /var/tmp, /dev/shm; mount with noexec",
            )

    # -- T1027.004 Compile After Delivery ----------------------------------

    def _check_compile_after_delivery(self, session: Session) -> None:
        compilers = ["gcc", "g++", "cc", "make", "as", "ld"]
        found = []
        for compiler in compilers:
            result = session.execute(f"which {compiler} 2>/dev/null")
            if result.success and result.output.strip():
                found.append(f"{compiler}: {result.output.strip()}")

        if found:
            self.add_finding(
                title=f"Compilation tools available ({len(found)} found)",
                description="Compilers and build tools are installed, enabling compile-after-delivery attacks",
                severity=Severity.MEDIUM,
                evidence="\n".join(found),
                remediation="Remove development tools from production systems: yum groupremove 'Development Tools'",
            )

        # Check for source files in temp directories
        result = session.execute(
            "find /tmp /dev/shm /var/tmp -maxdepth 3 -type f "
            "\\( -name '*.c' -o -name '*.cpp' -o -name '*.h' -o -name 'Makefile' -o -name '*.py' -o -name '*.pl' \\) "
            "2>/dev/null | head -15"
        )
        if result.success and result.output.strip():
            self.add_finding(
                title="Source code files found in temp directories",
                description="Source files in /tmp or /dev/shm may indicate compile-after-delivery activity",
                severity=Severity.HIGH,
                evidence=result.output.strip()[:500],
                remediation="Investigate source files in temp directories; mount temp dirs with noexec",
            )

    # -- T1027.010 Command Obfuscation -------------------------------------

    def _check_command_obfuscation(self, session: Session) -> None:
        # Check crontabs for base64-encoded commands
        result = session.execute(
            "grep -r 'base64' /var/spool/cron/ /etc/cron.d/ /etc/crontab 2>/dev/null | "
            "grep -v '^#' | head -10"
        )
        if result.success and result.output.strip():
            self.add_finding(
                title="Base64 references found in cron jobs",
                description="Cron entries referencing base64 may contain obfuscated commands",
                severity=Severity.HIGH,
                evidence=result.output.strip()[:500],
                remediation="Review and decode all base64 references in cron configurations",
            )

        # Check systemd service files for base64
        result = session.execute(
            "grep -rl 'base64' /etc/systemd/system/ /run/systemd/system/ 2>/dev/null | head -10"
        )
        if result.success and result.output.strip():
            self.add_finding(
                title="Base64 references found in systemd service files",
                description="Service unit files containing base64 may hide obfuscated commands",
                severity=Severity.HIGH,
                evidence=result.output.strip()[:500],
                remediation="Audit systemd service files for encoded payloads; compare against vendor originals",
            )

    # -- T1027.011 Fileless Storage ----------------------------------------

    def _check_fileless_storage(self, session: Session) -> None:
        # Check /dev/shm for suspicious files
        result = session.execute("find /dev/shm -type f 2>/dev/null | head -20")
        if result.success and result.output.strip():
            files = result.output.strip().splitlines()
            self.add_finding(
                title=f"Files found in /dev/shm ({len(files)} files)",
                description="/dev/shm is a tmpfs filesystem stored in RAM — ideal for fileless payloads",
                severity=Severity.MEDIUM,
                evidence="\n".join(files[:10]),
                remediation="Mount /dev/shm with noexec,nosuid,nodev; investigate any unexpected files",
            )

        # Check for large environment variables that might store data
        result = session.execute(
            "env 2>/dev/null | awk -F= '{if (length($2) > 500) print $1 \" (\" length($2) \" chars)\"}' | head -10"
        )
        if result.success and result.output.strip():
            self.add_finding(
                title="Large environment variables detected",
                description="Unusually large environment variables may be used for fileless data storage",
                severity=Severity.LOW,
                evidence=result.output.strip()[:500],
                remediation="Investigate oversized environment variables; audit /etc/environment and profile scripts",
            )

    # -- T1027.013 Encrypted / Encoded Files -------------------------------

    def _check_encoded_files(self, session: Session) -> None:
        for tmp_dir in ("/tmp", "/var/tmp", "/dev/shm"):
            result = session.execute(
                f"find {tmp_dir} -maxdepth 2 -type f -size +1k 2>/dev/null | "
                "while read f; do "
                "head -1 \"$f\" 2>/dev/null | grep -qE '^[A-Za-z0-9+/=]{50,}$' && echo \"$f\"; "
                "done | head -10"
            )
            if result.success and result.output.strip():
                self.add_finding(
                    title=f"Possible base64-encoded files in {tmp_dir}",
                    description="Files beginning with long base64 strings may contain encoded payloads",
                    severity=Severity.MEDIUM,
                    evidence=result.output.strip()[:500],
                    remediation=f"Investigate and decode suspicious files in {tmp_dir}",
                )

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Remove compilers and development tools from production servers",
            "Mount /tmp, /var/tmp, and /dev/shm with noexec,nosuid,nodev",
            "Deploy fapolicyd or AIDE to detect unauthorized executables",
            "Monitor cron and systemd service files for obfuscated content with auditd",
            "Use SELinux to restrict script interpreter execution in temp directories",
        ]

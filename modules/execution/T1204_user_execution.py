"""T1204 — User Execution.

Checks for conditions that allow users to download and execute malicious
files, including missing noexec mount options, executable files in
world-writable directories, and insecure desktop file associations.
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class UserExecutionCheck(BaseModule):
    TECHNIQUE_ID = "T1204"
    TECHNIQUE_NAME = "User Execution"
    TACTIC = Tactic.EXECUTION
    SEVERITY = Severity.MEDIUM
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    NOEXEC_PATHS = ["/tmp", "/home", "/var/tmp", "/dev/shm"]

    def check(self, session: Session) -> ModuleResult:
        self._check_noexec_mounts(session)
        self._check_executables_in_world_writable(session)
        self._check_download_and_execute(session)
        self._check_desktop_files(session)
        self._check_mime_handlers(session)

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def _check_noexec_mounts(self, session: Session) -> None:
        """Check if noexec is set on /tmp, /home, /var/tmp, /dev/shm."""
        result = session.execute("mount 2>/dev/null")
        if not result.success or not result.output.strip():
            return

        mount_lines = result.output.strip().splitlines()
        missing_noexec = []

        for path in self.NOEXEC_PATHS:
            found_mount = False
            has_noexec = False
            for line in mount_lines:
                parts = line.split()
                if len(parts) >= 3 and parts[2] == path:
                    found_mount = True
                    if "noexec" in line:
                        has_noexec = True
                    break

            if found_mount and not has_noexec:
                missing_noexec.append(path)
            elif not found_mount and path in ("/tmp", "/var/tmp", "/dev/shm"):
                # These should ideally be separate mounts
                missing_noexec.append(f"{path} (not a separate mount)")

        if missing_noexec:
            self.add_finding(
                title="Filesystem paths missing noexec mount option",
                description=(
                    "Directories commonly used for temporary file storage are mounted "
                    "without the noexec option, allowing execution of downloaded files."
                ),
                severity=Severity.MEDIUM,
                evidence="\n".join(missing_noexec),
                remediation=(
                    "Add noexec,nosuid,nodev mount options in /etc/fstab for "
                    "/tmp, /var/tmp, /dev/shm, and /home. "
                    "Remount with: mount -o remount,noexec <path>"
                ),
            )

    def _check_executables_in_world_writable(self, session: Session) -> None:
        """Check for executable files in world-writable directories."""
        result = session.execute(
            "find /tmp /var/tmp /dev/shm -type f -executable "
            "-maxdepth 3 2>/dev/null | head -20"
        )
        if result.success and result.output.strip():
            files = result.output.strip().splitlines()
            self.add_finding(
                title="Executable files found in world-writable directories",
                description=(
                    f"{len(files)} executable file(s) found in world-writable "
                    "directories (/tmp, /var/tmp, /dev/shm). These could be "
                    "attacker-planted payloads."
                ),
                severity=Severity.MEDIUM,
                evidence="\n".join(files[:10]),
                remediation=(
                    "Mount /tmp, /var/tmp, /dev/shm with noexec. "
                    "Regularly audit and clean executable files in these locations."
                ),
            )

    def _check_download_and_execute(self, session: Session) -> None:
        """Check if users can download and execute files (wget, curl + chmod)."""
        download_tools = []
        for tool in ("wget", "curl"):
            result = session.execute(f"which {tool} 2>/dev/null")
            if result.success and result.output.strip():
                download_tools.append(result.output.strip())

        if download_tools:
            # Check if chmod is available (it always should be, but check suid)
            chmod_result = session.execute("which chmod 2>/dev/null")
            if chmod_result.success and chmod_result.output.strip():
                self.add_finding(
                    title="Download-and-execute capability available",
                    description=(
                        "Download tools and chmod are available, enabling users to "
                        "fetch remote payloads and make them executable. "
                        "Combined with writable+executable paths, this is a common attack vector."
                    ),
                    severity=Severity.LOW,
                    evidence="Available tools: " + ", ".join(download_tools),
                    remediation=(
                        "Restrict wget/curl access via SELinux policy or remove "
                        "from non-admin systems. Mount writable paths with noexec."
                    ),
                )

    def _check_desktop_files(self, session: Session) -> None:
        """Check .desktop files for potentially malicious Exec= entries."""
        result = session.execute(
            "find /usr/share/applications /home -name '*.desktop' "
            "-exec grep -l 'Exec=' {} \\; 2>/dev/null | head -30"
        )
        if not result.success or not result.output.strip():
            return

        desktop_files = result.output.strip().splitlines()

        # Check for suspicious patterns in desktop files
        suspicious = []
        for df in desktop_files[:15]:
            df = df.strip()
            if not df:
                continue
            exec_result = session.execute(f"grep '^Exec=' '{df}' 2>/dev/null")
            if exec_result.success and exec_result.output.strip():
                exec_line = exec_result.output.strip()
                # Look for suspicious patterns
                for pattern in ("/tmp/", "/var/tmp/", "curl ", "wget ", "bash -c", "sh -c"):
                    if pattern in exec_line:
                        suspicious.append(f"{df}: {exec_line}")
                        break

        if suspicious:
            self.add_finding(
                title="Suspicious .desktop file entries found",
                description=(
                    "Desktop files with suspicious Exec= entries were found, "
                    "potentially pointing to malicious commands or temporary paths."
                ),
                severity=Severity.HIGH,
                evidence="\n".join(suspicious[:10]),
                remediation=(
                    "Audit all .desktop files for suspicious Exec= entries. "
                    "Ensure only trusted applications have desktop entries."
                ),
            )

    def _check_mime_handlers(self, session: Session) -> None:
        """Check MIME type handler associations for risky defaults."""
        # Check if xdg-open is available and what handles common risky types
        result = session.execute("which xdg-open 2>/dev/null")
        if not result.success or not result.output.strip():
            return

        risky_mimes = [
            "application/x-executable",
            "application/x-shellscript",
            "text/x-python",
        ]
        findings_evidence = []

        for mime in risky_mimes:
            handler = session.execute(
                f"xdg-mime query default {mime} 2>/dev/null"
            )
            if handler.success and handler.output.strip():
                findings_evidence.append(f"{mime} -> {handler.output.strip()}")

        if findings_evidence:
            self.add_finding(
                title="MIME handlers configured for executable content types",
                description=(
                    "MIME type handlers are configured for executable content types, "
                    "which could allow automatic execution when users open files."
                ),
                severity=Severity.LOW,
                evidence="\n".join(findings_evidence),
                remediation=(
                    "Review and restrict MIME type associations for executable "
                    "content types. Remove unnecessary handlers from /usr/share/applications/mimeinfo.cache."
                ),
            )

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Mount /tmp, /var/tmp, /dev/shm, and /home with noexec,nosuid,nodev options in /etc/fstab.",
            "Remove wget and curl from non-admin systems or restrict via SELinux booleans.",
            "Enable and configure fapolicyd to whitelist approved executables only.",
            "Audit .desktop files and MIME handlers regularly for unauthorized changes.",
            "Use tmpwatch or systemd-tmpfiles to automatically clean temporary directories.",
        ]

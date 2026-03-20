"""T1656 — Impersonation.

Checks for user namespace impersonation, su/sudo identity logging,
misleading process names, symlink attacks in /tmp, and TIOCSTI terminal
injection availability on RHEL systems.
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class ImpersonationCheck(BaseModule):
    TECHNIQUE_ID = "T1656"
    TECHNIQUE_NAME = "Impersonation"
    TACTIC = Tactic.DEFENSE_EVASION
    SEVERITY = Severity.MEDIUM
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        self._check_user_namespaces(session)
        self._check_su_sudo_logging(session)
        self._check_misleading_processes(session)
        self._check_tmp_symlink_attacks(session)
        self._check_tiocsti(session)

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    # -- User namespace support for unprivileged impersonation ----------------

    def _check_user_namespaces(self, session: Session) -> None:
        # Check if unprivileged user namespaces are enabled
        userns = session.execute("cat /proc/sys/user/max_user_namespaces 2>/dev/null || true")
        if userns.success and userns.output.strip():
            try:
                max_ns = int(userns.output.strip())
                if max_ns > 0:
                    self.add_finding(
                        title=f"Unprivileged user namespaces enabled (max={max_ns})",
                        description=(
                            "User namespaces allow unprivileged users to create isolated "
                            "environments where they appear as root (UID 0). This can be "
                            "used to impersonate privileged users or exploit kernel vulnerabilities "
                            "that require specific UID mappings."
                        ),
                        severity=Severity.MEDIUM,
                        evidence=f"user.max_user_namespaces={max_ns}",
                        remediation="Disable user namespaces if not needed: sysctl -w user.max_user_namespaces=0 and persist in /etc/sysctl.d/",
                    )
            except ValueError:
                pass

        # Check for unprivileged_userns_clone (older kernels)
        userns_clone = session.execute("cat /proc/sys/kernel/unprivileged_userns_clone 2>/dev/null || true")
        if userns_clone.success and userns_clone.output.strip() == "1":
            self.add_finding(
                title="Unprivileged user namespace cloning enabled",
                description="The kernel allows unprivileged users to clone user namespaces, enabling UID impersonation",
                severity=Severity.MEDIUM,
                evidence="unprivileged_userns_clone=1",
                remediation="Disable: sysctl -w kernel.unprivileged_userns_clone=0",
            )

    # -- su/sudo logging captures original user identity ----------------------

    def _check_su_sudo_logging(self, session: Session) -> None:
        # Check if sudo logs capture the original user
        sudo_log = session.execute("grep -i 'log_output\\|logfile\\|syslog' /etc/sudoers /etc/sudoers.d/* 2>/dev/null || true")
        if sudo_log.success:
            if "log_output" not in sudo_log.output and "logfile" not in sudo_log.output:
                self.add_finding(
                    title="sudo session I/O logging not enabled",
                    description=(
                        "sudo does not log session I/O (log_output). Without session logging, "
                        "actions taken after privilege escalation cannot be attributed to "
                        "the original user identity."
                    ),
                    severity=Severity.MEDIUM,
                    evidence="No log_output or logfile directive found in sudoers",
                    remediation="Add 'Defaults log_output' to /etc/sudoers to enable session I/O logging",
                )

        # Check if su logs to syslog
        pam_su_syslog = session.execute("grep 'pam_syslog\\|pam_tty_audit' /etc/pam.d/su /etc/pam.d/su-l 2>/dev/null || true")
        if not pam_su_syslog.success or not pam_su_syslog.output.strip():
            # Check if at least session logging exists
            su_session = session.execute("grep 'session.*pam_unix\\|session.*pam_systemd' /etc/pam.d/su 2>/dev/null || true")
            if not su_session.success or not su_session.output.strip():
                self.add_finding(
                    title="su session logging may be insufficient",
                    description="The su PAM configuration may not adequately log session events, making user impersonation harder to detect",
                    severity=Severity.LOW,
                    evidence="Limited session logging in /etc/pam.d/su",
                    remediation="Add pam_tty_audit to /etc/pam.d/su for keystroke logging of privileged sessions",
                )

        # Check for pam_tty_audit (logs keystrokes for specific users)
        tty_audit = session.execute("grep -r 'pam_tty_audit' /etc/pam.d/ 2>/dev/null || true")
        if not tty_audit.success or not tty_audit.output.strip():
            self.add_finding(
                title="TTY audit logging not configured",
                description=(
                    "pam_tty_audit is not configured in any PAM service. Without TTY auditing, "
                    "commands typed during su/sudo sessions are not captured, hindering "
                    "identification of the original actor."
                ),
                severity=Severity.MEDIUM,
                evidence="No pam_tty_audit found in /etc/pam.d/",
                remediation="Add 'session required pam_tty_audit.so enable=*' to /etc/pam.d/system-auth",
            )

    # -- Processes running under misleading user names ------------------------

    def _check_misleading_processes(self, session: Session) -> None:
        # Check for processes where the executable name doesn't match the comm field
        # (process has renamed itself via prctl PR_SET_NAME or argv[0] manipulation)
        mismatched = session.execute(
            "for pid in $(ls /proc/ 2>/dev/null | grep -E '^[0-9]+$' | head -100); do "
            "comm=$(cat /proc/$pid/comm 2>/dev/null) && "
            "exe=$(readlink /proc/$pid/exe 2>/dev/null | xargs basename 2>/dev/null) && "
            "if [ -n \"$comm\" ] && [ -n \"$exe\" ] && [ \"$comm\" != \"$exe\" ]; then "
            "echo \"PID=$pid comm=$comm exe=$exe\"; fi; done 2>/dev/null | head -20"
        )
        if mismatched.success and mismatched.output.strip():
            lines = mismatched.output.strip().splitlines()
            # Filter common false positives
            suspicious = []
            known_ok = ["bash", "sh", "python", "python3", "java", "node", "ruby", "perl"]
            for line in lines:
                is_known = False
                for ok in known_ok:
                    if f"exe={ok}" in line:
                        is_known = True
                        break
                if not is_known:
                    suspicious.append(line)

            if suspicious:
                self.add_finding(
                    title=f"Processes with mismatched names ({len(suspicious)} found)",
                    description=(
                        "Processes have different names in /proc/comm vs their actual executable. "
                        "This could indicate process name spoofing to impersonate legitimate services."
                    ),
                    severity=Severity.MEDIUM,
                    evidence="\n".join(suspicious[:10]),
                    remediation="Investigate mismatched processes; use auditd to monitor prctl PR_SET_NAME calls",
                )

    # -- Symlink attacks in /tmp (sticky bit) ---------------------------------

    def _check_tmp_symlink_attacks(self, session: Session) -> None:
        # Check if protected_symlinks is enabled
        symlink_protection = session.execute("cat /proc/sys/fs/protected_symlinks 2>/dev/null || true")
        if symlink_protection.success and symlink_protection.output.strip() == "0":
            self.add_finding(
                title="Symlink protection disabled (fs.protected_symlinks=0)",
                description=(
                    "The kernel does not enforce symlink ownership checks in world-writable "
                    "directories. An attacker can create symlinks in /tmp pointing to "
                    "sensitive files, tricking privileged processes into reading/writing "
                    "the wrong files (impersonation via file system)."
                ),
                severity=Severity.HIGH,
                evidence="fs.protected_symlinks=0",
                remediation="Enable symlink protection: sysctl -w fs.protected_symlinks=1 and persist in /etc/sysctl.d/",
            )

        # Check if protected_hardlinks is enabled
        hardlink_protection = session.execute("cat /proc/sys/fs/protected_hardlinks 2>/dev/null || true")
        if hardlink_protection.success and hardlink_protection.output.strip() == "0":
            self.add_finding(
                title="Hardlink protection disabled (fs.protected_hardlinks=0)",
                description="The kernel does not enforce hardlink restrictions, allowing hardlink-based impersonation attacks",
                severity=Severity.HIGH,
                evidence="fs.protected_hardlinks=0",
                remediation="Enable hardlink protection: sysctl -w fs.protected_hardlinks=1 and persist in /etc/sysctl.d/",
            )

        # Check sticky bit on /tmp
        tmp_perms = session.execute("stat -c '%a' /tmp 2>/dev/null || true")
        if tmp_perms.success and tmp_perms.output.strip():
            mode = tmp_perms.output.strip()
            if not mode.startswith("1"):
                self.add_finding(
                    title=f"/tmp does not have sticky bit set (mode={mode})",
                    description="Without the sticky bit, users can delete or rename other users' files in /tmp, enabling impersonation attacks",
                    severity=Severity.HIGH,
                    evidence=f"/tmp mode: {mode}",
                    remediation="Set sticky bit: chmod 1777 /tmp",
                )

    # -- TIOCSTI ioctl availability (terminal injection) ----------------------

    def _check_tiocsti(self, session: Session) -> None:
        # Check if TIOCSTI is restricted (kernel 6.2+ or with patch)
        tiocsti = session.execute("cat /proc/sys/dev/tty/legacy_tiocsti 2>/dev/null || true")
        if tiocsti.success and tiocsti.output.strip():
            if tiocsti.output.strip() == "1":
                self.add_finding(
                    title="TIOCSTI ioctl is enabled (legacy_tiocsti=1)",
                    description=(
                        "The TIOCSTI ioctl allows a process to inject characters into "
                        "another process's terminal input. An attacker can use this to "
                        "inject commands into a parent shell after sudo/su, effectively "
                        "impersonating the parent user's session."
                    ),
                    severity=Severity.MEDIUM,
                    evidence="dev.tty.legacy_tiocsti=1",
                    remediation="Disable TIOCSTI: sysctl -w dev.tty.legacy_tiocsti=0 and persist in /etc/sysctl.d/",
                )
        else:
            # On older kernels without the sysctl, TIOCSTI is always available
            kernel_ver = session.execute("uname -r 2>/dev/null || true")
            if kernel_ver.success and kernel_ver.output.strip():
                ver = kernel_ver.output.strip()
                # TIOCSTI restriction was added in kernel 6.2
                try:
                    major_minor = ver.split(".")[:2]
                    major = int(major_minor[0])
                    minor = int(major_minor[1])
                    if major < 6 or (major == 6 and minor < 2):
                        self.add_finding(
                            title=f"TIOCSTI ioctl unrestricted (kernel {ver})",
                            description=(
                                "The running kernel predates TIOCSTI restrictions (added in 6.2). "
                                "Any process can inject keystrokes into other terminals on the same TTY, "
                                "enabling command injection and user impersonation."
                            ),
                            severity=Severity.MEDIUM,
                            evidence=f"Kernel version: {ver}",
                            remediation="Update to kernel 6.2+ and set dev.tty.legacy_tiocsti=0, or use SELinux to restrict ioctl calls",
                        )
                except (ValueError, IndexError):
                    pass

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Disable unprivileged user namespaces if not needed: sysctl -w user.max_user_namespaces=0",
            "Enable sudo I/O logging (Defaults log_output) and deploy pam_tty_audit for keystroke capture",
            "Enable fs.protected_symlinks=1 and fs.protected_hardlinks=1 to prevent symlink/hardlink attacks",
            "Disable TIOCSTI on kernel 6.2+: sysctl -w dev.tty.legacy_tiocsti=0",
            "Monitor for process name spoofing with auditd rules on prctl and execve syscalls",
        ]

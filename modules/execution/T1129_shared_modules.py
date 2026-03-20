"""T1129 — Shared Modules.

Checks for insecure shared library loading configurations on RHEL systems.
Covers LD_PRELOAD, LD_LIBRARY_PATH, ld.so.preload, writable library paths,
and ld.so.conf.d entries.
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class SharedModulesCheck(BaseModule):
    TECHNIQUE_ID = "T1129"
    TECHNIQUE_NAME = "Shared Modules"
    TACTIC = Tactic.EXECUTION
    SEVERITY = Severity.MEDIUM
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    SYSTEM_LIB_DIRS = ["/usr/lib64", "/usr/lib", "/lib64", "/lib"]

    def check(self, session: Session) -> ModuleResult:
        self._check_ld_preload_env(session)
        self._check_ld_so_preload(session)
        self._check_ld_library_path(session)
        self._check_writable_lib_paths(session)
        self._check_writable_shared_libs(session)
        self._check_ld_so_conf(session)

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def _check_ld_preload_env(self, session: Session) -> None:
        """Check if LD_PRELOAD is set in the current environment."""
        result = session.execute("echo ${LD_PRELOAD:-}")
        if result.success and result.output.strip():
            self.add_finding(
                title="LD_PRELOAD environment variable is set",
                description=(
                    "LD_PRELOAD is set, which forces the dynamic linker to load "
                    "specified shared libraries before all others. Attackers use this "
                    "to hijack library calls."
                ),
                severity=Severity.HIGH,
                evidence=f"LD_PRELOAD={result.output.strip()}",
                remediation="Unset LD_PRELOAD and investigate the source of the setting.",
            )

        # Check for LD_PRELOAD in profile scripts
        profile_preload = session.execute(
            "grep -r 'LD_PRELOAD' /etc/profile /etc/profile.d/ /etc/environment /etc/bashrc 2>/dev/null"
        )
        if profile_preload.success and profile_preload.output.strip():
            self.add_finding(
                title="LD_PRELOAD configured in system profile scripts",
                description="LD_PRELOAD is set in a system-wide profile script, affecting all users.",
                severity=Severity.HIGH,
                evidence=profile_preload.output[:500],
                remediation="Remove LD_PRELOAD entries from system profile scripts.",
            )

    def _check_ld_so_preload(self, session: Session) -> None:
        """Check /etc/ld.so.preload for preloaded libraries."""
        result = session.execute("cat /etc/ld.so.preload 2>/dev/null")
        if result.success and result.output.strip():
            entries = [
                l.strip() for l in result.output.splitlines()
                if l.strip() and not l.strip().startswith("#")
            ]
            if entries:
                self.add_finding(
                    title=f"/etc/ld.so.preload contains {len(entries)} entr(y/ies)",
                    description=(
                        "Libraries listed in /etc/ld.so.preload are loaded into every "
                        "dynamically-linked process. This is a common persistence mechanism."
                    ),
                    severity=Severity.HIGH,
                    evidence="\n".join(entries),
                    remediation=(
                        "Review each entry in /etc/ld.so.preload. Remove unauthorized libraries. "
                        "Protect the file: chattr +i /etc/ld.so.preload"
                    ),
                )

        # Check file permissions
        preload_perms = session.execute("stat -c '%a %U:%G' /etc/ld.so.preload 2>/dev/null")
        if preload_perms.success and preload_perms.output.strip():
            perms = preload_perms.output.strip().split()[0]
            if int(perms[-1]) >= 2:  # world-writable
                self.add_finding(
                    title="/etc/ld.so.preload is world-writable",
                    description="Any user can add libraries to /etc/ld.so.preload for system-wide code injection.",
                    severity=Severity.CRITICAL,
                    evidence=preload_perms.output.strip(),
                    remediation="chmod 644 /etc/ld.so.preload && chown root:root /etc/ld.so.preload",
                )

    def _check_ld_library_path(self, session: Session) -> None:
        """Check if LD_LIBRARY_PATH is set broadly."""
        result = session.execute("echo ${LD_LIBRARY_PATH:-}")
        if result.success and result.output.strip():
            self.add_finding(
                title="LD_LIBRARY_PATH is set",
                description=(
                    "LD_LIBRARY_PATH overrides the default library search order, "
                    "which can be abused to load malicious shared libraries."
                ),
                severity=Severity.MEDIUM,
                evidence=f"LD_LIBRARY_PATH={result.output.strip()}",
                remediation="Avoid setting LD_LIBRARY_PATH globally. Use rpath or ldconfig instead.",
            )

        # Check for system-wide LD_LIBRARY_PATH settings
        sys_ldpath = session.execute(
            "grep -r 'LD_LIBRARY_PATH' /etc/profile /etc/profile.d/ /etc/environment /etc/bashrc 2>/dev/null"
        )
        if sys_ldpath.success and sys_ldpath.output.strip():
            self.add_finding(
                title="LD_LIBRARY_PATH set in system profile scripts",
                description="LD_LIBRARY_PATH is configured system-wide, affecting all users' library resolution.",
                severity=Severity.MEDIUM,
                evidence=sys_ldpath.output[:500],
                remediation="Remove LD_LIBRARY_PATH from profile scripts; use ldconfig or rpath instead.",
            )

    def _check_writable_lib_paths(self, session: Session) -> None:
        """Check for writable directories in the library search path."""
        result = session.execute(
            "ldconfig -v 2>/dev/null | grep '^/' | tr -d ':'"
        )
        if result.success and result.output.strip():
            lib_dirs = result.output.strip().splitlines()
            for lib_dir in lib_dirs:
                lib_dir = lib_dir.strip()
                if not lib_dir:
                    continue
                writable = session.execute(f"test -w '{lib_dir}' && echo writable")
                if writable.success and "writable" in writable.output:
                    self.add_finding(
                        title=f"Library search path directory is writable: {lib_dir}",
                        description=(
                            f"The directory {lib_dir} is in the library search path and "
                            "is writable by the current user. A malicious library placed "
                            "here could be loaded by any application."
                        ),
                        severity=Severity.HIGH,
                        evidence=f"Writable directory in ldconfig path: {lib_dir}",
                        remediation=f"Fix permissions: chmod 755 {lib_dir} && chown root:root {lib_dir}",
                    )

    def _check_writable_shared_libs(self, session: Session) -> None:
        """Check for world-writable shared libraries in system directories."""
        for lib_dir in self.SYSTEM_LIB_DIRS:
            result = session.execute(
                f"find {lib_dir} -maxdepth 1 -name '*.so*' -writable -type f 2>/dev/null | head -20"
            )
            if result.success and result.output.strip():
                self.add_finding(
                    title=f"Writable shared libraries found in {lib_dir}",
                    description=(
                        f"Shared library files in {lib_dir} are writable by the current user. "
                        "An attacker could replace them with malicious versions."
                    ),
                    severity=Severity.CRITICAL,
                    evidence=result.output[:500],
                    remediation=f"Fix permissions: chmod 755 {lib_dir}/*.so* && chown root:root {lib_dir}/*.so*",
                )

    def _check_ld_so_conf(self, session: Session) -> None:
        """Check /etc/ld.so.conf.d/ for suspicious or insecure entries."""
        result = session.execute("ls -la /etc/ld.so.conf.d/ 2>/dev/null")
        if result.success and result.output.strip():
            # Check for world-writable conf files
            writable_conf = session.execute(
                "find /etc/ld.so.conf.d/ -writable -type f 2>/dev/null"
            )
            if writable_conf.success and writable_conf.output.strip():
                self.add_finding(
                    title="Writable ld.so.conf.d files found",
                    description=(
                        "Configuration files in /etc/ld.so.conf.d/ are writable by the current "
                        "user. An attacker could add a directory containing malicious libraries."
                    ),
                    severity=Severity.HIGH,
                    evidence=writable_conf.output[:500],
                    remediation="chmod 644 /etc/ld.so.conf.d/*.conf && chown root:root /etc/ld.so.conf.d/*.conf",
                )

            # Check for entries pointing to unusual paths
            conf_entries = session.execute(
                "cat /etc/ld.so.conf.d/*.conf 2>/dev/null | grep -v '^#' | grep -v '^$'"
            )
            if conf_entries.success and conf_entries.output.strip():
                suspicious = []
                for line in conf_entries.output.strip().splitlines():
                    path = line.strip()
                    if path and not any(path.startswith(d) for d in ("/usr/lib", "/lib", "/opt")):
                        suspicious.append(path)
                if suspicious:
                    self.add_finding(
                        title="Unusual library paths in ld.so.conf.d",
                        description="Library search paths outside standard locations may indicate tampering.",
                        severity=Severity.MEDIUM,
                        evidence="\n".join(suspicious),
                        remediation="Review and remove unauthorized entries from /etc/ld.so.conf.d/ and run ldconfig.",
                    )

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Ensure /etc/ld.so.preload is owned by root with 644 permissions and use chattr +i.",
            "Never set LD_PRELOAD or LD_LIBRARY_PATH in system-wide profile scripts.",
            "Ensure all directories in the library search path are owned by root and not world-writable.",
            "Audit /etc/ld.so.conf.d/ entries regularly and remove unauthorized paths.",
            "Use SELinux to prevent unauthorized shared library loading via lib_t labels.",
        ]

"""T1574 — Hijack Execution Flow (Defense Evasion perspective).

Checks for dynamic linker abuse, preloaded library manipulation, RPATH abuse,
and writable library directories that could be used to evade security controls
on RHEL systems.
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class HijackExecutionEvasionCheck(BaseModule):
    TECHNIQUE_ID = "T1574"
    TECHNIQUE_NAME = "Hijack Execution Flow"
    TACTIC = Tactic.DEFENSE_EVASION
    SEVERITY = Severity.HIGH
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        self._check_ld_debug(session)
        self._check_preloaded_libraries(session)
        self._check_ld_so_preload_hiding(session)
        self._check_rpath_abuse(session)
        self._check_writable_lib_dirs(session)

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    # -- Dynamic linker logging (LD_DEBUG) ------------------------------------

    def _check_ld_debug(self, session: Session) -> None:
        # Check environment for LD_DEBUG set globally
        result = session.execute(
            "grep -rs 'LD_DEBUG' /etc/environment /etc/profile /etc/profile.d/*.sh "
            "/etc/ld.so.conf /etc/ld.so.conf.d/*.conf 2>/dev/null"
        )
        if result.success and result.output.strip():
            self.add_finding(
                title="LD_DEBUG is configured in system-wide profiles",
                description=(
                    "Dynamic linker debug logging is enabled globally, which can "
                    "expose library resolution order and aid attackers in crafting "
                    "library hijack attacks"
                ),
                severity=Severity.MEDIUM,
                evidence=result.output.strip()[:500],
                remediation="Remove LD_DEBUG from system-wide environment files",
            )

        # Check running processes for LD_DEBUG
        proc_check = session.execute(
            "xargs -0 -I{} sh -c 'echo {}' < /proc/*/environ 2>/dev/null | grep LD_DEBUG || true"
        )
        if proc_check.success and proc_check.output.strip():
            self.add_finding(
                title="Running processes have LD_DEBUG set",
                description="Active processes have LD_DEBUG in their environment, which may leak library resolution details",
                severity=Severity.MEDIUM,
                evidence=proc_check.output.strip()[:500],
                remediation="Investigate processes with LD_DEBUG and remove the variable from their launch configuration",
            )

    # -- Preloaded libraries intercepting security tools ----------------------

    def _check_preloaded_libraries(self, session: Session) -> None:
        # Check /etc/ld.so.preload
        preload = session.execute("cat /etc/ld.so.preload 2>/dev/null")
        if preload.success and preload.output.strip():
            lines = [l.strip() for l in preload.output.strip().splitlines() if l.strip() and not l.strip().startswith("#")]
            if lines:
                self.add_finding(
                    title="Libraries preloaded via /etc/ld.so.preload",
                    description=(
                        "Preloaded libraries intercept function calls for all dynamically "
                        "linked binaries, including security tools. An attacker could use "
                        "this to hide processes, files, or network connections."
                    ),
                    severity=Severity.HIGH,
                    evidence="\n".join(lines),
                    remediation=(
                        "Audit /etc/ld.so.preload entries. Remove any unauthorized libraries. "
                        "Monitor this file with auditd: -w /etc/ld.so.preload -p wa -k preload"
                    ),
                )

        # Check LD_PRELOAD in environment
        env_preload = session.execute(
            "grep -rs 'LD_PRELOAD' /etc/environment /etc/profile /etc/profile.d/*.sh 2>/dev/null"
        )
        if env_preload.success and env_preload.output.strip():
            self.add_finding(
                title="LD_PRELOAD set in system-wide profiles",
                description="LD_PRELOAD in global profiles can be used to intercept security tool library calls",
                severity=Severity.HIGH,
                evidence=env_preload.output.strip()[:500],
                remediation="Remove LD_PRELOAD from system-wide profiles unless explicitly required and documented",
            )

    # -- /etc/ld.so.preload hiding from ldd output ----------------------------

    def _check_ld_so_preload_hiding(self, session: Session) -> None:
        preload = session.execute("cat /etc/ld.so.preload 2>/dev/null")
        if not preload.success or not preload.output.strip():
            return

        for line in preload.output.strip().splitlines():
            lib = line.strip()
            if not lib or lib.startswith("#"):
                continue
            # Check if the preloaded library exists and if it hooks common functions
            exists = session.execute(f"test -f '{lib}' && echo exists || echo missing")
            if exists.success and "missing" in exists.output:
                self.add_finding(
                    title=f"Preload library does not exist: {lib}",
                    description="A referenced preload library is missing, which could indicate a failed hijack or cleanup artifact",
                    severity=Severity.MEDIUM,
                    evidence=f"{lib} referenced in /etc/ld.so.preload but file not found",
                    remediation="Remove non-existent entries from /etc/ld.so.preload",
                )
            elif exists.success and "exists" in exists.output:
                # Check if library hooks libc functions commonly used for hiding
                nm_check = session.execute(f"nm -D '{lib}' 2>/dev/null | grep -E '(readdir|stat|open|write|connect)' || true")
                if nm_check.success and nm_check.output.strip():
                    self.add_finding(
                        title=f"Preload library hooks sensitive functions: {lib}",
                        description="The preloaded library overrides libc functions commonly used for rootkit-style hiding",
                        severity=Severity.CRITICAL,
                        evidence=nm_check.output.strip()[:500],
                        remediation=f"Investigate {lib} for malicious function interception and remove if unauthorized",
                    )

    # -- RPATH abuse in commonly-used binaries --------------------------------

    def _check_rpath_abuse(self, session: Session) -> None:
        # Check key security binaries for RPATH/RUNPATH that could be abused
        binaries = ["/usr/bin/sudo", "/usr/bin/su", "/usr/bin/ssh", "/usr/bin/passwd", "/usr/sbin/auditd"]
        for binary in binaries:
            result = session.execute(f"readelf -d '{binary}' 2>/dev/null | grep -i 'rpath\\|runpath' || true")
            if result.success and result.output.strip():
                self.add_finding(
                    title=f"RPATH/RUNPATH set on {binary}",
                    description=(
                        f"The binary {binary} has a hardcoded library search path. "
                        "If the RPATH directory is writable, an attacker could place "
                        "a malicious library to hijack execution."
                    ),
                    severity=Severity.HIGH,
                    evidence=result.output.strip(),
                    remediation=f"Rebuild {binary} without RPATH or ensure the RPATH directory is root-owned and not writable",
                )

    # -- Writable library directories -----------------------------------------

    def _check_writable_lib_dirs(self, session: Session) -> None:
        lib_dirs = ["/lib", "/lib64", "/usr/lib", "/usr/lib64"]
        for lib_dir in lib_dirs:
            result = session.execute(f"find {lib_dir} -maxdepth 1 -writable -type d 2>/dev/null | head -5")
            if result.success and result.output.strip():
                self.add_finding(
                    title=f"Writable library directory: {lib_dir}",
                    description=(
                        f"The library directory {lib_dir} is writable by the current user. "
                        "An attacker could replace security tool libraries to evade detection."
                    ),
                    severity=Severity.CRITICAL,
                    evidence=result.output.strip(),
                    remediation=f"Fix permissions: chmod 755 {lib_dir} and ensure root ownership",
                )

        # Check ld.so.conf.d for directories that are writable
        conf_dirs = session.execute("cat /etc/ld.so.conf /etc/ld.so.conf.d/*.conf 2>/dev/null | grep -v '^#' | grep '/'")
        if conf_dirs.success and conf_dirs.output.strip():
            for line in conf_dirs.output.strip().splitlines()[:10]:
                d = line.strip()
                if not d:
                    continue
                writable = session.execute(f"test -d '{d}' && test -w '{d}' && echo writable || true")
                if writable.success and "writable" in writable.output:
                    self.add_finding(
                        title=f"Writable ld.so.conf library directory: {d}",
                        description=f"Library directory {d} referenced in ld.so.conf is writable, allowing library replacement",
                        severity=Severity.HIGH,
                        evidence=f"{d} is writable by current user",
                        remediation=f"Restrict permissions on {d} to root-only write access",
                    )

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Monitor /etc/ld.so.preload with auditd: -w /etc/ld.so.preload -p wa -k preload",
            "Ensure all library directories (/lib, /lib64, /usr/lib, /usr/lib64) are owned by root with mode 755",
            "Use SELinux to restrict LD_PRELOAD and LD_DEBUG usage by confined processes",
            "Rebuild critical binaries without RPATH or restrict RPATH directories to root-only access",
            "Deploy AIDE or OSSEC to detect unauthorized changes to shared library directories",
        ]

"""T1218 — System Binary Proxy Execution.

Checks for Electron app abuse, GTFOBins-style proxy execution via system
binaries, LD_PRELOAD-capable SUID binaries, binaries with file capabilities,
and env command execution bypass on RHEL systems.
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class ProxyExecutionCheck(BaseModule):
    TECHNIQUE_ID = "T1218"
    TECHNIQUE_NAME = "System Binary Proxy Execution"
    TACTIC = Tactic.DEFENSE_EVASION
    SEVERITY = Severity.HIGH
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        self._check_electron_apps(session)
        self._check_gtfobins_binaries(session)
        self._check_ld_preload_suid(session)
        self._check_file_capability_binaries(session)
        self._check_env_bypass(session)

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    # -- T1218.015 Electron apps ----------------------------------------------

    def _check_electron_apps(self, session: Session) -> None:
        result = session.execute(
            "find /usr/lib /usr/local/lib /opt /snap -name 'electron' -o -name 'Electron' 2>/dev/null | head -10"
        )
        if result.success and result.output.strip():
            apps = result.output.strip().splitlines()
            self.add_finding(
                title=f"Electron application binaries found ({len(apps)} locations)",
                description=(
                    "Electron apps can be abused for proxy execution via --inspect "
                    "or --inspect-brk flags to enable Node.js debugging"
                ),
                severity=Severity.MEDIUM,
                evidence="\n".join(apps[:10]),
                remediation="Remove unnecessary Electron apps; restrict --inspect flag usage via AppArmor or SELinux",
            )

        # Check for electron inspect capability
        result = session.execute(
            "find /usr/bin /usr/local/bin -type f 2>/dev/null | "
            "xargs file 2>/dev/null | grep -i 'electron' | head -10"
        )
        if result.success and result.output.strip():
            electron_bins = result.output.strip().splitlines()
            if electron_bins:
                self.add_finding(
                    title=f"Electron-based binaries in PATH ({len(electron_bins)} found)",
                    description="Electron binaries in PATH may accept --inspect for proxy execution",
                    severity=Severity.MEDIUM,
                    evidence="\n".join(electron_bins[:10]),
                    remediation="Audit Electron-based applications; restrict debugging capabilities",
                )

    # -- GTFOBins-style proxy execution binaries ------------------------------

    def _check_gtfobins_binaries(self, session: Session) -> None:
        # Binaries known to allow command execution
        gtfobins = {
            "find": "find / -name x -exec /bin/sh \\;",
            "tar": "tar --checkpoint-action=exec=/bin/sh",
            "zip": "zip -T -TT '/bin/sh #'",
            "awk": "awk 'BEGIN{system(\"/bin/sh\")}'",
            "nmap": "nmap --interactive (older versions)",
            "vim": "vim -c '!sh'",
            "less": "less -> !/bin/sh",
            "man": "man -> !/bin/sh",
            "rvim": "rvim -c ':py import os; os.system(\"/bin/sh\")'",
            "python3": "python3 -c 'import os; os.system(\"/bin/sh\")'",
            "perl": "perl -e 'exec \"/bin/sh\"'",
            "ruby": "ruby -e 'exec \"/bin/sh\"'",
        }
        found = []
        for binary, example in gtfobins.items():
            result = session.execute(f"which {binary} 2>/dev/null")
            if result.success and result.output.strip():
                path = result.output.strip()
                # Check if SUID
                suid_result = session.execute(f"test -u {path} && echo SUID")
                if suid_result.success and "SUID" in suid_result.output:
                    found.append(f"SUID {path}: {example}")

        if found:
            self.add_finding(
                title=f"SUID GTFOBins-capable binaries found ({len(found)} binaries)",
                description="SUID binaries that can execute arbitrary commands enable privilege escalation via proxy execution",
                severity=Severity.HIGH,
                evidence="\n".join(found[:10]),
                remediation="Remove SUID bit from unnecessary binaries: chmod u-s <binary>",
            )

    # -- LD_PRELOAD-capable SUID binaries ------------------------------------

    def _check_ld_preload_suid(self, session: Session) -> None:
        result = session.execute(
            "find /usr/bin /usr/sbin /usr/local/bin -perm -4000 -type f 2>/dev/null | "
            "while read f; do "
            "readelf -d \"$f\" 2>/dev/null | grep -q NEEDED && echo \"$f\"; "
            "done | head -20"
        )
        if result.success and result.output.strip():
            suid_bins = result.output.strip().splitlines()
            if suid_bins:
                self.add_finding(
                    title=f"SUID binaries with dynamic library dependencies ({len(suid_bins)} found)",
                    description=(
                        "SUID binaries that load shared libraries may be vulnerable to "
                        "LD_PRELOAD or library path hijacking if not properly hardened"
                    ),
                    severity=Severity.MEDIUM,
                    evidence="\n".join(suid_bins[:10]),
                    remediation="Audit SUID binaries; ensure they ignore LD_PRELOAD (libc does this for SUID by default)",
                )

    # -- Binaries with file capabilities --------------------------------------

    def _check_file_capability_binaries(self, session: Session) -> None:
        result = session.execute(
            "getcap -r /usr/bin /usr/sbin /usr/local/bin 2>/dev/null | head -20"
        )
        if result.success and result.output.strip():
            cap_bins = result.output.strip().splitlines()
            # Flag dangerous capabilities
            dangerous_caps = ["cap_setuid", "cap_setgid", "cap_sys_admin", "cap_sys_ptrace", "cap_dac_override"]
            dangerous = [
                line for line in cap_bins
                if any(cap in line for cap in dangerous_caps)
            ]
            if dangerous:
                self.add_finding(
                    title=f"Binaries with dangerous file capabilities ({len(dangerous)} found)",
                    description="Binaries with elevated capabilities can be used for proxy execution to bypass access controls",
                    severity=Severity.HIGH,
                    evidence="\n".join(dangerous[:10]),
                    remediation="Remove unnecessary capabilities: setcap -r <binary>; audit with getcap -r /",
                )

    # -- env command for execution bypass -------------------------------------

    def _check_env_bypass(self, session: Session) -> None:
        result = session.execute("which env 2>/dev/null")
        if result.success and result.output.strip():
            env_path = result.output.strip()
            # Check if env has SUID
            suid_result = session.execute(f"test -u {env_path} && echo SUID")
            if suid_result.success and "SUID" in suid_result.output:
                self.add_finding(
                    title="env binary has SUID bit set",
                    description="SUID env can execute arbitrary commands with elevated privileges",
                    severity=Severity.CRITICAL,
                    evidence=f"SUID on {env_path}",
                    remediation=f"Remove SUID bit: chmod u-s {env_path}",
                )

            # Check if env can bypass restricted shells
            result2 = session.execute(f"file {env_path} 2>/dev/null")
            if result2.success and result2.output.strip():
                # Check for restricted shell users that could use env to escape
                restricted = session.execute(
                    "grep -E '(/usr/bin/rbash|/bin/rbash|/usr/sbin/nologin)' /etc/passwd 2>/dev/null | head -5"
                )
                if restricted.success and restricted.output.strip():
                    pass  # env is available but only a concern if SUID, already checked above

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Audit and remove SUID bits from unnecessary binaries: find / -perm -4000 -type f",
            "Use fapolicyd to restrict execution of untrusted binaries on RHEL 8/9",
            "Remove dangerous file capabilities with setcap -r on non-essential binaries",
            "Enable SELinux in enforcing mode to restrict proxy execution techniques",
            "Restrict installation of Electron apps and development tools on production systems",
        ]

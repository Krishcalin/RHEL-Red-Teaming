"""T1203 — Exploitation for Client Execution.

Checks kernel and binary-level exploit mitigations on RHEL systems,
including ASLR, NX/DEP, stack canaries, RELRO, PIE, and outdated
packages with known vulnerabilities.
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class ClientExecutionCheck(BaseModule):
    TECHNIQUE_ID = "T1203"
    TECHNIQUE_NAME = "Exploitation for Client Execution"
    TACTIC = Tactic.EXECUTION
    SEVERITY = Severity.HIGH
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    CRITICAL_BINARIES = [
        "/usr/bin/ssh",
        "/usr/bin/sudo",
        "/usr/bin/passwd",
        "/usr/sbin/sshd",
        "/usr/bin/su",
        "/usr/bin/login",
        "/usr/bin/pkexec",
    ]

    def check(self, session: Session) -> ModuleResult:
        self._check_aslr(session)
        self._check_nx_dep(session)
        self._check_stack_protector(session)
        self._check_relro(session)
        self._check_pie(session)
        self._check_outdated_packages(session)

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def _check_aslr(self, session: Session) -> None:
        """Check ASLR status via kernel.randomize_va_space."""
        result = session.execute(
            "sysctl -n kernel.randomize_va_space 2>/dev/null"
        )
        if result.success and result.output.strip():
            value = result.output.strip()
            if value == "0":
                self.add_finding(
                    title="ASLR is disabled (kernel.randomize_va_space=0)",
                    description=(
                        "Address Space Layout Randomization is completely disabled, "
                        "making memory corruption exploits significantly easier."
                    ),
                    severity=Severity.CRITICAL,
                    evidence=f"kernel.randomize_va_space = {value}",
                    remediation=(
                        "Enable full ASLR: sysctl -w kernel.randomize_va_space=2 "
                        "and persist in /etc/sysctl.d/99-security.conf"
                    ),
                )
            elif value == "1":
                self.add_finding(
                    title="ASLR is partially enabled (kernel.randomize_va_space=1)",
                    description=(
                        "ASLR is set to partial randomization. Full randomization "
                        "(value 2) provides stronger exploit mitigation."
                    ),
                    severity=Severity.MEDIUM,
                    evidence=f"kernel.randomize_va_space = {value}",
                    remediation=(
                        "Enable full ASLR: sysctl -w kernel.randomize_va_space=2 "
                        "and persist in /etc/sysctl.d/99-security.conf"
                    ),
                )

    def _check_nx_dep(self, session: Session) -> None:
        """Check NX (No-eXecute) / DEP support."""
        result = session.execute(
            "grep -o ' nx ' /proc/cpuinfo 2>/dev/null | head -1"
        )
        if result.success and "nx" in result.output.lower():
            return  # NX is supported

        # Alternative check via dmesg
        dmesg_result = session.execute(
            "dmesg 2>/dev/null | grep -i 'NX\\|Execute Disable' | head -3"
        )
        if dmesg_result.success and dmesg_result.output.strip():
            if "not supported" in dmesg_result.output.lower():
                self.add_finding(
                    title="NX/DEP is not supported or disabled",
                    description=(
                        "Hardware NX (No-eXecute) bit is not supported or disabled, "
                        "allowing execution of code from data pages."
                    ),
                    severity=Severity.HIGH,
                    evidence=dmesg_result.output.strip()[:300],
                    remediation=(
                        "Enable NX/XD bit in BIOS/UEFI firmware settings. "
                        "Ensure the kernel supports PAE/NX."
                    ),
                )
        elif not result.success or "nx" not in result.output.lower():
            # Could not confirm NX support
            flags_result = session.execute(
                "grep -m1 'flags' /proc/cpuinfo 2>/dev/null"
            )
            if flags_result.success and "nx" not in flags_result.output.lower():
                self.add_finding(
                    title="NX/DEP flag not found in CPU features",
                    description=(
                        "The NX (No-eXecute) flag was not found in CPU features. "
                        "This could indicate NX is disabled in BIOS or unsupported hardware."
                    ),
                    severity=Severity.HIGH,
                    evidence=flags_result.output.strip()[:300],
                    remediation="Enable NX/XD bit in BIOS/UEFI firmware settings.",
                )

    def _check_stack_protector(self, session: Session) -> None:
        """Check stack canary (stack protector) on critical binaries."""
        if not self._has_readelf(session):
            return

        unprotected = []
        for binary in self.CRITICAL_BINARIES:
            result = session.execute(
                f"readelf -s '{binary}' 2>/dev/null | grep -q '__stack_chk_fail' "
                f"&& echo 'protected' || echo 'unprotected'"
            )
            if result.success and "unprotected" in result.output.strip():
                unprotected.append(binary)

        if unprotected:
            self.add_finding(
                title="Critical binaries compiled without stack protector",
                description=(
                    f"{len(unprotected)} critical binary(ies) lack stack canaries "
                    "(__stack_chk_fail), making them vulnerable to stack buffer overflows."
                ),
                severity=Severity.HIGH,
                evidence="\n".join(unprotected),
                remediation=(
                    "Recompile affected binaries with -fstack-protector-strong. "
                    "Ensure system-wide compiler flags include stack protection."
                ),
            )

    def _check_relro(self, session: Session) -> None:
        """Check RELRO (Relocation Read-Only) status on key binaries."""
        if not self._has_readelf(session):
            return

        no_relro = []
        partial_relro = []

        for binary in self.CRITICAL_BINARIES:
            result = session.execute(
                f"readelf -l '{binary}' 2>/dev/null | grep -i 'gnu_relro'"
            )
            bind_now = session.execute(
                f"readelf -d '{binary}' 2>/dev/null | grep -i 'bind_now\\|flags.*now'"
            )

            if not result.success or "GNU_RELRO" not in result.output.upper():
                no_relro.append(binary)
            elif not bind_now.success or not bind_now.output.strip():
                partial_relro.append(binary)

        if no_relro:
            self.add_finding(
                title="Critical binaries without RELRO protection",
                description=(
                    f"{len(no_relro)} binary(ies) have no RELRO, allowing GOT overwrite attacks."
                ),
                severity=Severity.HIGH,
                evidence="\n".join(no_relro),
                remediation="Recompile with -Wl,-z,relro,-z,now for full RELRO.",
            )
        if partial_relro:
            self.add_finding(
                title="Critical binaries with only partial RELRO",
                description=(
                    f"{len(partial_relro)} binary(ies) have partial RELRO (missing BIND_NOW). "
                    "Full RELRO provides stronger protection against GOT overwrites."
                ),
                severity=Severity.MEDIUM,
                evidence="\n".join(partial_relro),
                remediation="Recompile with -Wl,-z,relro,-z,now for full RELRO.",
            )

    def _check_pie(self, session: Session) -> None:
        """Check PIE (Position Independent Executable) compilation on critical binaries."""
        if not self._has_readelf(session):
            return

        no_pie = []
        for binary in self.CRITICAL_BINARIES:
            result = session.execute(
                f"readelf -h '{binary}' 2>/dev/null | grep 'Type:'"
            )
            if result.success and result.output.strip():
                if "DYN" not in result.output:
                    no_pie.append(binary)

        if no_pie:
            self.add_finding(
                title="Critical binaries not compiled as PIE",
                description=(
                    f"{len(no_pie)} critical binary(ies) are not Position Independent "
                    "Executables, reducing the effectiveness of ASLR."
                ),
                severity=Severity.MEDIUM,
                evidence="\n".join(no_pie),
                remediation="Recompile binaries with -fPIE -pie flags for full ASLR benefit.",
            )

    def _check_outdated_packages(self, session: Session) -> None:
        """Check for outdated packages that may have known CVEs."""
        result = session.execute(
            "rpm -qa --last 2>/dev/null | head -20"
        )
        if not result.success or not result.output.strip():
            return

        # Check for available security updates
        update_result = session.execute(
            "yum updateinfo list security 2>/dev/null | grep -c '/Sec.' || "
            "dnf updateinfo list security 2>/dev/null | grep -c '/Sec.' || echo '0'"
        )
        if update_result.success and update_result.output.strip():
            try:
                count = int(update_result.output.strip().splitlines()[-1])
            except (ValueError, IndexError):
                count = 0

            if count > 0:
                self.add_finding(
                    title=f"{count} security update(s) available",
                    description=(
                        f"There are {count} pending security updates. Unpatched "
                        "packages may contain known CVEs exploitable for client execution."
                    ),
                    severity=Severity.HIGH if count > 10 else Severity.MEDIUM,
                    evidence=f"Pending security updates: {count}",
                    remediation=(
                        "Apply security updates: dnf update --security. "
                        "Enable automatic security updates via dnf-automatic."
                    ),
                )

    def _has_readelf(self, session: Session) -> bool:
        """Check if readelf is available."""
        result = session.execute("which readelf 2>/dev/null")
        return result.success and bool(result.output.strip())

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Ensure ASLR is fully enabled: set kernel.randomize_va_space=2 in /etc/sysctl.d/99-security.conf.",
            "Verify all system binaries are compiled with full RELRO (-Wl,-z,relro,-z,now) and PIE (-fPIE -pie).",
            "Enable automatic security updates via dnf-automatic with apply_updates=yes.",
            "Ensure NX/XD bit is enabled in BIOS/UEFI and the kernel supports it.",
            "Use hardened compiler flags system-wide: -fstack-protector-strong, -D_FORTIFY_SOURCE=2.",
        ]

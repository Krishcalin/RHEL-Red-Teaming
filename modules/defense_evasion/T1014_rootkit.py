"""T1014 — Rootkit Detection.

Checks for rootkit detection tools, hidden kernel modules, hidden
processes, hidden network connections, modified system binaries,
ld.so.preload abuse, unsigned kernel modules, and suspicious
kernel log messages on RHEL systems.
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class RootkitCheck(BaseModule):
    TECHNIQUE_ID = "T1014"
    TECHNIQUE_NAME = "Rootkit"
    TACTIC = Tactic.DEFENSE_EVASION
    SEVERITY = Severity.CRITICAL
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        self._check_rootkit_scanners(session)
        self._check_hidden_kernel_modules(session)
        self._check_hidden_processes(session)
        self._check_hidden_network_connections(session)
        self._check_modified_binaries(session)
        self._check_ld_preload(session)
        self._check_kernel_module_signatures(session)
        self._check_dmesg_module_loading(session)

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    # -- Rootkit scanner availability --------------------------------------

    def _check_rootkit_scanners(self, session: Session) -> None:
        scanners = {
            "rkhunter": "rkhunter (Rootkit Hunter)",
            "chkrootkit": "chkrootkit",
        }
        found_any = False
        for binary, name in scanners.items():
            result = session.execute(f"which {binary} 2>/dev/null")
            if result.success and result.output.strip():
                found_any = True

        if not found_any:
            self.add_finding(
                title="No rootkit detection tools installed",
                description="Neither rkhunter nor chkrootkit is installed for rootkit scanning",
                severity=Severity.MEDIUM,
                evidence="rkhunter and chkrootkit not found in PATH",
                remediation="Install rkhunter: yum install rkhunter && rkhunter --update && rkhunter --propupd",
            )

    # -- Hidden kernel modules ---------------------------------------------

    def _check_hidden_kernel_modules(self, session: Session) -> None:
        result = session.execute(
            "diff <(lsmod | awk 'NR>1{print $1}' | sort) "
            "<(cat /proc/modules | awk '{print $1}' | sort) 2>/dev/null"
        )
        if result.success and result.output.strip():
            # Lines starting with > are in /proc/modules but not in lsmod
            hidden = [l for l in result.output.strip().splitlines() if l.startswith(">")]
            if hidden:
                self.add_finding(
                    title=f"Potentially hidden kernel modules ({len(hidden)} found)",
                    description="Modules present in /proc/modules but missing from lsmod output",
                    severity=Severity.CRITICAL,
                    evidence="\n".join(hidden[:10]),
                    remediation="Investigate hidden modules; check for rootkits with rkhunter --check",
                )

    # -- Hidden processes --------------------------------------------------

    def _check_hidden_processes(self, session: Session) -> None:
        result = session.execute(
            "diff <(ps -eo pid --no-headers | awk '{print $1}' | sort -n) "
            "<(ls /proc/ 2>/dev/null | grep '^[0-9]' | sort -n) 2>/dev/null"
        )
        if result.success and result.output.strip():
            # Lines starting with > are in /proc but not in ps output
            hidden = [l for l in result.output.strip().splitlines() if l.startswith(">")]
            if hidden:
                self.add_finding(
                    title=f"Potentially hidden processes ({len(hidden)} found)",
                    description="PIDs visible in /proc but missing from ps output may indicate a rootkit",
                    severity=Severity.CRITICAL,
                    evidence="\n".join(hidden[:10]),
                    remediation="Investigate hidden PIDs; run rkhunter or chkrootkit for rootkit detection",
                )

    # -- Hidden network connections ----------------------------------------

    def _check_hidden_network_connections(self, session: Session) -> None:
        result = session.execute(
            "diff <(ss -tlnp 2>/dev/null | awk 'NR>1{print $4}' | sort) "
            "<(cat /proc/net/tcp /proc/net/tcp6 2>/dev/null | awk 'NR>1{print $2}' | sort) 2>/dev/null"
        )
        if result.success and result.output.strip():
            diff_lines = [l for l in result.output.strip().splitlines() if l.startswith(">")]
            if len(diff_lines) > 5:
                self.add_finding(
                    title="Discrepancies between ss and /proc/net/tcp",
                    description="Network connections visible in /proc but not in ss may indicate hiding",
                    severity=Severity.HIGH,
                    evidence="\n".join(diff_lines[:10]),
                    remediation="Investigate network discrepancies; scan for rootkits that hook netstat/ss",
                )

    # -- Modified system binaries ------------------------------------------

    def _check_modified_binaries(self, session: Session) -> None:
        result = session.execute(
            "rpm -Va --nomtime 2>/dev/null | grep -E '^..5' | head -20"
        )
        if result.success and result.output.strip():
            files = result.output.strip().splitlines()
            # Filter to binaries in critical paths
            critical = [f for f in files if any(
                p in f for p in ("/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/", "/lib", "/usr/lib")
            )]
            if critical:
                self.add_finding(
                    title=f"Modified system binaries detected ({len(critical)} files)",
                    description="RPM verification shows binaries with changed checksums (MD5 mismatch)",
                    severity=Severity.CRITICAL,
                    evidence="\n".join(critical[:10]),
                    remediation="Reinstall affected packages: rpm -qf <file> then yum reinstall <package>",
                )

    # -- /etc/ld.so.preload ------------------------------------------------

    def _check_ld_preload(self, session: Session) -> None:
        result = session.execute("cat /etc/ld.so.preload 2>/dev/null")
        if result.success and result.output.strip():
            self.add_finding(
                title="ld.so.preload contains entries",
                description="/etc/ld.so.preload forces library preloading for all processes — a common rootkit technique",
                severity=Severity.CRITICAL,
                evidence=result.output.strip()[:500],
                remediation="Investigate libraries in /etc/ld.so.preload; remove unauthorized entries",
            )

        # Also check LD_PRELOAD environment variable
        result = session.execute("echo $LD_PRELOAD")
        if result.success and result.output.strip():
            self.add_finding(
                title="LD_PRELOAD environment variable is set",
                description="LD_PRELOAD injects shared libraries into processes — may indicate rootkit activity",
                severity=Severity.HIGH,
                evidence=f"LD_PRELOAD={result.output.strip()}",
                remediation="Unset LD_PRELOAD; investigate source of the variable in profile scripts",
            )

    # -- Kernel module signatures ------------------------------------------

    def _check_kernel_module_signatures(self, session: Session) -> None:
        # Check if module signature enforcement is enabled
        result = session.execute(
            "cat /proc/sys/kernel/modules_disabled 2>/dev/null"
        )
        if result.success and result.output.strip() == "0":
            # Module loading is allowed; check signature enforcement
            sig_enforce = session.execute(
                "cat /proc/keys 2>/dev/null | grep -c 'asymmetri'"
            )
            lockdown = session.execute(
                "cat /sys/kernel/security/lockdown 2>/dev/null"
            )
            if lockdown.success and "[none]" in lockdown.output:
                self.add_finding(
                    title="Kernel lockdown is not enabled",
                    description="Without lockdown, unsigned kernel modules can be loaded",
                    severity=Severity.HIGH,
                    evidence=lockdown.output.strip(),
                    remediation="Enable Secure Boot or set lockdown=integrity in kernel parameters",
                )

        # Check for unsigned modules currently loaded
        result = session.execute(
            "for mod in $(lsmod | awk 'NR>1{print $1}' | head -30); do "
            "modinfo $mod 2>/dev/null | grep -q 'sig_id' || echo \"unsigned: $mod\"; "
            "done"
        )
        if result.success and result.output.strip():
            unsigned = result.output.strip().splitlines()
            if unsigned:
                self.add_finding(
                    title=f"Unsigned kernel modules loaded ({len(unsigned)} found)",
                    description="Kernel modules without signatures could be malicious",
                    severity=Severity.HIGH,
                    evidence="\n".join(unsigned[:10]),
                    remediation="Enable module signature verification; investigate unsigned modules",
                )

    # -- dmesg module loading messages -------------------------------------

    def _check_dmesg_module_loading(self, session: Session) -> None:
        result = session.execute(
            "dmesg 2>/dev/null | grep -iE '(module.*load|module.*verif|tainting|unsigned)' | tail -15"
        )
        if result.success and result.output.strip():
            lines = result.output.strip().splitlines()
            taint_lines = [l for l in lines if "taint" in l.lower() or "unsigned" in l.lower()]
            if taint_lines:
                self.add_finding(
                    title="Kernel taint or unsigned module loading detected in dmesg",
                    description="Kernel log shows modules loaded without proper signatures",
                    severity=Severity.HIGH,
                    evidence="\n".join(taint_lines[:10]),
                    remediation="Investigate tainted module loading; enable Secure Boot for signature enforcement",
                )

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Install and schedule rkhunter for regular rootkit scanning",
            "Enable Secure Boot and kernel lockdown to enforce module signature verification",
            "Monitor /etc/ld.so.preload with auditd watches for unauthorized changes",
            "Use rpm -Va periodically to detect modified system binaries",
            "Enable SELinux in enforcing mode to restrict kernel module loading and library preloading",
        ]

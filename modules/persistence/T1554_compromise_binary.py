"""T1554 — Compromise Host Software Binary.

Checks for modification or replacement of critical system binaries on RHEL systems,
including RPM integrity verification and LD_PRELOAD hijacking.
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class CompromiseBinaryCheck(BaseModule):
    TECHNIQUE_ID = "T1554"
    TECHNIQUE_NAME = "Compromise Host Software Binary"
    TACTIC = Tactic.PERSISTENCE
    SEVERITY = Severity.CRITICAL
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = True
    SAFE_MODE = True

    # Critical binaries commonly targeted for trojanization
    CRITICAL_BINARIES = [
        "/usr/bin/ssh", "/usr/sbin/sshd", "/usr/bin/sudo",
        "/usr/bin/su", "/usr/bin/login", "/usr/bin/passwd",
        "/usr/bin/curl", "/usr/bin/wget", "/usr/bin/crontab",
    ]

    def check(self, session: Session) -> ModuleResult:
        # Verify RPM package integrity for all installed packages
        rpm_verify = session.execute(
            "rpm -Va 2>/dev/null | grep '^..5' | head -30"
        )
        if rpm_verify.success and rpm_verify.output.strip():
            self.add_finding(
                title="RPM package integrity failures — modified binaries detected",
                description="Files with checksum mismatches (..5..) have been modified from their original RPM contents",
                severity=Severity.CRITICAL,
                evidence=rpm_verify.output.strip(),
                remediation="Investigate each modified file; reinstall affected packages with dnf reinstall <package>",
            )

        # Check critical target binaries specifically
        bin_list = " ".join(self.CRITICAL_BINARIES)
        critical_verify = session.execute(
            f"for bin in {bin_list}; do "
            "rpm -Vf \"$bin\" 2>/dev/null | grep \"$bin\" && echo \"  -> $bin\"; "
            "done | head -20"
        )
        if critical_verify.success and critical_verify.output.strip():
            self.add_finding(
                title="Critical security binaries modified from RPM originals",
                description="ssh, sshd, sudo, su, login, or passwd binaries have been tampered with — possible trojanization",
                severity=Severity.CRITICAL,
                evidence=critical_verify.output.strip(),
                remediation="Immediately reinstall openssh, sudo, util-linux, shadow-utils packages; investigate compromise",
            )

        # Check binary timestamps against package install dates
        timestamp_check = session.execute(
            "for bin in /usr/bin/ssh /usr/sbin/sshd /usr/bin/sudo /usr/bin/su /usr/bin/login; do "
            "if [ -f \"$bin\" ]; then "
            "pkg=$(rpm -qf \"$bin\" 2>/dev/null); "
            "if [ $? -eq 0 ]; then "
            "install_date=$(rpm -q --queryformat '%{INSTALLTIME}' \"$pkg\" 2>/dev/null); "
            "file_mtime=$(stat -c '%Y' \"$bin\" 2>/dev/null); "
            "if [ \"$file_mtime\" -gt \"$install_date\" ] 2>/dev/null; then "
            "echo \"NEWER: $bin (file: $(date -d @$file_mtime '+%F %T'), pkg: $(date -d @$install_date '+%F %T'))\"; "
            "fi; fi; fi; done 2>/dev/null | head -10"
        )
        if timestamp_check.success and timestamp_check.output.strip():
            self.add_finding(
                title="Binary files newer than their package install date",
                description="Binary modification timestamp is after the RPM install date, indicating post-install tampering",
                severity=Severity.HIGH,
                evidence=timestamp_check.output.strip(),
                remediation="Verify file integrity with rpm -Vf; reinstall affected packages if checksums differ",
            )

        # Check for LD_PRELOAD hooks on critical binaries
        ld_preload_env = session.execute(
            "cat /etc/environment 2>/dev/null | grep -i 'LD_PRELOAD'; "
            "cat /etc/ld.so.preload 2>/dev/null; "
            "grep -r 'LD_PRELOAD' /etc/profile.d/ /etc/bashrc /etc/profile 2>/dev/null | grep -v '^#'"
        )
        if ld_preload_env.success and ld_preload_env.output.strip():
            self.add_finding(
                title="LD_PRELOAD hooks detected — library injection active",
                description="LD_PRELOAD allows interception of library calls for any binary, enabling credential theft or backdoors",
                severity=Severity.CRITICAL,
                evidence=ld_preload_env.output.strip(),
                remediation="Remove entries from /etc/ld.so.preload and LD_PRELOAD from environment files; investigate loaded libraries",
            )

        # Check /etc/ld.so.preload specifically
        ld_so_preload = session.execute(
            "test -f /etc/ld.so.preload && cat /etc/ld.so.preload 2>/dev/null"
        )
        if ld_so_preload.success and ld_so_preload.output.strip():
            self.add_finding(
                title="/etc/ld.so.preload contains library injection entries",
                description="Libraries in /etc/ld.so.preload are loaded before all others, affecting every dynamically linked binary",
                severity=Severity.CRITICAL,
                evidence=ld_so_preload.output.strip(),
                remediation="Remove /etc/ld.so.preload or clear its contents; audit listed libraries for malicious code",
            )

        # Check for modified binaries in /usr/bin and /usr/sbin not matching RPM database
        unpackaged_bins = session.execute(
            "find /usr/bin /usr/sbin -type f -executable 2>/dev/null "
            "| while read f; do rpm -qf \"$f\" 2>/dev/null || echo \"UNPACKAGED: $f\"; done "
            "| grep '^UNPACKAGED' | head -15"
        )
        if unpackaged_bins.success and unpackaged_bins.output.strip():
            self.add_finding(
                title="Unpackaged executables found in system binary directories",
                description="Executables in /usr/bin or /usr/sbin not tracked by RPM may be trojanized or backdoor binaries",
                severity=Severity.HIGH,
                evidence=unpackaged_bins.output.strip(),
                remediation="Audit each unpackaged binary; remove unauthorized files from /usr/bin and /usr/sbin",
            )

        # Check for prelink modifications
        prelink_check = session.execute(
            "rpm -q prelink 2>/dev/null && prelink --verify -a 2>/dev/null | head -20"
        )
        if prelink_check.success and "is not installed" not in prelink_check.output:
            # prelink is installed — check for unexpected modifications
            prelink_verify = session.execute(
                "prelink --verify -a 2>/dev/null | grep -v '^$' | head -20"
            )
            if prelink_verify.success and prelink_verify.output.strip():
                self.add_finding(
                    title="Prelink is installed and may mask binary modifications",
                    description="Prelink modifies ELF binaries for faster loading but can mask trojanized binaries",
                    severity=Severity.MEDIUM,
                    evidence=prelink_verify.output.strip(),
                    remediation="Remove prelink (dnf remove prelink) and use rpm -Va to verify binary integrity",
                )

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Run rpm -Va regularly and alert on checksum mismatches (..5..) for critical binaries",
            "Deploy AIDE or OSSEC for file integrity monitoring on /usr/bin, /usr/sbin, and /usr/lib64",
            "Enable SELinux in enforcing mode to prevent unauthorized binary replacement",
            "Remove prelink and ensure /etc/ld.so.preload does not exist or is empty",
            "Use auditd to monitor writes to critical binary paths: -w /usr/sbin/sshd -p wa -k binary_tamper",
        ]

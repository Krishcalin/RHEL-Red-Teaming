"""T1548 — Abuse Elevation Control Mechanism.

Checks SUID/SGID binaries and sudo misconfigurations.
Sub-techniques: T1548.001 (Setuid/Setgid), T1548.003 (Sudo/Sudo Caching).
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule

# Known-safe SUID binaries on RHEL (CIS baseline)
EXPECTED_SUID = {
    "/usr/bin/passwd", "/usr/bin/gpasswd", "/usr/bin/newgrp", "/usr/bin/chage",
    "/usr/bin/chfn", "/usr/bin/chsh", "/usr/bin/su", "/usr/bin/sudo",
    "/usr/bin/mount", "/usr/bin/umount", "/usr/bin/crontab", "/usr/bin/at",
    "/usr/bin/ssh-agent", "/usr/bin/pkexec", "/usr/bin/Xorg",
    "/usr/sbin/pam_timestamp_check", "/usr/sbin/unix_chkpwd",
    "/usr/sbin/usernetctl", "/usr/sbin/mount.nfs",
    "/usr/lib/polkit-1/polkit-agent-helper-1",
    "/usr/libexec/dbus-1/dbus-daemon-launch-helper",
    "/usr/libexec/openssh/ssh-keysign",
    "/usr/libexec/sssd/krb5_child", "/usr/libexec/sssd/ldap_child",
    "/usr/libexec/sssd/selinux_child", "/usr/libexec/sssd/proxy_child",
}

# SUID binaries known to be exploitable via GTFOBins
GTFOBINS_SUID = {
    "ar", "aria2c", "ash", "awk", "base64", "bash", "busybox", "cat", "chmod",
    "chown", "cp", "curl", "cut", "dash", "dd", "diff", "docker", "ed", "emacs",
    "env", "expand", "expect", "file", "find", "flock", "fmt", "fold", "gdb",
    "gimp", "grep", "head", "ionice", "ip", "jq", "ksh", "ld.so", "less", "logsave",
    "lua", "make", "man", "mawk", "more", "mv", "nano", "nawk", "nice", "nl",
    "nmap", "node", "od", "openssl", "perl", "php", "pic", "pico", "python",
    "python3", "readelf", "restic", "rev", "rlwrap", "rsync", "ruby", "run-parts",
    "rview", "rvim", "sed", "setarch", "shuf", "socat", "sort", "sqlite3",
    "stdbuf", "strace", "strings", "tail", "tar", "taskset", "tclsh", "tee",
    "time", "timeout", "ul", "unexpand", "uniq", "unshare", "vi", "vim", "watch",
    "wget", "xargs", "xxd", "zip", "zsh",
}


class ElevationControlCheck(BaseModule):
    TECHNIQUE_ID = "T1548"
    TECHNIQUE_NAME = "Abuse Elevation Control Mechanism"
    TACTIC = Tactic.PRIVILEGE_ESCALATION
    SEVERITY = Severity.HIGH
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        # T1548.001 — SUID/SGID Binaries
        suid_result = session.execute(
            "find / -perm -4000 -type f 2>/dev/null | grep -v '/proc\\|/sys' | sort"
        )
        if suid_result.success and suid_result.output.strip():
            all_suid = set(suid_result.output.strip().splitlines())
            unexpected = all_suid - EXPECTED_SUID

            if unexpected:
                # Check for GTFOBins exploitables
                exploitable = []
                non_standard = []
                for path in unexpected:
                    binary_name = path.rsplit("/", 1)[-1]
                    if binary_name in GTFOBINS_SUID:
                        exploitable.append(path)
                    else:
                        non_standard.append(path)

                if exploitable:
                    self.add_finding(
                        title=f"Exploitable SUID binaries (GTFOBins): {len(exploitable)}",
                        description="SUID binaries with known privilege escalation techniques",
                        severity=Severity.CRITICAL,
                        evidence="\n".join(exploitable),
                        remediation="Remove SUID bit: chmod u-s <binary>",
                    )

                if non_standard:
                    self.add_finding(
                        title=f"Non-standard SUID binaries: {len(non_standard)}",
                        description="SUID binaries not in the expected CIS baseline",
                        severity=Severity.HIGH,
                        evidence="\n".join(non_standard[:20]),
                        remediation="Audit and remove SUID bit from unnecessary binaries",
                    )

            self.add_finding(
                title=f"Total SUID binaries: {len(all_suid)}",
                description="Complete SUID binary inventory",
                severity=Severity.INFO,
                evidence=f"{len(all_suid)} total, {len(all_suid - EXPECTED_SUID)} non-standard",
            )

        # SGID binaries
        sgid_result = session.execute(
            "find / -perm -2000 -type f 2>/dev/null | grep -v '/proc\\|/sys' | head -30"
        )
        if sgid_result.success and sgid_result.output.strip():
            sgid_bins = sgid_result.output.strip().splitlines()
            self.add_finding(
                title=f"SGID binaries found: {len(sgid_bins)}",
                description="SGID binaries may allow group privilege escalation",
                severity=Severity.LOW,
                evidence="\n".join(sgid_bins[:15]),
            )

        # T1548.003 — Sudo Misconfigurations
        # Check NOPASSWD
        nopasswd = session.execute("grep -r 'NOPASSWD' /etc/sudoers /etc/sudoers.d/ 2>/dev/null | grep -v '^#'")
        if nopasswd.success and nopasswd.output.strip():
            self.add_finding(
                title="Sudo NOPASSWD entries found",
                description="Users can execute commands as root without password",
                severity=Severity.HIGH,
                evidence=nopasswd.output.strip()[:500],
                remediation="Remove NOPASSWD unless absolutely necessary; use targeted commands",
            )

        # Check wildcard abuse in sudoers
        wildcards = session.execute("grep -r '\\*' /etc/sudoers /etc/sudoers.d/ 2>/dev/null | grep -v '^#' | grep -v 'Defaults'")
        if wildcards.success and wildcards.output.strip():
            self.add_finding(
                title="Sudo rules with wildcards",
                description="Wildcard (*) in sudo rules can be abused for privilege escalation",
                severity=Severity.MEDIUM,
                evidence=wildcards.output.strip()[:400],
                remediation="Replace wildcards with explicit command paths",
            )

        # Check sudo timestamp (credential caching)
        sudo_timeout = session.execute("sudo -l 2>/dev/null | grep -i 'timestamp_timeout'")
        timestamp_default = session.execute("grep -r 'timestamp_timeout' /etc/sudoers /etc/sudoers.d/ 2>/dev/null")
        if not timestamp_default.success or not timestamp_default.output.strip():
            self.add_finding(
                title="Sudo timestamp_timeout uses default (15 min)",
                description="Sudo caches credentials for 15 minutes — privilege reuse window",
                severity=Severity.LOW,
                evidence="Default timestamp_timeout = 15",
                remediation="Set Defaults timestamp_timeout=5 or timestamp_timeout=0",
            )

        # Check env_keep (environment variable passthrough)
        env_keep = session.execute("grep -r 'env_keep' /etc/sudoers /etc/sudoers.d/ 2>/dev/null | grep -v '^#'")
        if env_keep.success and env_keep.output.strip():
            dangerous_vars = ["LD_PRELOAD", "LD_LIBRARY_PATH", "PYTHONPATH", "PERL5LIB"]
            for var in dangerous_vars:
                if var in env_keep.output:
                    self.add_finding(
                        title=f"Dangerous env_keep variable: {var}",
                        description=f"{var} in sudo env_keep allows library injection as root",
                        severity=Severity.CRITICAL,
                        evidence=env_keep.output.strip()[:300],
                        remediation=f"Remove {var} from Defaults env_keep",
                    )

        # Check writable sudoers files
        writable = session.execute("find /etc/sudoers.d/ -writable 2>/dev/null")
        if writable.success and writable.output.strip():
            self.add_finding(
                title="Writable sudoers files!",
                description="Current user can modify sudo configuration — instant root escalation",
                severity=Severity.CRITICAL,
                evidence=writable.output.strip(),
                remediation="Fix permissions: chmod 440 /etc/sudoers.d/*",
            )

        # Check sudo -l for current user
        sudo_l = session.execute("sudo -ln 2>/dev/null")
        if sudo_l.success and sudo_l.output.strip() and "not allowed" not in sudo_l.output.lower():
            self.add_finding(
                title="Current user has sudo privileges",
                description="Sudo access details for the current user",
                severity=Severity.INFO,
                evidence=sudo_l.output.strip()[:600],
            )

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Remove SUID/SGID from non-essential binaries",
            "Audit SUID binaries against CIS baseline regularly",
            "Remove NOPASSWD from sudoers unless strictly necessary",
            "Replace wildcards in sudoers with explicit commands",
            "Set Defaults timestamp_timeout=5",
            "Never keep LD_PRELOAD/LD_LIBRARY_PATH in sudo env_keep",
            "Set sudoers files to 440 root:root",
        ]

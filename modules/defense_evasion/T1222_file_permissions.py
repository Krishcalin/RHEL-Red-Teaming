"""T1222 — File and Directory Permissions Modification.

Checks for world-writable system files, unpackaged SUID/SGID binaries,
ownerless files, weak umask settings, ACLs on sensitive files, and
dangerous capabilities on RHEL systems.
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class FilePermissionsCheck(BaseModule):
    TECHNIQUE_ID = "T1222"
    TECHNIQUE_NAME = "File and Directory Permissions Modification"
    TACTIC = Tactic.DEFENSE_EVASION
    SEVERITY = Severity.HIGH
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    SENSITIVE_FILES = [
        "/etc/shadow",
        "/etc/gshadow",
        "/etc/passwd",
        "/etc/sudoers",
        "/etc/ssh/sshd_config",
        "/root/.ssh/authorized_keys",
    ]

    def check(self, session: Session) -> ModuleResult:
        self._check_world_writable(session)
        self._check_suid_sgid(session)
        self._check_no_owner(session)
        self._check_umask(session)
        self._check_acls(session)
        self._check_capabilities(session)

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    # -- T1222.002 World-writable files in system dirs ---------------------

    def _check_world_writable(self, session: Session) -> None:
        result = session.execute(
            "find /etc /usr /var/log -xdev -type f -perm -0002 2>/dev/null | head -20"
        )
        if result.success and result.output.strip():
            files = result.output.strip().splitlines()
            self.add_finding(
                title=f"World-writable files in system directories ({len(files)} found)",
                description="Files writable by any user in system directories can be modified by attackers",
                severity=Severity.HIGH,
                evidence="\n".join(files[:10]),
                remediation="Remove world-writable permission: chmod o-w <file> for each affected file",
            )

    # -- SUID / SGID binaries not in RPM packages --------------------------

    def _check_suid_sgid(self, session: Session) -> None:
        result = session.execute(
            "find / -xdev -type f \\( -perm -4000 -o -perm -2000 \\) 2>/dev/null | "
            "while read f; do rpm -qf \"$f\" >/dev/null 2>&1 || echo \"$f\"; done | head -20"
        )
        if result.success and result.output.strip():
            files = result.output.strip().splitlines()
            self.add_finding(
                title=f"Unpackaged SUID/SGID binaries found ({len(files)})",
                description="SUID/SGID binaries not owned by any RPM package may be planted by attackers",
                severity=Severity.CRITICAL,
                evidence="\n".join(files[:10]),
                remediation="Investigate each unpackaged SUID/SGID binary; remove the setuid/setgid bit if unnecessary: chmod u-s,g-s <file>",
            )

    # -- Files with no owner or group --------------------------------------

    def _check_no_owner(self, session: Session) -> None:
        result = session.execute(
            "find / -xdev \\( -nouser -o -nogroup \\) -type f 2>/dev/null | head -20"
        )
        if result.success and result.output.strip():
            files = result.output.strip().splitlines()
            self.add_finding(
                title=f"Files with no owner or group ({len(files)} found)",
                description="Orphaned files may belong to deleted accounts and could be claimed by new users with the same UID/GID",
                severity=Severity.MEDIUM,
                evidence="\n".join(files[:10]),
                remediation="Assign proper ownership: chown root:root <file> or remove if unnecessary",
            )

    # -- Umask settings ----------------------------------------------------

    def _check_umask(self, session: Session) -> None:
        umask_files = ["/etc/profile", "/etc/bashrc", "/etc/login.defs"]
        for cfg in umask_files:
            result = session.execute(f"grep -i 'umask' {cfg} 2>/dev/null")
            if result.success and result.output.strip():
                for line in result.output.strip().splitlines():
                    stripped = line.strip()
                    if stripped.startswith("#"):
                        continue
                    # Extract umask value
                    parts = stripped.split()
                    for i, p in enumerate(parts):
                        if p.lower() == "umask" and i + 1 < len(parts):
                            val = parts[i + 1]
                            if val in ("0000", "000", "0002", "002", "0022"):
                                if val in ("0000", "000", "0002", "002"):
                                    self.add_finding(
                                        title=f"Weak umask {val} in {cfg}",
                                        description=f"Umask {val} allows group or world access to newly created files",
                                        severity=Severity.HIGH,
                                        evidence=f"{cfg}: {stripped}",
                                        remediation=f"Set umask to 027 or 077 in {cfg}",
                                    )

    # -- ACLs on sensitive files -------------------------------------------

    def _check_acls(self, session: Session) -> None:
        for filepath in self.SENSITIVE_FILES:
            result = session.execute(f"getfacl {filepath} 2>/dev/null")
            if result.success and result.output.strip():
                # Check for non-standard ACL entries (beyond owner/group/other)
                for line in result.output.strip().splitlines():
                    if line.startswith("user:") and ":" in line[5:]:
                        named_user = line.split(":")[1]
                        if named_user:  # Named user ACL entry
                            self.add_finding(
                                title=f"Custom ACL on {filepath}",
                                description=f"A named user ACL entry grants additional access to {filepath}",
                                severity=Severity.HIGH,
                                evidence=f"{filepath}: {line}",
                                remediation=f"Remove unnecessary ACLs: setfacl -b {filepath}",
                            )
                    elif line.startswith("group:") and ":" in line[6:]:
                        named_group = line.split(":")[1]
                        if named_group:
                            self.add_finding(
                                title=f"Custom group ACL on {filepath}",
                                description=f"A named group ACL entry grants additional access to {filepath}",
                                severity=Severity.HIGH,
                                evidence=f"{filepath}: {line}",
                                remediation=f"Remove unnecessary ACLs: setfacl -b {filepath}",
                            )

    # -- Capabilities on binaries ------------------------------------------

    def _check_capabilities(self, session: Session) -> None:
        result = session.execute("getcap -r / 2>/dev/null | head -30")
        if result.success and result.output.strip():
            dangerous_caps = [
                "cap_setuid", "cap_setgid", "cap_dac_override",
                "cap_sys_admin", "cap_sys_ptrace", "cap_net_raw",
                "cap_net_admin", "cap_sys_module",
            ]
            for line in result.output.strip().splitlines():
                for cap in dangerous_caps:
                    if cap in line.lower():
                        self.add_finding(
                            title=f"Dangerous capability found: {line.strip()}",
                            description=f"Binary has {cap} capability which could be abused for privilege escalation",
                            severity=Severity.HIGH,
                            evidence=line.strip(),
                            remediation=f"Remove capability if unnecessary: setcap -r {line.split()[0]}",
                        )
                        break

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Set umask to 027 or 077 system-wide in /etc/profile and /etc/bashrc",
            "Audit SUID/SGID binaries regularly and remove unnecessary setuid bits",
            "Use getcap/setcap to audit and minimize Linux capabilities on binaries",
            "Enforce file ownership via periodic rpm -Va integrity checks",
            "Deploy AIDE for file integrity monitoring on critical system directories",
        ]

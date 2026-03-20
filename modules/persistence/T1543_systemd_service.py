"""T1543 — Create or Modify System Process: Systemd Service.

Checks for persistence via systemd service creation or modification.
Sub-technique: T1543.002 (Systemd Service).
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class SystemdServicePersistenceCheck(BaseModule):
    TECHNIQUE_ID = "T1543"
    TECHNIQUE_NAME = "Create or Modify System Process: Systemd Service"
    TACTIC = Tactic.PERSISTENCE
    SEVERITY = Severity.HIGH
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        # T1543.002: Check for recently created/modified systemd service files (last 7 days)
        recent_services = session.execute(
            "find /etc/systemd/system /usr/lib/systemd/system /usr/local/lib/systemd/system "
            "-name '*.service' -mtime -7 2>/dev/null | head -20"
        )
        if recent_services.success and recent_services.output.strip():
            self.add_finding(
                title="Recently modified systemd service files",
                description="Service files modified in the last 7 days may indicate persistence implant",
                severity=Severity.HIGH,
                evidence=recent_services.output.strip(),
                remediation="Audit recently modified service files and compare against change management records",
            )

        # Check for services with ExecStart pointing to unusual paths
        suspicious_exec = session.execute(
            r"grep -rls 'ExecStart' /etc/systemd/system/ /usr/lib/systemd/system/ 2>/dev/null "
            r"| xargs grep -l 'ExecStart=.*/\(tmp\|home\|dev/shm\)' 2>/dev/null | head -10"
        )
        if suspicious_exec.success and suspicious_exec.output.strip():
            # Get the actual ExecStart lines for evidence
            detail = session.execute(
                r"grep -rh 'ExecStart=.*/\(tmp\|home\|dev/shm\)' /etc/systemd/system/ "
                r"/usr/lib/systemd/system/ 2>/dev/null | head -10"
            )
            self.add_finding(
                title="Systemd services executing from suspicious paths",
                description="Services with ExecStart pointing to /tmp, /home, or /dev/shm are highly suspicious",
                severity=Severity.CRITICAL,
                evidence=detail.output.strip() if detail.success else suspicious_exec.output.strip(),
                remediation="Remove suspicious services; ensure ExecStart references binaries in /usr/bin or /usr/sbin only",
            )

        # Check for services with Type=oneshot that run scripts
        oneshot_scripts = session.execute(
            "grep -rlZ 'Type=oneshot' /etc/systemd/system/ /usr/lib/systemd/system/ 2>/dev/null "
            "| xargs -0 grep -l 'ExecStart=.*\\.sh' 2>/dev/null | head -10"
        )
        if oneshot_scripts.success and oneshot_scripts.output.strip():
            self.add_finding(
                title="Oneshot services executing shell scripts",
                description="Type=oneshot services running scripts can be used for persistence via script modification",
                severity=Severity.MEDIUM,
                evidence=oneshot_scripts.output.strip(),
                remediation="Audit oneshot services; ensure scripts are immutable (chattr +i) and owned by root",
            )

        # Check for enabled services not part of default RHEL install
        non_rpm_services = session.execute(
            "for svc in $(systemctl list-unit-files --type=service --state=enabled --no-pager --no-legend "
            "2>/dev/null | awk '{print $1}'); do "
            "rpm -qf /usr/lib/systemd/system/$svc 2>/dev/null || "
            "rpm -qf /etc/systemd/system/$svc 2>/dev/null || "
            "echo \"UNPACKAGED: $svc\"; done 2>/dev/null | grep '^UNPACKAGED' | head -15"
        )
        if non_rpm_services.success and non_rpm_services.output.strip():
            self.add_finding(
                title="Enabled services not from RPM packages",
                description="Services not tracked by RPM may have been manually installed for persistence",
                severity=Severity.HIGH,
                evidence=non_rpm_services.output.strip(),
                remediation="Audit unpackaged services; remove unauthorized ones with systemctl disable and delete unit files",
            )

        # Check for service files with permissive file permissions
        permissive_perms = session.execute(
            "find /etc/systemd/system /usr/lib/systemd/system -name '*.service' "
            "\\( -perm -o+w -o -perm -g+w \\) 2>/dev/null | head -10"
        )
        if permissive_perms.success and permissive_perms.output.strip():
            self.add_finding(
                title="Systemd service files with permissive permissions",
                description="Group or world-writable service files allow non-root users to modify service behavior",
                severity=Severity.CRITICAL,
                evidence=permissive_perms.output.strip(),
                remediation="Fix permissions: chmod 644 on all service files; chown root:root",
            )

        # Check generator directories
        generator_dirs = [
            "/etc/systemd/system-generators",
            "/usr/local/lib/systemd/system-generators",
            "/run/systemd/system-generators",
        ]
        for gen_dir in generator_dirs:
            gen_files = session.execute(f"ls -la {gen_dir}/ 2>/dev/null")
            if gen_files.success and gen_files.output.strip():
                # Check if any generators are not from RPM packages
                untracked = session.execute(
                    f"for f in {gen_dir}/*; do rpm -qf \"$f\" 2>/dev/null || "
                    f"echo \"UNPACKAGED: $f\"; done 2>/dev/null | grep '^UNPACKAGED' | head -5"
                )
                if untracked.success and untracked.output.strip():
                    self.add_finding(
                        title=f"Unpackaged systemd generators in {gen_dir}",
                        description="Custom systemd generators can create services at boot — a powerful persistence mechanism",
                        severity=Severity.HIGH,
                        evidence=untracked.output.strip(),
                        remediation=f"Audit generators in {gen_dir}; remove unauthorized files",
                    )

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Set systemd service directories to 755 root:root and unit files to 644 root:root",
            "Monitor /etc/systemd/system/ and generator directories with auditd (e.g., -w /etc/systemd/system/ -p wa)",
            "Use rpm -V to verify integrity of packaged service files regularly",
            "Restrict ExecStart paths to /usr/bin and /usr/sbin; block execution from /tmp and /dev/shm via noexec mount options",
            "Enable SELinux in enforcing mode to prevent unauthorized service file creation",
        ]

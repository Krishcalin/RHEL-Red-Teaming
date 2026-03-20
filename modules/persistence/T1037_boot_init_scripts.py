"""T1037 — Boot or Logon Initialization Scripts.

Checks for persistence via RC scripts, init.d scripts, profile.d scripts,
environment files, and systemd user environment generators on RHEL systems.
Sub-technique: T1037.004 (RC Scripts).
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class BootInitScriptsCheck(BaseModule):
    TECHNIQUE_ID = "T1037"
    TECHNIQUE_NAME = "Boot or Logon Initialization Scripts"
    TACTIC = Tactic.PERSISTENCE
    SEVERITY = Severity.HIGH
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = True
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        # --- T1037.004: RC Scripts ---

        # Check /etc/rc.local existence and content
        rc_local = session.execute(
            "for f in /etc/rc.local /etc/rc.d/rc.local; do "
            "if [ -f \"$f\" ]; then "
            "echo \"=== $f (perms: $(stat -c '%a' \"$f\")) ===\"; "
            "cat \"$f\" 2>/dev/null | grep -v '^#' | grep -v '^$' | head -20; "
            "fi; done"
        )
        if rc_local.success and rc_local.output.strip():
            # Only flag if there are actual commands (not just empty/comment-only)
            content_lines = [
                line for line in rc_local.output.strip().split("\n")
                if not line.startswith("===") and line.strip()
            ]
            if content_lines:
                self.add_finding(
                    title="rc.local contains active commands",
                    description="Commands in rc.local execute as root at boot and are a common persistence mechanism",
                    severity=Severity.HIGH,
                    evidence=rc_local.output.strip(),
                    remediation="Remove commands from rc.local; disable rc-local.service; use systemd units instead",
                )

        # Check if rc-local.service is enabled
        rc_svc = session.execute(
            "systemctl is-enabled rc-local.service 2>/dev/null"
        )
        if rc_svc.success and "enabled" in rc_svc.output.strip():
            self.add_finding(
                title="rc-local.service is enabled",
                description="The rc-local service runs /etc/rc.d/rc.local at boot, executing any commands within as root",
                severity=Severity.MEDIUM,
                evidence=rc_svc.output.strip(),
                remediation="Disable the service: systemctl disable rc-local.service",
            )

        # Check /etc/init.d/ for non-package scripts
        initd_scripts = session.execute(
            "for f in /etc/init.d/*; do "
            "[ -f \"$f\" ] && (rpm -qf \"$f\" 2>/dev/null || echo \"UNPACKAGED: $f\"); "
            "done 2>/dev/null | grep '^UNPACKAGED' | head -15"
        )
        if initd_scripts.success and initd_scripts.output.strip():
            self.add_finding(
                title="Unpackaged scripts in /etc/init.d/",
                description="Init scripts not from RPM packages may have been manually planted for persistence",
                severity=Severity.HIGH,
                evidence=initd_scripts.output.strip(),
                remediation="Audit unpackaged init.d scripts; remove unauthorized entries and convert legitimate ones to systemd units",
            )

        # Check /etc/profile.d/ for suspicious scripts
        profiled_scripts = session.execute(
            "for f in /etc/profile.d/*.sh /etc/profile.d/*.csh; do "
            "[ -f \"$f\" ] && (rpm -qf \"$f\" 2>/dev/null || echo \"UNPACKAGED: $f\"); "
            "done 2>/dev/null | grep '^UNPACKAGED' | head -10"
        )
        if profiled_scripts.success and profiled_scripts.output.strip():
            # Get content of unpackaged scripts
            unpackaged_files = [
                line.replace("UNPACKAGED: ", "").strip()
                for line in profiled_scripts.output.strip().split("\n")
                if line.startswith("UNPACKAGED:")
            ]
            evidence = profiled_scripts.output.strip()
            if unpackaged_files:
                content_check = session.execute(
                    f"head -5 {' '.join(unpackaged_files[:5])} 2>/dev/null"
                )
                if content_check.success:
                    evidence += f"\n\nScript contents (first 5 lines each):\n{content_check.output.strip()}"
            self.add_finding(
                title="Unpackaged scripts in /etc/profile.d/",
                description="Scripts in /etc/profile.d/ execute for every login shell; unpackaged scripts may inject backdoors",
                severity=Severity.HIGH,
                evidence=evidence,
                remediation="Remove unauthorized scripts from /etc/profile.d/; audit remaining scripts for malicious content",
            )

        # Check /etc/environment for injected variables
        env_file = session.execute(
            "cat /etc/environment 2>/dev/null | grep -v '^#' | grep -v '^$'"
        )
        if env_file.success and env_file.output.strip():
            # Look for suspicious entries like LD_PRELOAD, PATH manipulation
            suspicious_env = session.execute(
                "grep -i 'LD_PRELOAD\\|LD_LIBRARY_PATH\\|PROMPT_COMMAND\\|BASH_ENV' "
                "/etc/environment 2>/dev/null | grep -v '^#'"
            )
            if suspicious_env.success and suspicious_env.output.strip():
                self.add_finding(
                    title="Suspicious environment variables in /etc/environment",
                    description="LD_PRELOAD, LD_LIBRARY_PATH, PROMPT_COMMAND, or BASH_ENV in /etc/environment affect all sessions",
                    severity=Severity.CRITICAL,
                    evidence=suspicious_env.output.strip(),
                    remediation="Remove injected variables from /etc/environment; investigate origin of modifications",
                )

        # Check /etc/bashrc and /etc/profile for modifications vs RPM originals
        shell_configs = session.execute(
            "rpm -Vf /etc/bashrc 2>/dev/null | grep '/etc/bashrc'; "
            "rpm -Vf /etc/profile 2>/dev/null | grep '/etc/profile'"
        )
        if shell_configs.success and shell_configs.output.strip():
            # Check for suspicious content in modified files
            suspicious_content = session.execute(
                "grep -n 'curl\\|wget\\|base64\\|eval\\|exec\\|/dev/tcp\\|nc \\|ncat\\|socat' "
                "/etc/bashrc /etc/profile 2>/dev/null | grep -v '^#' | head -10"
            )
            evidence = f"Modified files:\n{shell_configs.output.strip()}"
            if suspicious_content.success and suspicious_content.output.strip():
                evidence += f"\n\nSuspicious content:\n{suspicious_content.output.strip()}"
                severity = Severity.CRITICAL
            else:
                severity = Severity.MEDIUM
            self.add_finding(
                title="Shell initialization files modified from RPM originals",
                description="/etc/bashrc or /etc/profile have been modified; injected commands run for every user login",
                severity=severity,
                evidence=evidence,
                remediation="Compare against RPM originals: rpm -Vf /etc/bashrc; restore with dnf reinstall bash setup",
            )

        # Check systemd user environment generators
        env_generators = session.execute(
            "find /etc/systemd/user-environment-generators "
            "/usr/lib/systemd/user-environment-generators "
            "/usr/local/lib/systemd/user-environment-generators "
            "-type f 2>/dev/null | head -10"
        )
        if env_generators.success and env_generators.output.strip():
            unpackaged_gen = session.execute(
                "for f in $(find /etc/systemd/user-environment-generators "
                "/usr/lib/systemd/user-environment-generators "
                "/usr/local/lib/systemd/user-environment-generators "
                "-type f 2>/dev/null); do "
                "rpm -qf \"$f\" 2>/dev/null || echo \"UNPACKAGED: $f\"; "
                "done | grep '^UNPACKAGED' | head -10"
            )
            if unpackaged_gen.success and unpackaged_gen.output.strip():
                self.add_finding(
                    title="Unpackaged systemd user environment generators",
                    description="User environment generators set environment variables for all systemd user sessions at login",
                    severity=Severity.HIGH,
                    evidence=unpackaged_gen.output.strip(),
                    remediation="Audit and remove unauthorized generators; only RPM-packaged generators should exist",
                )

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Disable rc-local.service and remove /etc/rc.d/rc.local or make it non-executable",
            "Monitor /etc/profile.d/, /etc/init.d/, and /etc/environment with auditd: -w /etc/profile.d/ -p wa -k init_scripts",
            "Regularly verify shell config integrity with rpm -Vf /etc/bashrc /etc/profile",
            "Remove unnecessary init.d scripts and convert legitimate ones to systemd units",
            "Use AIDE or OSSEC to monitor all login initialization paths for unauthorized changes",
        ]

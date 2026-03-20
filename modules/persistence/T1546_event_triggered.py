"""T1546 — Event Triggered Execution.

Checks for persistence via shell configs, trap commands, RPM scriptlets,
udev rules, and Python startup hooks.
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class EventTriggeredCheck(BaseModule):
    TECHNIQUE_ID = "T1546"
    TECHNIQUE_NAME = "Event Triggered Execution"
    TACTIC = Tactic.PERSISTENCE
    SEVERITY = Severity.HIGH
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    # Patterns commonly associated with malicious shell profile entries
    SUSPICIOUS_SHELL_PATTERNS = (
        "curl |wget |nc |ncat |bash -i|/dev/tcp|python -c|python3 -c|"
        "perl -e|ruby -e|base64|eval |exec [0-9]|nohup|setsid|disown"
    )

    def check(self, session: Session) -> ModuleResult:
        self._check_shell_configs(session)
        self._check_trap_commands(session)
        self._check_rpm_scriptlets(session)
        self._check_udev_rules(session)
        self._check_python_startup(session)

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def _check_shell_configs(self, session: Session) -> None:
        """T1546.004: Check shell configuration files for suspicious entries."""
        # Check system-wide profile scripts
        system_profiles = session.execute(
            f"grep -rn -E '{self.SUSPICIOUS_SHELL_PATTERNS}' "
            "/etc/profile /etc/profile.d/ /etc/bashrc /etc/bash.bashrc 2>/dev/null | head -20"
        )
        if system_profiles.success and system_profiles.output.strip():
            self.add_finding(
                title="Suspicious entries in system shell profiles",
                description="System-wide shell profiles contain commands commonly used for persistence or reverse shells",
                severity=Severity.CRITICAL,
                evidence=system_profiles.output.strip()[:500],
                remediation="Audit /etc/profile.d/ and /etc/bashrc; remove unauthorized entries",
            )

        # Check user-level shell configs
        user_profiles = session.execute(
            f"for home in /root /home/*; do "
            f"grep -Hn -E '{self.SUSPICIOUS_SHELL_PATTERNS}' "
            f"\"$home/.bashrc\" \"$home/.bash_profile\" \"$home/.profile\" "
            f"2>/dev/null; done | head -20"
        )
        if user_profiles.success and user_profiles.output.strip():
            self.add_finding(
                title="Suspicious entries in user shell profiles",
                description="User .bashrc/.bash_profile/.profile contain suspicious commands",
                severity=Severity.HIGH,
                evidence=user_profiles.output.strip()[:500],
                remediation="Audit user shell profiles; use AIDE or auditd to monitor changes to these files",
            )

        # Check for recently modified profile files
        recent_profiles = session.execute(
            "find /etc/profile.d/ /root/.bashrc /root/.bash_profile "
            "/home/*/.bashrc /home/*/.bash_profile -mtime -7 2>/dev/null | head -10"
        )
        if recent_profiles.success and recent_profiles.output.strip():
            self.add_finding(
                title="Recently modified shell profile files",
                description="Shell profiles modified in the last 7 days may indicate recent persistence activity",
                severity=Severity.MEDIUM,
                evidence=recent_profiles.output.strip(),
                remediation="Review recent modifications against change management records",
            )

    def _check_trap_commands(self, session: Session) -> None:
        """T1546.005: Check for trap commands in shell profiles."""
        trap_entries = session.execute(
            "grep -rn 'trap ' /etc/profile /etc/profile.d/ /etc/bashrc "
            "/root/.bashrc /root/.bash_profile /home/*/.bashrc /home/*/.bash_profile "
            "2>/dev/null | grep -v '^#' | head -10"
        )
        if trap_entries.success and trap_entries.output.strip():
            self.add_finding(
                title="Trap commands found in shell profiles",
                description="Shell trap commands can execute arbitrary code on signals (EXIT, ERR, DEBUG) for persistence",
                severity=Severity.HIGH,
                evidence=trap_entries.output.strip()[:500],
                remediation="Audit trap statements in shell profiles; remove unauthorized signal handlers",
            )

    def _check_rpm_scriptlets(self, session: Session) -> None:
        """T1546.016: Check RPM scriptlets for suspicious post-install hooks."""
        # Check for packages with post-install scripts that look suspicious
        suspicious_scriptlets = session.execute(
            "rpm -qa --scripts 2>/dev/null | grep -B2 -E "
            f"'{self.SUSPICIOUS_SHELL_PATTERNS}' | head -30"
        )
        if suspicious_scriptlets.success and suspicious_scriptlets.output.strip():
            self.add_finding(
                title="RPM packages with suspicious scriptlets",
                description="Installed packages contain post-install scriptlets with suspicious commands",
                severity=Severity.HIGH,
                evidence=suspicious_scriptlets.output.strip()[:500],
                remediation="Verify suspicious packages with rpm -V; remove unauthorized packages",
            )

        # Check for packages not signed by Red Hat
        unsigned_pkgs = session.execute(
            "rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE} %{SIGPGP:pgpsig}\\n' 2>/dev/null "
            "| grep -E '\\(none\\)|Key ID' | grep -v 'Key ID fd431d51' | head -10"
        )
        if unsigned_pkgs.success and unsigned_pkgs.output.strip():
            self.add_finding(
                title="Packages not signed by Red Hat GPG key",
                description="Unsigned or third-party packages may contain malicious scriptlets",
                severity=Severity.MEDIUM,
                evidence=unsigned_pkgs.output.strip()[:500],
                remediation="Remove unauthorized packages; ensure gpgcheck=1 in all yum/dnf repo configs",
            )

    def _check_udev_rules(self, session: Session) -> None:
        """T1546.017: Check udev rules for rules with RUN= directives."""
        # Check for custom udev rules with RUN directives
        udev_run = session.execute(
            "grep -rn 'RUN+=' /etc/udev/rules.d/ 2>/dev/null | head -15"
        )
        if udev_run.success and udev_run.output.strip():
            self.add_finding(
                title="Udev rules with RUN directives",
                description="Custom udev rules with RUN+= execute commands on device events — potential persistence vector",
                severity=Severity.HIGH,
                evidence=udev_run.output.strip()[:500],
                remediation="Audit /etc/udev/rules.d/ for unauthorized RUN directives; restrict directory permissions",
            )

        # Check udev rules file permissions
        udev_perms = session.execute(
            "find /etc/udev/rules.d/ -type f \\( -perm -o+w -o -perm -g+w \\) 2>/dev/null | head -10"
        )
        if udev_perms.success and udev_perms.output.strip():
            self.add_finding(
                title="Udev rules files with permissive permissions",
                description="Writable udev rules allow non-root users to inject persistent commands",
                severity=Severity.CRITICAL,
                evidence=udev_perms.output.strip(),
                remediation="Fix permissions: chmod 644 on udev rules; chown root:root",
            )

        # Check for recently added udev rules
        recent_udev = session.execute(
            "find /etc/udev/rules.d/ -type f -mtime -7 2>/dev/null | head -10"
        )
        if recent_udev.success and recent_udev.output.strip():
            self.add_finding(
                title="Recently modified udev rules",
                description="Udev rules modified in the last 7 days should be reviewed",
                severity=Severity.MEDIUM,
                evidence=recent_udev.output.strip(),
                remediation="Verify recent udev rule changes against change management records",
            )

    def _check_python_startup(self, session: Session) -> None:
        """T1546.018: Check Python startup hooks."""
        # Check PYTHONSTARTUP environment variable
        pystartup = session.execute(
            "grep -rn 'PYTHONSTARTUP' /etc/environment /etc/profile /etc/profile.d/ "
            "/etc/bashrc /root/.bashrc /home/*/.bashrc 2>/dev/null | head -5"
        )
        if pystartup.success and pystartup.output.strip():
            self.add_finding(
                title="PYTHONSTARTUP environment variable set",
                description="PYTHONSTARTUP references a script executed on every interactive Python session",
                severity=Severity.HIGH,
                evidence=pystartup.output.strip(),
                remediation="Remove unauthorized PYTHONSTARTUP settings from environment and profile files",
            )

        # Check sitecustomize.py and usercustomize.py
        py_customize = session.execute(
            "find /usr/lib/python*/site-packages /usr/lib64/python*/site-packages "
            "/usr/local/lib/python*/site-packages "
            "-name 'sitecustomize.py' -o -name 'usercustomize.py' 2>/dev/null | head -10"
        )
        if py_customize.success and py_customize.output.strip():
            for pyfile in py_customize.output.strip().splitlines():
                # Check if it contains suspicious content
                content = session.execute(f"cat '{pyfile}' 2>/dev/null")
                if content.success and content.output.strip():
                    suspicious = session.execute(
                        f"grep -nE '{self.SUSPICIOUS_SHELL_PATTERNS}|import os|subprocess|socket' "
                        f"'{pyfile}' 2>/dev/null"
                    )
                    if suspicious.success and suspicious.output.strip():
                        self.add_finding(
                            title=f"Suspicious Python startup file: {pyfile}",
                            description="sitecustomize.py/usercustomize.py with suspicious imports runs on every Python invocation",
                            severity=Severity.HIGH,
                            evidence=suspicious.output.strip()[:300],
                            remediation=f"Audit and verify contents of {pyfile}; remove unauthorized code",
                        )

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Monitor shell profile files with auditd: -w /etc/profile.d/ -p wa -k shell_profiles",
            "Enforce gpgcheck=1 in all yum/dnf repo configurations to prevent malicious RPM scriptlets",
            "Restrict /etc/udev/rules.d/ permissions to 755 root:root and rule files to 644",
            "Use AIDE or OSSEC to detect unauthorized changes to shell profiles and Python startup files",
            "Enable SELinux in enforcing mode to constrain udev rule actions and shell profile modifications",
        ]

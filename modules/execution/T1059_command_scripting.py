"""T1059 — Command and Scripting Interpreter.

Checks availability and security controls around command-line interpreters
and scripting engines on RHEL systems. Covers Unix shells, Python, Node.js,
Lua, and enforcement via AppArmor/SELinux.
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class CommandScriptingCheck(BaseModule):
    TECHNIQUE_ID = "T1059"
    TECHNIQUE_NAME = "Command and Scripting Interpreter"
    TACTIC = Tactic.EXECUTION
    SEVERITY = Severity.HIGH
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    DANGEROUS_SHELLS = ["/bin/sh", "/bin/bash", "/bin/dash", "/bin/zsh", "/bin/ksh"]

    def check(self, session: Session) -> ModuleResult:
        self._check_unix_shells(session)
        self._check_bash_history(session)
        self._check_python(session)
        self._check_scripting_engines(session)
        self._check_lua(session)
        self._check_mandatory_access_control(session)

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    # -- T1059.004  Unix Shell ------------------------------------------------

    def _check_unix_shells(self, session: Session) -> None:
        """Check /etc/shells for dangerous or unrestricted shells."""
        result = session.execute("cat /etc/shells 2>/dev/null")
        if result.success and result.output:
            shells = [
                line.strip()
                for line in result.output.splitlines()
                if line.strip() and not line.strip().startswith("#")
            ]
            dangerous = [s for s in shells if s in self.DANGEROUS_SHELLS]
            if dangerous:
                self.add_finding(
                    title="Unrestricted shells available in /etc/shells",
                    description=(
                        "Multiple unrestricted shells are listed in /etc/shells, "
                        "allowing users to change their login shell to a full-featured interpreter."
                    ),
                    severity=Severity.MEDIUM,
                    evidence="\n".join(dangerous),
                    remediation=(
                        "Remove unnecessary shells from /etc/shells. "
                        "Use restricted shells (rbash) for service accounts."
                    ),
                )

        # Check if restricted shells are available
        rbash = session.execute("which rbash 2>/dev/null")
        if not rbash.success or not rbash.output.strip():
            self.add_finding(
                title="Restricted shell (rbash) not available",
                description="rbash is not installed; service accounts cannot be confined to a restricted shell.",
                severity=Severity.LOW,
                evidence="rbash not found in PATH",
                remediation="Install or symlink rbash and assign it to service accounts.",
            )

    def _check_bash_history(self, session: Session) -> None:
        """Check whether bash history logging is properly configured."""
        histcontrol = session.execute("echo $HISTCONTROL")
        if histcontrol.success and histcontrol.output.strip():
            value = histcontrol.output.strip()
            if "ignorespace" in value or "ignoreboth" in value:
                self.add_finding(
                    title="HISTCONTROL allows commands to be hidden",
                    description=(
                        "HISTCONTROL is set to a value that lets users hide commands "
                        "by prefixing them with a space."
                    ),
                    severity=Severity.MEDIUM,
                    evidence=f"HISTCONTROL={value}",
                    remediation=(
                        "Set HISTCONTROL='' in /etc/profile.d/ and mark HISTFILE/HISTCONTROL readonly."
                    ),
                )

        # Check if HISTFILE is immutable
        histfile_check = session.execute(
            "grep -r 'HISTFILE' /etc/profile /etc/profile.d/ /etc/bashrc 2>/dev/null"
        )
        readonly_check = session.execute(
            "grep -r 'readonly HISTFILE\\|declare -r HISTFILE' /etc/profile /etc/profile.d/ /etc/bashrc 2>/dev/null"
        )
        if not readonly_check.success or not readonly_check.output.strip():
            self.add_finding(
                title="Bash HISTFILE not set as readonly",
                description="Users can unset HISTFILE to disable command history logging.",
                severity=Severity.MEDIUM,
                evidence=histfile_check.output[:500] if histfile_check.output else "No HISTFILE configuration found",
                remediation="Add 'readonly HISTFILE' in /etc/profile.d/history.sh",
            )

    # -- T1059.006  Python ----------------------------------------------------

    def _check_python(self, session: Session) -> None:
        """Check Python availability and security posture."""
        for pybin in ("python3", "python"):
            which = session.execute(f"which {pybin} 2>/dev/null")
            if which.success and which.output.strip():
                path = which.output.strip()
                self.add_finding(
                    title=f"Python interpreter available: {path}",
                    description=(
                        "Python is available system-wide and can be used to execute "
                        "arbitrary code, import os/subprocess/ctypes, and bypass controls."
                    ),
                    severity=Severity.MEDIUM,
                    evidence=path,
                    remediation=(
                        "Remove Python from non-admin systems, or confine with SELinux. "
                        "Use 'alternatives' to restrict access."
                    ),
                )

                # Check for setuid bit
                suid = session.execute(f"stat -c '%a %U' {path} 2>/dev/null")
                if suid.success and suid.output.strip():
                    perms = suid.output.strip().split()[0]
                    if len(perms) == 4 and perms[0] in ("4", "6"):
                        self.add_finding(
                            title=f"Python binary has setuid bit: {path}",
                            description="The Python binary has the setuid bit set, enabling privilege escalation.",
                            severity=Severity.CRITICAL,
                            evidence=suid.output.strip(),
                            remediation=f"Remove setuid bit: chmod u-s {path}",
                        )
                break  # only report first found

    # -- T1059.005 / T1059.007  Other scripting engines -----------------------

    def _check_scripting_engines(self, session: Session) -> None:
        """Check availability of Node.js, cscript, and other scripting runtimes."""
        engines = [
            ("node", "Node.js JavaScript runtime"),
            ("cscript", "Windows Script Host (unexpected on RHEL)"),
            ("perl", "Perl interpreter"),
        ]
        for binary, desc in engines:
            result = session.execute(f"which {binary} 2>/dev/null")
            if result.success and result.output.strip():
                self.add_finding(
                    title=f"Scripting engine available: {desc}",
                    description=f"{desc} is installed and can be used for code execution.",
                    severity=Severity.LOW,
                    evidence=result.output.strip(),
                    remediation=f"Remove {binary} if not required, or confine with SELinux policy.",
                )

    # -- T1059.011  Lua -------------------------------------------------------

    def _check_lua(self, session: Session) -> None:
        """Check if Lua interpreter is installed."""
        for luabin in ("lua", "luajit"):
            result = session.execute(f"which {luabin} 2>/dev/null")
            if result.success and result.output.strip():
                self.add_finding(
                    title=f"Lua interpreter available: {luabin}",
                    description=f"{luabin} is installed and could be abused for script execution.",
                    severity=Severity.LOW,
                    evidence=result.output.strip(),
                    remediation=f"Remove {luabin} if not needed, or restrict via SELinux.",
                )

    # -- AppArmor / SELinux confinement ---------------------------------------

    def _check_mandatory_access_control(self, session: Session) -> None:
        """Check if SELinux or AppArmor is enforcing to confine shell access."""
        selinux = session.execute("getenforce 2>/dev/null")
        if selinux.success and selinux.output.strip():
            mode = selinux.output.strip()
            if mode.lower() != "enforcing":
                self.add_finding(
                    title=f"SELinux is not enforcing (mode: {mode})",
                    description="SELinux is not in enforcing mode; shell confinement is weakened.",
                    severity=Severity.HIGH,
                    evidence=f"getenforce: {mode}",
                    remediation="Set SELINUX=enforcing in /etc/selinux/config and run setenforce 1.",
                )
        else:
            # Check AppArmor as fallback
            apparmor = session.execute("aa-status 2>/dev/null")
            if not apparmor.success or not apparmor.output.strip():
                self.add_finding(
                    title="No mandatory access control (SELinux/AppArmor) detected",
                    description="Neither SELinux nor AppArmor is active to confine shell access.",
                    severity=Severity.HIGH,
                    evidence="getenforce and aa-status both failed",
                    remediation="Enable and configure SELinux in enforcing mode on RHEL systems.",
                )

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Enable SELinux in enforcing mode to confine shell and interpreter access.",
            "Remove unnecessary interpreters (python, perl, lua, node) from production systems.",
            "Set HISTCONTROL='' and 'readonly HISTFILE' in /etc/profile.d/ for all users.",
            "Assign restricted shells (rbash) to service and non-interactive accounts.",
            "Use fapolicyd or SELinux booleans to restrict script execution.",
        ]

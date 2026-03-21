"""T1574.007 — Path Interception by PATH Environment Variable.

Checks for writable PATH directories and PATH manipulation risks
that enable execution flow hijacking on RHEL systems.
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class PathHijackingCheck(BaseModule):
    TECHNIQUE_ID = "T1574.007"
    TECHNIQUE_NAME = "Path Interception by PATH Environment Variable"
    TACTIC = Tactic.DEFENSE_EVASION
    SEVERITY = Severity.HIGH
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        self._check_writable_path_dirs(session)
        self._check_relative_path(session)
        self._check_path_order(session)

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def _check_writable_path_dirs(self, session: Session) -> None:
        result = session.execute("echo $PATH")
        if result.success and result.output.strip():
            for d in result.output.strip().split(":"):
                if not d:
                    continue
                writable = session.execute(f"test -d {d} && test -w {d} && echo writable 2>/dev/null")
                if writable.success and "writable" in writable.output:
                    self.add_finding(
                        title=f"Writable PATH directory: {d}",
                        description=f"{d} is in PATH and writable — binaries can be planted to hijack execution",
                        severity=Severity.HIGH,
                        evidence=f"{d} is writable and in PATH",
                        remediation=f"Remove write permissions: chmod 755 {d}; chown root:root {d}",
                    )

    def _check_relative_path(self, session: Session) -> None:
        result = session.execute("echo $PATH")
        if result.success and result.output.strip():
            paths = result.output.strip().split(":")
            relative = [p for p in paths if p and not p.startswith("/")]
            if relative:
                self.add_finding(
                    title=f"Relative directories in PATH: {', '.join(relative)}",
                    description="Relative PATH entries allow hijacking from the current working directory",
                    severity=Severity.HIGH,
                    evidence=f"Relative paths: {', '.join(relative)}",
                    remediation="Remove relative paths from PATH; use only absolute paths",
                )
            if "" in paths or "." in paths:
                self.add_finding(
                    title="Empty or '.' entry in PATH",
                    description="Empty or dot PATH entry means CWD is searched — trivial binary planting",
                    severity=Severity.CRITICAL,
                    evidence="PATH contains empty or '.' entry",
                    remediation="Remove empty and '.' entries from PATH in all profile scripts",
                )

    def _check_path_order(self, session: Session) -> None:
        result = session.execute("echo $PATH")
        if result.success and result.output.strip():
            paths = result.output.strip().split(":")
            system_dirs = {"/usr/bin", "/usr/sbin", "/bin", "/sbin",
                          "/usr/local/bin", "/usr/local/sbin"}
            for i, p in enumerate(paths):
                if p in system_dirs:
                    # Check if any user-writable dir comes before system dirs
                    for j in range(i):
                        prev = paths[j]
                        if prev and prev not in system_dirs:
                            writable = session.execute(f"test -w {prev} && echo writable 2>/dev/null")
                            if writable.success and "writable" in writable.output:
                                self.add_finding(
                                    title=f"Writable dir {prev} precedes {p} in PATH",
                                    description=f"A writable directory comes before {p} — system binaries can be shadowed",
                                    severity=Severity.HIGH,
                                    evidence=f"PATH order: ...{prev}...{p}...",
                                    remediation=f"Reorder PATH so system directories come first",
                                )
                                return

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Ensure all PATH directories are owned by root with 755 permissions",
            "Remove relative and empty entries from PATH",
            "Place system directories (/usr/bin, /usr/sbin) first in PATH",
            "Use secure_path in sudoers to enforce a clean PATH for sudo",
        ]

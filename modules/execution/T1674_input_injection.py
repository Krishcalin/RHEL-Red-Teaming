"""T1674 — Input Injection.

Checks for conditions that allow adversaries to inject input events
on RHEL systems, including X11 forwarding, input simulation tools,
Xauthority permissions, and input device access controls.
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class InputInjectionCheck(BaseModule):
    TECHNIQUE_ID = "T1674"
    TECHNIQUE_NAME = "Input Injection"
    TACTIC = Tactic.EXECUTION
    SEVERITY = Severity.MEDIUM
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        self._check_x11_forwarding(session)
        self._check_input_tools(session)
        self._check_xauthority(session)
        self._check_wayland(session)
        self._check_input_devices(session)

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def _check_x11_forwarding(self, session: Session) -> None:
        """Check if X11 forwarding is enabled in SSH configuration."""
        result = session.execute(
            "grep -i '^\\s*X11Forwarding' /etc/ssh/sshd_config "
            "/etc/ssh/sshd_config.d/*.conf 2>/dev/null"
        )
        if result.success and result.output.strip():
            for line in result.output.strip().splitlines():
                if "yes" in line.lower():
                    self.add_finding(
                        title="X11 forwarding is enabled in SSH",
                        description=(
                            "X11 forwarding allows remote users to interact with the "
                            "display server, potentially enabling keylogging, screen "
                            "capture, and input injection attacks."
                        ),
                        severity=Severity.MEDIUM,
                        evidence=line.strip(),
                        remediation=(
                            "Disable X11 forwarding in /etc/ssh/sshd_config: "
                            "X11Forwarding no. Restart sshd after change."
                        ),
                    )
                    break
        else:
            # Default behavior check - X11Forwarding defaults to no in RHEL
            # but worth noting if not explicitly set
            pass

        # Check X11UseLocalhost setting
        localhost_result = session.execute(
            "grep -i '^\\s*X11UseLocalhost' /etc/ssh/sshd_config "
            "/etc/ssh/sshd_config.d/*.conf 2>/dev/null"
        )
        if localhost_result.success and localhost_result.output.strip():
            for line in localhost_result.output.strip().splitlines():
                if "no" in line.lower():
                    self.add_finding(
                        title="X11UseLocalhost is disabled",
                        description=(
                            "X11UseLocalhost is set to no, allowing X11 forwarding "
                            "connections from non-localhost addresses, broadening "
                            "the attack surface for input injection."
                        ),
                        severity=Severity.MEDIUM,
                        evidence=line.strip(),
                        remediation=(
                            "Set X11UseLocalhost yes in /etc/ssh/sshd_config."
                        ),
                    )
                    break

    def _check_input_tools(self, session: Session) -> None:
        """Check if input injection tools (xdotool, xte, xdo) are available."""
        tools = [
            ("xdotool", "X11 automation tool capable of simulating keyboard/mouse input"),
            ("xte", "XAutomate tool for generating keyboard/mouse events"),
            ("xdo", "X11 utility for performing actions on windows"),
            ("xmodmap", "X11 keyboard modifier map tool"),
            ("xinput", "X11 input device configuration and monitoring tool"),
        ]
        found_tools = []
        for tool, desc in tools:
            result = session.execute(f"which {tool} 2>/dev/null")
            if result.success and result.output.strip():
                found_tools.append(f"{tool}: {result.output.strip()} - {desc}")

        if found_tools:
            self.add_finding(
                title="Input injection/simulation tools available",
                description=(
                    f"{len(found_tools)} input simulation tool(s) are installed that "
                    "can be used to inject keystrokes, mouse clicks, or manipulate "
                    "input devices programmatically."
                ),
                severity=Severity.MEDIUM,
                evidence="\n".join(found_tools),
                remediation=(
                    "Remove unnecessary input simulation tools: "
                    "dnf remove xdotool xautomation xdo. "
                    "Restrict access via SELinux if tools are needed."
                ),
            )

    def _check_xauthority(self, session: Session) -> None:
        """Check Xauthority file permissions."""
        result = session.execute(
            "find /home /root -name '.Xauthority' -maxdepth 2 2>/dev/null"
        )
        if not result.success or not result.output.strip():
            return

        insecure_files = []
        for xauth_file in result.output.strip().splitlines():
            xauth_file = xauth_file.strip()
            if not xauth_file:
                continue
            perms_result = session.execute(
                f"stat -c '%a %U %G' '{xauth_file}' 2>/dev/null"
            )
            if perms_result.success and perms_result.output.strip():
                parts = perms_result.output.strip().split()
                if len(parts) >= 1:
                    perms = parts[0]
                    # Xauthority should be 600 (owner read/write only)
                    if perms != "600" and perms != "0600":
                        insecure_files.append(
                            f"{xauth_file}: permissions {perms}"
                        )

        if insecure_files:
            self.add_finding(
                title="Xauthority files with insecure permissions",
                description=(
                    "Xauthority files with overly permissive access could allow "
                    "other users to connect to the X display and inject input events."
                ),
                severity=Severity.MEDIUM,
                evidence="\n".join(insecure_files),
                remediation=(
                    "Set Xauthority file permissions to 600: "
                    "chmod 600 ~/.Xauthority"
                ),
            )

    def _check_wayland(self, session: Session) -> None:
        """Check if Wayland is in use (more secure than X11 for input isolation)."""
        # Check if Wayland is the active display server
        result = session.execute("echo $XDG_SESSION_TYPE 2>/dev/null")
        session_type = result.output.strip() if result.success else ""

        if not session_type:
            result = session.execute("loginctl show-session $(loginctl | awk 'NR==2{print $1}') -p Type 2>/dev/null")
            if result.success and result.output.strip():
                session_type = result.output.strip().split("=")[-1]

        if session_type == "x11":
            self.add_finding(
                title="X11 display server in use (less secure than Wayland)",
                description=(
                    "The system is using X11 as the display server. X11 has a "
                    "shared input model that allows any X client to capture keystrokes "
                    "and inject input events into other applications. Wayland provides "
                    "better input isolation between clients."
                ),
                severity=Severity.MEDIUM,
                evidence=f"Session type: {session_type}",
                remediation=(
                    "Switch to Wayland display server where supported. "
                    "On RHEL 8+, set WaylandEnable=true in /etc/gdm/custom.conf."
                ),
            )
        elif session_type == "tty":
            # No graphical session, not vulnerable to display-level injection
            pass

    def _check_input_devices(self, session: Session) -> None:
        """Check if /dev/input/* devices are readable by non-root users."""
        result = session.execute(
            "ls -la /dev/input/ 2>/dev/null | grep -v '^total'"
        )
        if not result.success or not result.output.strip():
            return

        world_readable = []
        for line in result.output.strip().splitlines():
            parts = line.split()
            if len(parts) < 9:
                continue
            perms = parts[0]
            name = parts[-1]
            # Check if world-readable (others have 'r')
            if len(perms) >= 8 and perms[7] == "r":
                world_readable.append(f"{name}: {perms}")

        if world_readable:
            self.add_finding(
                title="Input devices readable by non-root users",
                description=(
                    f"{len(world_readable)} input device(s) under /dev/input/ are "
                    "world-readable, potentially allowing unprivileged users to "
                    "capture keyboard and mouse events (keylogging)."
                ),
                severity=Severity.HIGH,
                evidence="\n".join(world_readable[:10]),
                remediation=(
                    "Restrict /dev/input/* permissions via udev rules. "
                    "Create /etc/udev/rules.d/99-input.rules with: "
                    'KERNEL=="event*", SUBSYSTEM=="input", MODE="0640", GROUP="input"'
                ),
            )

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Disable X11 forwarding in /etc/ssh/sshd_config (X11Forwarding no).",
            "Remove input injection tools (xdotool, xte) from production systems.",
            "Restrict /dev/input/* device permissions to root and the input group via udev rules.",
            "Switch to Wayland display server for stronger per-application input isolation.",
            "Ensure .Xauthority files are set to mode 600 and owned by the respective user.",
        ]

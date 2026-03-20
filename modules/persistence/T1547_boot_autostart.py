"""T1547 — Boot or Logon Autostart Execution.

Checks for persistence via kernel modules, XDG autostart entries, rc.local,
and GRUB init overrides on RHEL systems.
Sub-techniques: T1547.006 (Kernel Modules), T1547.013 (XDG Autostart Entries).
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class BootAutostartCheck(BaseModule):
    TECHNIQUE_ID = "T1547"
    TECHNIQUE_NAME = "Boot or Logon Autostart Execution"
    TACTIC = Tactic.PERSISTENCE
    SEVERITY = Severity.HIGH
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = True
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        # --- T1547.006: Kernel Modules ---

        # Check /etc/modules-load.d/ for suspicious entries
        modules_load = session.execute(
            "cat /etc/modules-load.d/*.conf 2>/dev/null | grep -v '^#' | grep -v '^$'"
        )
        if modules_load.success and modules_load.output.strip():
            # Cross-reference with RPM to find non-packaged configs
            unpackaged_conf = session.execute(
                "for f in /etc/modules-load.d/*.conf; do "
                "rpm -qf \"$f\" 2>/dev/null || echo \"UNPACKAGED: $f\"; "
                "done 2>/dev/null | grep '^UNPACKAGED' | head -10"
            )
            if unpackaged_conf.success and unpackaged_conf.output.strip():
                self.add_finding(
                    title="Unpackaged kernel module load configs in /etc/modules-load.d/",
                    description="Non-RPM configuration files may load malicious kernel modules at boot",
                    severity=Severity.HIGH,
                    evidence=f"Configs: {unpackaged_conf.output.strip()}\nModules: {modules_load.output.strip()}",
                    remediation="Audit /etc/modules-load.d/ configs; remove entries not required for system operation",
                )

        # Check lsmod for unusual modules (not matching kernel RPM)
        unusual_modules = session.execute(
            "lsmod 2>/dev/null | tail -n +2 | awk '{print $1}' "
            "| while read mod; do modinfo \"$mod\" 2>/dev/null | grep -q 'intree:.*Y' || "
            "echo \"OUT-OF-TREE: $mod\"; done | head -10"
        )
        if unusual_modules.success and unusual_modules.output.strip():
            self.add_finding(
                title="Out-of-tree kernel modules loaded",
                description="Kernel modules not marked as in-tree may be rootkits or unauthorized drivers",
                severity=Severity.HIGH,
                evidence=unusual_modules.output.strip(),
                remediation="Investigate out-of-tree modules with modinfo; remove unauthorized modules with rmmod and blacklist them",
            )

        # Check modprobe.d for load-on-boot configs
        modprobe_install = session.execute(
            "grep -rn 'install\\|softdep' /etc/modprobe.d/ 2>/dev/null | grep -v '^#' | head -10"
        )
        if modprobe_install.success and modprobe_install.output.strip():
            self.add_finding(
                title="Custom module install/softdep rules in modprobe.d",
                description="Install and softdep directives in modprobe.d can execute commands when modules load",
                severity=Severity.MEDIUM,
                evidence=modprobe_install.output.strip(),
                remediation="Audit /etc/modprobe.d/ install rules; ensure no arbitrary commands are executed on module load",
            )

        # Check if module signing is enforced
        module_signing = session.execute(
            "cat /proc/sys/kernel/modules_disabled 2>/dev/null; "
            "cat /sys/module/module/parameters/sig_enforce 2>/dev/null"
        )
        if module_signing.success:
            lines = module_signing.output.strip().split("\n")
            modules_disabled = lines[0].strip() if len(lines) > 0 else ""
            sig_enforce = lines[1].strip() if len(lines) > 1 else ""
            if modules_disabled != "1" and sig_enforce != "Y":
                self.add_finding(
                    title="Kernel module signing not enforced",
                    description="Without module signature enforcement, unsigned (potentially malicious) modules can be loaded",
                    severity=Severity.HIGH,
                    evidence=f"modules_disabled={modules_disabled}, sig_enforce={sig_enforce}",
                    remediation="Enable module signature enforcement in GRUB: module.sig_enforce=1; or set modules_disabled=1 after boot",
                )

        # --- T1547.013: XDG Autostart ---

        # Check system-wide XDG autostart
        xdg_system = session.execute(
            "find /etc/xdg/autostart/ -name '*.desktop' 2>/dev/null | head -10"
        )
        if xdg_system.success and xdg_system.output.strip():
            xdg_exec = session.execute(
                "grep -h 'Exec=' /etc/xdg/autostart/*.desktop 2>/dev/null | head -10"
            )
            unpackaged_xdg = session.execute(
                "for f in /etc/xdg/autostart/*.desktop; do "
                "rpm -qf \"$f\" 2>/dev/null || echo \"UNPACKAGED: $f\"; "
                "done 2>/dev/null | grep '^UNPACKAGED' | head -10"
            )
            if unpackaged_xdg.success and unpackaged_xdg.output.strip():
                self.add_finding(
                    title="Unpackaged XDG autostart entries found",
                    description="Desktop autostart files not from RPM packages may execute malicious commands at user login",
                    severity=Severity.HIGH,
                    evidence=f"{unpackaged_xdg.output.strip()}\n{xdg_exec.output.strip() if xdg_exec.success else ''}",
                    remediation="Remove unauthorized .desktop files from /etc/xdg/autostart/",
                )

        # Check user-level XDG autostart
        user_xdg = session.execute(
            "find /home/*/.config/autostart/ /root/.config/autostart/ -name '*.desktop' 2>/dev/null | head -10"
        )
        if user_xdg.success and user_xdg.output.strip():
            user_xdg_exec = session.execute(
                "grep -h 'Exec=' /home/*/.config/autostart/*.desktop /root/.config/autostart/*.desktop 2>/dev/null | head -10"
            )
            self.add_finding(
                title="User-level XDG autostart entries detected",
                description="User autostart .desktop files execute commands at graphical login",
                severity=Severity.MEDIUM,
                evidence=f"Files: {user_xdg.output.strip()}\nExec: {user_xdg_exec.output.strip() if user_xdg_exec.success else ''}",
                remediation="Audit user autostart entries; check Exec= lines for suspicious commands or paths",
            )

        # Check /etc/rc.local and /etc/rc.d/rc.local
        rc_local = session.execute(
            "for f in /etc/rc.local /etc/rc.d/rc.local; do "
            "if [ -f \"$f\" ] && [ -x \"$f\" ]; then "
            "echo \"EXECUTABLE: $f\"; cat \"$f\" 2>/dev/null | grep -v '^#' | grep -v '^$'; "
            "fi; done"
        )
        if rc_local.success and rc_local.output.strip():
            self.add_finding(
                title="Executable rc.local found with active commands",
                description="rc.local runs commands as root at boot — a classic persistence mechanism",
                severity=Severity.HIGH,
                evidence=rc_local.output.strip(),
                remediation="Remove executable permission from rc.local: chmod -x /etc/rc.d/rc.local; audit its contents",
            )

        # Check rc-local.service status
        rc_local_svc = session.execute(
            "systemctl is-enabled rc-local.service 2>/dev/null"
        )
        if rc_local_svc.success and "enabled" in rc_local_svc.output.strip():
            self.add_finding(
                title="rc-local.service is enabled",
                description="The rc-local systemd service runs /etc/rc.d/rc.local at boot as root",
                severity=Severity.MEDIUM,
                evidence=rc_local_svc.output.strip(),
                remediation="Disable rc-local.service: systemctl disable rc-local.service",
            )

        # Check GRUB config for init= overrides
        grub_init = session.execute(
            "grep -i 'init=' /boot/grub2/grub.cfg /etc/default/grub /boot/efi/EFI/redhat/grub.cfg 2>/dev/null "
            "| grep -v '^#' | head -5"
        )
        if grub_init.success and grub_init.output.strip():
            self.add_finding(
                title="GRUB init= override detected",
                description="An init= parameter in GRUB replaces the default init process, potentially running a backdoor as PID 1",
                severity=Severity.CRITICAL,
                evidence=grub_init.output.strip(),
                remediation="Remove init= overrides from /etc/default/grub; run grub2-mkconfig -o /boot/grub2/grub.cfg",
            )

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Enforce kernel module signing: add module.sig_enforce=1 to GRUB kernel command line",
            "Monitor /etc/modules-load.d/, /etc/modprobe.d/, and /etc/xdg/autostart/ with auditd file watches",
            "Disable and remove /etc/rc.d/rc.local; disable rc-local.service",
            "Protect GRUB configuration with grub2-setpassword and restrict /boot/grub2/grub.cfg permissions",
            "Use AIDE file integrity monitoring to detect unauthorized changes to autostart locations",
        ]

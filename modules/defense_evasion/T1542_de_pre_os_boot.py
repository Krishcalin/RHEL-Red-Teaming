"""T1542 — Pre-OS Boot (Defense Evasion perspective).

Checks for Secure Boot bypass opportunities, unsigned kernel modules,
unprotected GRUB configuration, boot parameter manipulation, and
unrestricted UEFI firmware updates on RHEL systems.
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class PreOSBootEvasionCheck(BaseModule):
    TECHNIQUE_ID = "T1542"
    TECHNIQUE_NAME = "Pre-OS Boot"
    TACTIC = Tactic.DEFENSE_EVASION
    SEVERITY = Severity.CRITICAL
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        self._check_secure_boot_bypass(session)
        self._check_unsigned_kernel_modules(session)
        self._check_grub_authentication(session)
        self._check_boot_parameter_manipulation(session)
        self._check_uefi_firmware_restriction(session)

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    # -- Secure Boot bypass via MOK enrollment --------------------------------

    def _check_secure_boot_bypass(self, session: Session) -> None:
        sb_state = session.execute("mokutil --sb-state 2>/dev/null")
        if sb_state.success:
            output = sb_state.output.strip().lower()
            if "disabled" in output:
                self.add_finding(
                    title="Secure Boot is disabled",
                    description=(
                        "Secure Boot is not enabled, allowing unsigned bootloaders "
                        "and kernel modules to load without verification. An attacker "
                        "could persist via boot-level implants undetected."
                    ),
                    severity=Severity.CRITICAL,
                    evidence=sb_state.output.strip(),
                    remediation="Enable Secure Boot in UEFI firmware settings",
                )
        else:
            self.add_finding(
                title="Unable to determine Secure Boot status",
                description="mokutil is not available or failed — Secure Boot status cannot be verified",
                severity=Severity.MEDIUM,
                evidence="mokutil --sb-state failed",
                remediation="Install mokutil and verify Secure Boot is enabled: dnf install mokutil",
            )

        # Check for pending MOK enrollments that could add unauthorized keys
        mok_pending = session.execute("mokutil --list-new 2>/dev/null")
        if mok_pending.success and mok_pending.output.strip() and "empty" not in mok_pending.output.lower():
            self.add_finding(
                title="Pending MOK key enrollment detected",
                description=(
                    "A Machine Owner Key is pending enrollment. An attacker could "
                    "enroll a key to sign malicious kernel modules that bypass Secure Boot."
                ),
                severity=Severity.HIGH,
                evidence=mok_pending.output.strip()[:500],
                remediation="Review pending MOK enrollments with mokutil --list-new and delete unauthorized keys",
            )

    # -- Unsigned kernel modules loaded ---------------------------------------

    def _check_unsigned_kernel_modules(self, session: Session) -> None:
        # Check for modules loaded without proper signature
        unsigned = session.execute(
            "for mod in $(lsmod | awk 'NR>1{print $1}'); do "
            "modinfo $mod 2>/dev/null | grep -q 'sig_id' || echo $mod; "
            "done 2>/dev/null | head -20"
        )
        if unsigned.success and unsigned.output.strip():
            modules = unsigned.output.strip().splitlines()
            self.add_finding(
                title=f"Unsigned kernel modules loaded ({len(modules)} found)",
                description=(
                    "Kernel modules without valid signatures are loaded. "
                    "These could be used to inject rootkits or hide malicious activity "
                    "from security tools operating in user space."
                ),
                severity=Severity.HIGH,
                evidence=unsigned.output.strip()[:500],
                remediation="Enable kernel module signature enforcement: add module.sig_enforce=1 to kernel boot parameters",
            )

        # Check if module signature enforcement is enabled
        sig_enforce = session.execute("cat /proc/sys/kernel/modules_disabled 2>/dev/null")
        if sig_enforce.success and sig_enforce.output.strip() == "0":
            sig_verify = session.execute("cat /proc/sys/kernel/module_sig_enforce 2>/dev/null")
            if sig_verify.success and sig_verify.output.strip() == "0":
                self.add_finding(
                    title="Kernel module signature enforcement is disabled",
                    description="The kernel does not enforce module signatures, allowing arbitrary module loading",
                    severity=Severity.HIGH,
                    evidence="module_sig_enforce=0",
                    remediation="Set module.sig_enforce=1 in GRUB kernel parameters",
                )

    # -- GRUB config modification without authentication ----------------------

    def _check_grub_authentication(self, session: Session) -> None:
        # Check for GRUB password protection
        grub_files = [
            "/etc/grub.d/01_users",
            "/etc/grub.d/40_custom",
            "/boot/grub2/grub.cfg",
            "/boot/efi/EFI/redhat/grub.cfg",
        ]
        password_found = False
        for grub_file in grub_files:
            result = session.execute(f"grep -l 'password_pbkdf2\\|password ' '{grub_file}' 2>/dev/null || true")
            if result.success and result.output.strip():
                password_found = True
                break

        if not password_found:
            self.add_finding(
                title="GRUB bootloader is not password protected",
                description=(
                    "No GRUB password is configured. An attacker with physical or console "
                    "access can edit boot parameters to gain single-user root access or "
                    "boot from alternative media, bypassing all OS-level security."
                ),
                severity=Severity.CRITICAL,
                evidence="No password_pbkdf2 directive found in GRUB configuration",
                remediation="Set GRUB password: grub2-setpassword and regenerate grub.cfg",
            )

        # Check GRUB config file permissions
        for cfg in ["/boot/grub2/grub.cfg", "/boot/efi/EFI/redhat/grub.cfg"]:
            perms = session.execute(f"stat -c '%a %U' '{cfg}' 2>/dev/null || true")
            if perms.success and perms.output.strip():
                parts = perms.output.strip().split()
                if len(parts) >= 2:
                    mode = parts[0]
                    owner = parts[1]
                    if mode != "600" and mode != "400":
                        self.add_finding(
                            title=f"GRUB config has permissive mode: {cfg} ({mode})",
                            description="GRUB configuration is readable by non-root users, potentially exposing boot parameters",
                            severity=Severity.MEDIUM,
                            evidence=f"Mode: {mode}, Owner: {owner}",
                            remediation=f"Restrict permissions: chmod 600 {cfg}",
                        )

    # -- Boot parameter manipulation (init=/bin/sh) ---------------------------

    def _check_boot_parameter_manipulation(self, session: Session) -> None:
        # Check current kernel parameters for suspicious entries
        cmdline = session.execute("cat /proc/cmdline 2>/dev/null")
        if cmdline.success and cmdline.output.strip():
            suspicious = ["init=/bin/sh", "init=/bin/bash", "single", "emergency", "rd.break", "rescue"]
            for param in suspicious:
                if param in cmdline.output:
                    self.add_finding(
                        title=f"Suspicious boot parameter detected: {param}",
                        description=f"The kernel was booted with '{param}' which may indicate boot-level compromise or debugging left enabled",
                        severity=Severity.CRITICAL,
                        evidence=cmdline.output.strip(),
                        remediation="Reboot with standard parameters and investigate how boot parameters were modified",
                    )

        # Check if single-user mode requires root password
        sulogin = session.execute("grep -r 'sulogin' /usr/lib/systemd/system/emergency.service /usr/lib/systemd/system/rescue.service 2>/dev/null || true")
        if not sulogin.success or not sulogin.output.strip():
            self.add_finding(
                title="Single-user/rescue mode may not require authentication",
                description="The rescue/emergency targets do not appear to use sulogin, allowing passwordless root access at boot",
                severity=Severity.HIGH,
                evidence="No sulogin reference found in rescue/emergency service units",
                remediation="Ensure rescue.service and emergency.service use sulogin for authentication",
            )

    # -- UEFI firmware update restriction -------------------------------------

    def _check_uefi_firmware_restriction(self, session: Session) -> None:
        # Check if fwupd is installed and whether firmware updates are restricted
        fwupd = session.execute("systemctl is-active fwupd 2>/dev/null")
        if fwupd.success and fwupd.output.strip() == "active":
            # Check if firmware updates require authentication
            polkit = session.execute(
                "grep -r 'org.freedesktop.fwupd' /usr/share/polkit-1/actions/ 2>/dev/null | "
                "grep -i 'allow_active' || true"
            )
            if polkit.success and "yes" in polkit.output.lower():
                self.add_finding(
                    title="Firmware updates allowed without admin authentication",
                    description=(
                        "fwupd allows firmware updates without requiring admin credentials. "
                        "An attacker could install malicious firmware to persist below the OS level."
                    ),
                    severity=Severity.HIGH,
                    evidence=polkit.output.strip()[:500],
                    remediation="Configure polkit to require admin authentication for firmware updates",
                )

        # Check if UEFI capsule updates are possible
        capsule = session.execute("ls /sys/firmware/efi/efivars/ 2>/dev/null | head -5")
        if capsule.success and capsule.output.strip():
            efi_writable = session.execute("test -w /sys/firmware/efi/efivars/ && echo writable || true")
            if efi_writable.success and "writable" in efi_writable.output:
                self.add_finding(
                    title="EFI variables are writable",
                    description="The EFI variables filesystem is writable, potentially allowing UEFI-level persistence",
                    severity=Severity.MEDIUM,
                    evidence="EFI variables directory is writable by current user",
                    remediation="Restrict access to EFI variables and enable Secure Boot to prevent unauthorized firmware modifications",
                )

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Enable Secure Boot and enforce kernel module signature verification (module.sig_enforce=1)",
            "Protect GRUB with a password: grub2-setpassword and restrict grub.cfg to mode 600",
            "Ensure rescue and emergency modes require root authentication via sulogin",
            "Monitor MOK key enrollments and restrict mokutil access to authorized administrators",
            "Use fwupd with polkit authentication requirements for all firmware updates",
        ]

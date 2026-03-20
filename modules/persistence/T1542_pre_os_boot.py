"""T1542 — Pre-OS Boot.

Checks for persistence via firmware, bootloader, or boot partition manipulation.
Sub-techniques: T1542.002 (Component Firmware), T1542.003 (Bootkit).
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class PreOSBootCheck(BaseModule):
    TECHNIQUE_ID = "T1542"
    TECHNIQUE_NAME = "Pre-OS Boot"
    TACTIC = Tactic.PERSISTENCE
    SEVERITY = Severity.CRITICAL
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        # ---- T1542.002: Component Firmware ----

        # Check if fwupd is installed
        fwupd_installed = session.execute("rpm -q fwupd 2>/dev/null")
        if not fwupd_installed.success or "not installed" in fwupd_installed.output:
            self.add_finding(
                title="fwupd not installed",
                description=(
                    "The firmware update daemon (fwupd) is not installed. Without it, "
                    "firmware updates cannot be managed and firmware integrity cannot be verified."
                ),
                severity=Severity.MEDIUM,
                evidence="fwupd package not found",
                remediation="Install fwupd: dnf install fwupd; enable fwupd.service",
            )
        else:
            # Check if firmware is current
            fw_updates = session.execute("fwupdmgr get-updates 2>/dev/null")
            if fw_updates.success and fw_updates.output.strip() and "No upgrades" not in fw_updates.output:
                self.add_finding(
                    title="Firmware updates available",
                    description="Outdated firmware may contain vulnerabilities exploitable for pre-OS persistence",
                    severity=Severity.MEDIUM,
                    evidence=fw_updates.output.strip()[:500],
                    remediation="Apply firmware updates: fwupdmgr update; schedule regular firmware update checks",
                )

        # ---- T1542.003: Bootkit ----

        # Check if Secure Boot is enabled
        sb_state = session.execute("mokutil --sb-state 2>/dev/null")
        if sb_state.success:
            if "disabled" in sb_state.output.lower():
                self.add_finding(
                    title="UEFI Secure Boot is disabled",
                    description=(
                        "Secure Boot is disabled, allowing unsigned or tampered bootloaders "
                        "and kernels to execute. This is critical for bootkit prevention."
                    ),
                    severity=Severity.CRITICAL,
                    evidence=sb_state.output.strip(),
                    remediation="Enable Secure Boot in UEFI firmware settings; enroll RHEL keys with mokutil",
                )
        else:
            # mokutil not available or not UEFI
            efi_check = session.execute("test -d /sys/firmware/efi && echo 'UEFI' || echo 'BIOS'")
            if efi_check.success and "BIOS" in efi_check.output:
                self.add_finding(
                    title="System booted in legacy BIOS mode",
                    description="Legacy BIOS mode does not support Secure Boot, reducing protection against bootkits",
                    severity=Severity.MEDIUM,
                    evidence=efi_check.output.strip(),
                    remediation="Where possible, migrate to UEFI with Secure Boot enabled",
                )

        # Check GRUB config file permissions
        grub_configs = [
            "/boot/grub2/grub.cfg",
            "/boot/efi/EFI/redhat/grub.cfg",
            "/etc/default/grub",
        ]
        for cfg in grub_configs:
            perms = session.execute(f"stat -c '%a %U %G' {cfg} 2>/dev/null")
            if perms.success and perms.output.strip():
                parts = perms.output.strip().split()
                if len(parts) == 3:
                    mode, owner, group = parts
                    # grub.cfg should be 600 root:root ideally
                    if owner != "root" or group != "root":
                        self.add_finding(
                            title=f"GRUB config {cfg} not owned by root",
                            description=f"GRUB configuration file {cfg} is owned by {owner}:{group} instead of root:root",
                            severity=Severity.CRITICAL,
                            evidence=f"{cfg}: mode={mode} owner={owner} group={group}",
                            remediation=f"Fix ownership: chown root:root {cfg}; chmod 600 {cfg}",
                        )
                    elif int(mode, 8) & 0o077:
                        self.add_finding(
                            title=f"GRUB config {cfg} has excessive permissions",
                            description=f"GRUB configuration file is readable/writable by non-root users (mode {mode})",
                            severity=Severity.HIGH,
                            evidence=f"{cfg}: mode={mode}",
                            remediation=f"Restrict permissions: chmod 600 {cfg}",
                        )

        # Check if GRUB password is set
        grub_password = session.execute(
            "grep -E '^(set superusers|password_pbkdf2|password)' "
            "/etc/grub.d/* /boot/grub2/user.cfg 2>/dev/null"
        )
        if not grub_password.success or not grub_password.output.strip():
            self.add_finding(
                title="GRUB bootloader password not set",
                description=(
                    "No GRUB password is configured. An attacker with physical or console "
                    "access can edit boot parameters to gain single-user (root) access."
                ),
                severity=Severity.HIGH,
                evidence="No superusers or password directives found in GRUB config",
                remediation="Set GRUB password: grub2-setpassword; regenerate config with grub2-mkconfig -o /boot/grub2/grub.cfg",
            )

        # Check /boot partition permissions
        boot_perms = session.execute("stat -c '%a %U %G' /boot 2>/dev/null")
        if boot_perms.success and boot_perms.output.strip():
            parts = boot_perms.output.strip().split()
            if len(parts) == 3:
                mode = parts[0]
                if int(mode, 8) & 0o002:
                    self.add_finding(
                        title="/boot directory is world-writable",
                        description="The /boot directory is world-writable, allowing any user to modify kernel and bootloader files",
                        severity=Severity.CRITICAL,
                        evidence=f"/boot: mode={mode}",
                        remediation="Fix permissions: chmod 755 /boot; chown root:root /boot",
                    )

        # Check for files in /boot not owned by root
        boot_ownership = session.execute(
            "find /boot -not -user root -type f 2>/dev/null | head -10"
        )
        if boot_ownership.success and boot_ownership.output.strip():
            self.add_finding(
                title="Files in /boot not owned by root",
                description="Boot files not owned by root could be tampered with by non-root users",
                severity=Severity.HIGH,
                evidence=boot_ownership.output.strip(),
                remediation="Fix ownership: chown root:root on all /boot files; investigate how ownership changed",
            )

        # Check for EFI shell access
        efi_shell = session.execute(
            "find /boot/efi/ -iname '*shell*' -o -iname '*.efi' 2>/dev/null "
            "| grep -iv 'grub\\|shim\\|mm\\|fwupd\\|redhat' | head -10"
        )
        if efi_shell.success and efi_shell.output.strip():
            self.add_finding(
                title="Non-standard EFI binaries found in ESP",
                description=(
                    "Unexpected EFI binaries in the EFI System Partition could include "
                    "EFI shells or bootkit payloads."
                ),
                severity=Severity.HIGH,
                evidence=efi_shell.output.strip(),
                remediation="Audit all .efi files in /boot/efi/; remove unauthorized EFI binaries; enable Secure Boot",
            )

        # Check kernel command line for suspicious parameters
        cmdline = session.execute("cat /proc/cmdline 2>/dev/null")
        if cmdline.success and cmdline.output.strip():
            suspicious_params = [
                "init=/bin/bash", "init=/bin/sh", "single", "emergency",
                "rd.break", "enforcing=0", "selinux=0", "audit=0",
            ]
            found_suspicious = [
                param for param in suspicious_params
                if param in cmdline.output.lower()
            ]
            if found_suspicious:
                self.add_finding(
                    title="Suspicious kernel command line parameters detected",
                    description=(
                        "The kernel was booted with parameters that may indicate "
                        "security controls were bypassed or the system was booted into recovery mode."
                    ),
                    severity=Severity.CRITICAL,
                    evidence=f"Suspicious parameters: {', '.join(found_suspicious)}\nFull cmdline: {cmdline.output.strip()}",
                    remediation="Reboot with correct parameters; set GRUB password to prevent command line editing",
                )

        # Check GRUB config integrity against RPM
        grub_verify = session.execute("rpm -V grub2-common grub2-tools 2>/dev/null")
        if grub_verify.success and grub_verify.output.strip():
            self.add_finding(
                title="GRUB package files have been modified",
                description="GRUB files differ from their RPM-installed state, which could indicate tampering",
                severity=Severity.HIGH,
                evidence=grub_verify.output.strip()[:500],
                remediation="Investigate modified files; reinstall grub2 packages: dnf reinstall grub2-common grub2-tools",
            )

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Enable UEFI Secure Boot and enroll RHEL signing keys to prevent unsigned bootloader/kernel execution",
            "Set a GRUB bootloader password with grub2-setpassword to prevent unauthorized boot parameter changes",
            "Restrict /boot and GRUB config permissions to root:root 600; monitor with auditd (-w /boot/ -p wa)",
            "Install and enable fwupd for firmware update management; schedule regular firmware integrity checks",
            "Ensure SELinux is set to enforcing (not disabled via kernel cmdline) and audit kernel boot parameters",
        ]

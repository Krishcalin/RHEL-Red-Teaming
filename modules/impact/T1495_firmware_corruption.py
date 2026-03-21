"""T1495 — Firmware Corruption.

Checks firmware write access, Secure Boot status, and firmware update
tool availability on RHEL systems.
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class FirmwareCorruptionCheck(BaseModule):
    TECHNIQUE_ID = "T1495"
    TECHNIQUE_NAME = "Firmware Corruption"
    TACTIC = Tactic.IMPACT
    SEVERITY = Severity.CRITICAL
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        self._check_secure_boot(session)
        self._check_firmware_tools(session)
        self._check_efi_access(session)
        self._check_fwupd(session)

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def _check_secure_boot(self, session: Session) -> None:
        result = session.execute("mokutil --sb-state 2>/dev/null")
        if result.success and result.output.strip():
            if "disabled" in result.output.lower():
                self.add_finding(
                    title="UEFI Secure Boot is disabled",
                    description="Without Secure Boot, firmware and bootloader can be tampered with",
                    severity=Severity.HIGH,
                    evidence=result.output.strip(),
                    remediation="Enable Secure Boot in UEFI/BIOS settings",
                )
        else:
            legacy = session.execute("test -d /sys/firmware/efi && echo UEFI || echo BIOS")
            if legacy.success and "BIOS" in legacy.output:
                self.add_finding(
                    title="System booted in legacy BIOS mode",
                    description="BIOS mode does not support Secure Boot — firmware integrity is unverified",
                    severity=Severity.MEDIUM,
                    evidence="No EFI firmware interface detected",
                    remediation="Migrate to UEFI with Secure Boot enabled where possible",
                )

    def _check_firmware_tools(self, session: Session) -> None:
        tools = {"flashrom": "low-level firmware flash tool",
                 "dmidecode": "SMBIOS/DMI data reader",
                 "efibootmgr": "EFI boot manager"}
        for tool, desc in tools.items():
            result = session.execute(f"which {tool} 2>/dev/null")
            if result.success and result.output.strip():
                self.add_finding(
                    title=f"Firmware tool available: {tool}",
                    description=f"{tool} ({desc}) is installed",
                    severity=Severity.LOW,
                    evidence=result.output.strip(),
                    remediation=f"Restrict access to {tool} if not needed for operations",
                )

    def _check_efi_access(self, session: Session) -> None:
        efi_vars = session.execute("test -d /sys/firmware/efi/efivars && ls /sys/firmware/efi/efivars/ 2>/dev/null | wc -l")
        if efi_vars.success and efi_vars.output.strip():
            try:
                count = int(efi_vars.output.strip())
                if count > 0:
                    writable = session.execute(
                        "find /sys/firmware/efi/efivars/ -writable 2>/dev/null | head -5"
                    )
                    if writable.success and writable.output.strip():
                        self.add_finding(
                            title="Writable EFI variables detected",
                            description="EFI variables can be modified — potential for firmware manipulation",
                            severity=Severity.HIGH,
                            evidence=writable.output.strip()[:500],
                            remediation="Mount efivars read-only where possible; restrict access via permissions",
                        )
            except ValueError:
                pass

    def _check_fwupd(self, session: Session) -> None:
        fwupd = session.execute("systemctl is-active fwupd 2>/dev/null")
        if fwupd.success and fwupd.output.strip() == "active":
            self.add_finding(
                title="fwupd firmware update service is active",
                description="fwupd can apply firmware updates — monitor for unauthorized updates",
                severity=Severity.INFO,
                evidence="fwupd is active",
                remediation="Restrict fwupd access via polkit; monitor firmware update events",
            )

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Enable UEFI Secure Boot to verify firmware and bootloader integrity",
            "Restrict access to firmware tools (flashrom, efibootmgr)",
            "Mount EFI variables read-only in production environments",
            "Monitor firmware update events via fwupd and auditd",
            "Use TPM 2.0 measured boot for firmware attestation",
        ]

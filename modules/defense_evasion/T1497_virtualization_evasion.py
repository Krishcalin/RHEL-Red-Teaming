"""T1497 — Virtualization/Sandbox Evasion.

Checks for VM detection indicators, user activity analysis, time-based
evasion mechanisms, and hypervisor detection on RHEL systems.
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class VirtualizationEvasionCheck(BaseModule):
    TECHNIQUE_ID = "T1497"
    TECHNIQUE_NAME = "Virtualization/Sandbox Evasion"
    TACTIC = Tactic.DEFENSE_EVASION
    SEVERITY = Severity.LOW
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        self._check_systemd_detect_virt(session)
        self._check_dmi_vm_indicators(session)
        self._check_vm_kernel_modules(session)
        self._check_user_activity(session)
        self._check_ntp_sync(session)
        self._check_cpu_hypervisor(session)

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    # -- T1497.001 systemd-detect-virt ----------------------------------------

    def _check_systemd_detect_virt(self, session: Session) -> None:
        result = session.execute("systemd-detect-virt 2>/dev/null")
        if result.success and result.output.strip():
            virt_type = result.output.strip()
            if virt_type != "none":
                self.add_finding(
                    title=f"Virtualization detected: {virt_type}",
                    description=(
                        "systemd-detect-virt identifies this system as virtualized; "
                        "malware may use this to detect sandboxes and alter behavior"
                    ),
                    severity=Severity.LOW,
                    evidence=f"systemd-detect-virt: {virt_type}",
                    remediation="Harden VM to reduce detection indicators if used as a sandbox for malware analysis",
                )

    # -- T1497.001 DMI/SMBIOS data -------------------------------------------

    def _check_dmi_vm_indicators(self, session: Session) -> None:
        result = session.execute(
            "cat /sys/class/dmi/id/sys_vendor /sys/class/dmi/id/product_name "
            "/sys/class/dmi/id/board_vendor 2>/dev/null"
        )
        if result.success and result.output.strip():
            output = result.output.strip().lower()
            vm_indicators = [
                "vmware", "virtualbox", "qemu", "kvm", "xen",
                "microsoft corporation", "parallels", "bochs", "innotek",
            ]
            found = [ind for ind in vm_indicators if ind in output]
            if found:
                self.add_finding(
                    title=f"VM indicators in DMI/SMBIOS data ({', '.join(found)})",
                    description="DMI data reveals virtualization platform; detectable by evasion-aware malware",
                    severity=Severity.LOW,
                    evidence=result.output.strip()[:500],
                    remediation="Customize DMI/SMBIOS data in hypervisor settings to reduce VM fingerprinting",
                )

    # -- T1497.001 VM-specific kernel modules ---------------------------------

    def _check_vm_kernel_modules(self, session: Session) -> None:
        vm_modules = [
            "vmw_balloon", "vmw_vmci", "vmw_pvscsi", "vmxnet3",
            "virtio", "virtio_pci", "virtio_blk", "virtio_net",
            "hv_vmbus", "hv_storvsc", "hv_netvsc", "hyperv_keyboard",
            "xen_blkfront", "xen_netfront",
            "vboxguest", "vboxsf", "vboxvideo",
        ]
        result = session.execute("lsmod 2>/dev/null | awk '{print $1}'")
        if result.success and result.output.strip():
            loaded = result.output.strip().splitlines()
            found = [mod for mod in vm_modules if mod in loaded]
            if found:
                self.add_finding(
                    title=f"VM-specific kernel modules loaded ({len(found)} modules)",
                    description="Loaded kernel modules reveal the virtualization platform to evasion-aware malware",
                    severity=Severity.LOW,
                    evidence=", ".join(found),
                    remediation="Blacklist unnecessary VM guest modules if not required for system operation",
                )

    # -- T1497.002 User activity indicators -----------------------------------

    def _check_user_activity(self, session: Session) -> None:
        # Check for minimal user activity (sandbox indicator)
        empty_history = session.execute(
            "for h in /home/*/.bash_history; do "
            "[ -f \"$h\" ] && [ $(wc -l < \"$h\" 2>/dev/null) -lt 10 ] && echo \"sparse: $h\"; "
            "done 2>/dev/null"
        )
        no_logins = session.execute("last -n 5 2>/dev/null | grep -v 'wtmp' | grep -v '^$'")

        indicators = []
        if empty_history.success and empty_history.output.strip():
            indicators.append(f"Sparse bash histories: {empty_history.output.strip()}")
        if no_logins.success and not no_logins.output.strip():
            indicators.append("No recent login history found")

        if len(indicators) >= 2:
            self.add_finding(
                title="Low user activity may indicate sandbox environment",
                description="Minimal user activity (sparse history, no logins) is a common sandbox indicator",
                severity=Severity.LOW,
                evidence="\n".join(indicators),
                remediation="Populate user activity artifacts if system is used for malware analysis",
            )

    # -- T1497.003 NTP time sync ---------------------------------------------

    def _check_ntp_sync(self, session: Session) -> None:
        result = session.execute("timedatectl show 2>/dev/null | grep NTPSynchronized")
        if result.success and result.output.strip():
            if "NTPSynchronized=no" in result.output:
                self.add_finding(
                    title="NTP synchronization is disabled",
                    description=(
                        "Time not synchronized via NTP; malware may detect time drift "
                        "as a sandbox indicator or use timing attacks"
                    ),
                    severity=Severity.LOW,
                    evidence=result.output.strip(),
                    remediation="Enable NTP synchronization: timedatectl set-ntp true; configure chronyd",
                )

    # -- CPU hypervisor flag --------------------------------------------------

    def _check_cpu_hypervisor(self, session: Session) -> None:
        result = session.execute("grep -c 'hypervisor' /proc/cpuinfo 2>/dev/null")
        if result.success and result.output.strip():
            try:
                count = int(result.output.strip())
                if count > 0:
                    vendor = session.execute(
                        "grep 'Hypervisor vendor' /proc/cpuinfo 2>/dev/null | head -1"
                    )
                    evidence = f"hypervisor flag present in {count} CPU(s)"
                    if vendor.success and vendor.output.strip():
                        evidence += f"\n{vendor.output.strip()}"
                    self.add_finding(
                        title="CPU hypervisor flag detected",
                        description="The CPU advertises a hypervisor presence; trivially detectable by evasion-aware malware",
                        severity=Severity.LOW,
                        evidence=evidence,
                        remediation="Use CPU passthrough or nested virtualization hiding if operating a malware analysis sandbox",
                    )
            except ValueError:
                pass

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Customize DMI/SMBIOS vendor strings in hypervisor configuration to reduce VM fingerprinting",
            "Blacklist unnecessary VM guest kernel modules to reduce detection surface",
            "Ensure NTP synchronization is active via chronyd to prevent time-based evasion",
            "Populate realistic user activity artifacts on malware analysis sandboxes",
            "Use CPU host-passthrough mode to hide hypervisor flag from guest OS",
        ]

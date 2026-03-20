"""T1653 — Power Settings.

Checks for persistence via power management configuration abuse.
Attackers may modify power settings to prevent system sleep/shutdown,
ensuring persistent access, or abuse wake-on-LAN for remote reactivation.
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class PowerSettingsCheck(BaseModule):
    TECHNIQUE_ID = "T1653"
    TECHNIQUE_NAME = "Power Settings"
    TACTIC = Tactic.PERSISTENCE
    SEVERITY = Severity.LOW
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        # Check if suspend/hibernate is disabled via systemd sleep targets
        sleep_targets = ["sleep.target", "suspend.target", "hibernate.target", "hybrid-sleep.target"]
        for target in sleep_targets:
            result = session.execute(f"systemctl is-enabled {target} 2>/dev/null")
            if result.success and "masked" in result.output.lower():
                self.add_finding(
                    title=f"Systemd {target} is masked",
                    description=(
                        f"The {target} is masked, preventing the system from entering "
                        "that power state. While this may be intentional on servers, "
                        "it could indicate an attacker ensuring persistent uptime."
                    ),
                    severity=Severity.LOW,
                    evidence=f"{target}: {result.output.strip()}",
                    remediation=f"Review whether masking {target} is operationally required; unmask with: systemctl unmask {target}",
                )

        # Check logind.conf for power key and lid switch handling
        logind_conf = session.execute(
            "grep -vE '^#|^$' /etc/systemd/logind.conf 2>/dev/null"
        )
        if logind_conf.success and logind_conf.output.strip():
            suspicious_keys = ["HandleLidSwitch", "HandlePowerKey", "HandleSuspendKey",
                               "HandleHibernateKey", "IdleAction", "IdleActionSec"]
            found_settings = []
            for line in logind_conf.output.strip().splitlines():
                for key in suspicious_keys:
                    if key in line and "=" in line:
                        found_settings.append(line.strip())
            if found_settings:
                self.add_finding(
                    title="Custom power handling in logind.conf",
                    description=(
                        "Non-default power handling settings in logind.conf may indicate "
                        "an attacker preventing idle suspension or shutdown to maintain access."
                    ),
                    severity=Severity.LOW,
                    evidence="\n".join(found_settings),
                    remediation="Review logind.conf settings; ensure IdleAction and handle settings align with security policy",
                )

        # Also check logind.conf.d drop-ins
        logind_dropins = session.execute(
            "find /etc/systemd/logind.conf.d/ /usr/lib/systemd/logind.conf.d/ "
            "-name '*.conf' 2>/dev/null | head -10"
        )
        if logind_dropins.success and logind_dropins.output.strip():
            dropin_content = session.execute(
                "grep -hE '(HandleLidSwitch|HandlePowerKey|IdleAction|HandleSuspendKey)' "
                "/etc/systemd/logind.conf.d/*.conf /usr/lib/systemd/logind.conf.d/*.conf 2>/dev/null | head -10"
            )
            if dropin_content.success and dropin_content.output.strip():
                self.add_finding(
                    title="Power handling overrides in logind.conf.d drop-ins",
                    description="Drop-in configuration files override default power handling behavior",
                    severity=Severity.LOW,
                    evidence=dropin_content.output.strip(),
                    remediation="Audit drop-in files in /etc/systemd/logind.conf.d/ and remove unauthorized overrides",
                )

        # Check if screen lock is enforced on idle (GNOME settings if desktop installed)
        gnome_check = session.execute("rpm -q gnome-shell 2>/dev/null")
        if gnome_check.success and "not installed" not in gnome_check.output:
            # Check dconf lock-delay and lock-enabled
            lock_settings = session.execute(
                "dconf read /org/gnome/desktop/screensaver/lock-enabled 2>/dev/null; "
                "dconf read /org/gnome/desktop/screensaver/lock-delay 2>/dev/null; "
                "dconf read /org/gnome/desktop/session/idle-delay 2>/dev/null"
            )
            if lock_settings.success:
                if "false" in lock_settings.output.lower():
                    self.add_finding(
                        title="GNOME screen lock is disabled",
                        description=(
                            "Screen lock on idle is disabled, allowing unattended sessions "
                            "to remain accessible indefinitely."
                        ),
                        severity=Severity.MEDIUM,
                        evidence=lock_settings.output.strip(),
                        remediation="Enable screen lock: gsettings set org.gnome.desktop.screensaver lock-enabled true",
                    )

            # Check if idle-delay is set to 0 (never idle)
            idle_delay = session.execute(
                "gsettings get org.gnome.desktop.session idle-delay 2>/dev/null"
            )
            if idle_delay.success and "uint32 0" in idle_delay.output:
                self.add_finding(
                    title="GNOME idle delay set to never",
                    description="Session will never go idle, preventing automatic screen lock",
                    severity=Severity.MEDIUM,
                    evidence=idle_delay.output.strip(),
                    remediation="Set idle delay: gsettings set org.gnome.desktop.session idle-delay 300",
                )

        # Check if wake-on-LAN is enabled on network interfaces
        interfaces = session.execute(
            "ls /sys/class/net/ 2>/dev/null | grep -v lo"
        )
        if interfaces.success and interfaces.output.strip():
            for iface in interfaces.output.strip().splitlines():
                iface = iface.strip()
                if not iface:
                    continue
                wol_check = session.execute(f"ethtool {iface} 2>/dev/null | grep -i 'wake-on'")
                if wol_check.success and wol_check.output.strip():
                    # 'd' means disabled, anything else (g, u, m, b, a, p, s) means enabled
                    for line in wol_check.output.strip().splitlines():
                        if "Wake-on:" in line and "d" not in line.split(":")[-1]:
                            self.add_finding(
                                title=f"Wake-on-LAN enabled on {iface}",
                                description=(
                                    f"Wake-on-LAN is enabled on interface {iface}. An attacker "
                                    "could remotely power on the system for persistent access."
                                ),
                                severity=Severity.LOW,
                                evidence=line.strip(),
                                remediation=f"Disable WoL: ethtool -s {iface} wol d; persist via NetworkManager or /etc/sysconfig/network-scripts/",
                            )

        # Check UPS/ACPI settings that could be abused
        acpi_events = session.execute(
            "find /etc/acpi/ -type f -name '*.sh' 2>/dev/null | head -10"
        )
        if acpi_events.success and acpi_events.output.strip():
            # Check content of ACPI event scripts for suspicious commands
            suspicious_acpi = session.execute(
                "grep -rlE '(curl|wget|nc|ncat|bash -i|python|perl|ruby)' /etc/acpi/ 2>/dev/null | head -5"
            )
            if suspicious_acpi.success and suspicious_acpi.output.strip():
                self.add_finding(
                    title="ACPI event scripts contain suspicious commands",
                    description="ACPI event handler scripts contain network or scripting commands that could indicate persistence",
                    severity=Severity.HIGH,
                    evidence=suspicious_acpi.output.strip(),
                    remediation="Audit ACPI scripts in /etc/acpi/; remove unauthorized commands and restrict file permissions",
                )

        # Check for UPS daemon (apcupsd/nut) custom scripts
        ups_scripts = session.execute(
            "find /etc/apcupsd/ /etc/ups/ /etc/nut/ -type f -name '*.sh' -o -name '*.conf' 2>/dev/null | head -10"
        )
        if ups_scripts.success and ups_scripts.output.strip():
            self.add_finding(
                title="UPS management scripts detected",
                description=(
                    "UPS daemon configuration or scripts found. These can be abused "
                    "to execute commands on power events for persistence."
                ),
                severity=Severity.LOW,
                evidence=ups_scripts.output.strip(),
                remediation="Audit UPS scripts for unauthorized commands; restrict permissions to root:root 700",
            )

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Enforce screen lock timeouts via GNOME dconf locks or polkit policies on all interactive sessions",
            "Disable Wake-on-LAN on all interfaces unless operationally required: ethtool -s <iface> wol d",
            "Audit and restrict ACPI event scripts to root-only (chmod 700) and monitor with auditd",
            "Use logind.conf to set IdleAction=lock and appropriate HandlePowerKey/HandleLidSwitch policies",
            "Monitor changes to /etc/systemd/logind.conf and /etc/acpi/ with AIDE or auditd file watches",
        ]

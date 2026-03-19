"""T1111 — Multi-Factor Authentication Interception.

Checks for MFA token interception feasibility.
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class MFAInterceptionCheck(BaseModule):
    TECHNIQUE_ID = "T1111"
    TECHNIQUE_NAME = "Multi-Factor Authentication Interception"
    TACTIC = Tactic.CREDENTIAL_ACCESS
    SEVERITY = Severity.MEDIUM
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        # Check for TOTP seed files (Google Authenticator)
        totp_seeds = session.execute(
            "find /home /root -name '.google_authenticator' -readable 2>/dev/null | head -10"
        )
        if totp_seeds.success and totp_seeds.output.strip():
            self.add_finding(
                title=f"TOTP seed files accessible: {len(totp_seeds.output.strip().splitlines())}",
                description="Google Authenticator seed files are readable — TOTP cloning possible",
                severity=Severity.CRITICAL,
                evidence=totp_seeds.output.strip(),
                remediation="Set .google_authenticator permissions to 400; restrict home dir access",
            )

        # Check for YubiKey/OATH configurations
        oath_tokens = session.execute("find /etc/security -name 'users.oath' -readable 2>/dev/null")
        if oath_tokens.success and oath_tokens.output.strip():
            self.add_finding(
                title="OATH token file accessible",
                description="OATH token configuration is readable — token cloning possible",
                severity=Severity.HIGH,
                evidence=oath_tokens.output.strip(),
                remediation="Restrict /etc/security/users.oath to root:root 600",
            )

        # Check USB device access (hardware token interception)
        usb_hid = session.execute("ls /dev/hidraw* 2>/dev/null")
        if usb_hid.success and usb_hid.output.strip():
            readable = session.execute("test -r /dev/hidraw0 && echo readable 2>/dev/null")
            if readable.success and readable.output.strip() == "readable":
                self.add_finding(
                    title="HID raw devices accessible",
                    description="USB HID devices (security keys) are directly accessible",
                    severity=Severity.MEDIUM,
                    evidence=usb_hid.output.strip(),
                    remediation="Restrict /dev/hidraw* access via udev rules",
                )

        # Check for MFA relay/phishing tools
        relay_tools = ["evilginx", "modlishka", "muraena"]
        for tool in relay_tools:
            check = session.execute(f"which {tool} 2>/dev/null")
            if check.success and check.output.strip():
                self.add_finding(
                    title=f"MFA phishing tool found: {tool}",
                    description="MFA relay/phishing tool is installed",
                    severity=Severity.CRITICAL,
                    evidence=check.output.strip(),
                    remediation=f"Remove {tool} from this system",
                )

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Restrict TOTP seed file permissions to 400",
            "Use FIDO2/WebAuthn hardware keys (phishing-resistant)",
            "Restrict /dev/hidraw access via udev rules",
            "Remove MFA relay tools from all systems",
            "Use short TOTP windows and rate limiting",
        ]

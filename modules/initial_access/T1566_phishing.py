"""T1566 — Phishing.

Checks mail server configuration and attachment filtering on RHEL systems.
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class PhishingCheck(BaseModule):
    TECHNIQUE_ID = "T1566"
    TECHNIQUE_NAME = "Phishing"
    TACTIC = Tactic.INITIAL_ACCESS
    SEVERITY = Severity.HIGH
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        self._check_mail_filtering(session)
        self._check_spf_dkim_dmarc(session)
        self._check_antivirus_milter(session)

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def _check_mail_filtering(self, session: Session) -> None:
        postfix = session.execute("postconf content_filter 2>/dev/null")
        if postfix.success and postfix.output.strip():
            if "=" in postfix.output and not postfix.output.split("=", 1)[1].strip():
                self.add_finding(
                    title="Postfix content_filter not configured",
                    description="No content filtering on incoming mail — phishing attachments pass through",
                    severity=Severity.HIGH,
                    evidence=postfix.output.strip(),
                    remediation="Configure content_filter with amavis or rspamd",
                )

    def _check_spf_dkim_dmarc(self, session: Session) -> None:
        for tool, desc in [("opendkim", "DKIM signing"), ("opendmarc", "DMARC enforcement")]:
            result = session.execute(f"systemctl is-active {tool} 2>/dev/null")
            if result.success and result.output.strip() != "active":
                mta = session.execute("systemctl is-active postfix 2>/dev/null || systemctl is-active sendmail 2>/dev/null")
                if mta.success and "active" in mta.output:
                    self.add_finding(
                        title=f"{tool} not active",
                        description=f"{desc} is not running — spoofed emails may be accepted",
                        severity=Severity.MEDIUM,
                        evidence=f"{tool}: {result.output.strip() if result.success else 'not installed'}",
                        remediation=f"Install and configure {tool} for email authentication",
                    )

    def _check_antivirus_milter(self, session: Session) -> None:
        result = session.execute("systemctl is-active clamav-milter 2>/dev/null || systemctl is-active clamd 2>/dev/null")
        mta = session.execute("systemctl is-active postfix 2>/dev/null || systemctl is-active sendmail 2>/dev/null")
        if mta.success and "active" in mta.output:
            if not result.success or "active" not in result.output:
                self.add_finding(
                    title="No mail antivirus scanning",
                    description="ClamAV milter not active — malicious attachments are not scanned",
                    severity=Severity.HIGH,
                    evidence="clamav-milter/clamd not active",
                    remediation="Install and configure ClamAV with milter integration",
                )

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Configure mail content filtering (amavis/rspamd)",
            "Deploy SPF, DKIM, and DMARC for email authentication",
            "Enable ClamAV milter for attachment scanning",
            "Train users to identify phishing attempts",
        ]

"""T1667 — Email Bombing.

Checks for open mail relays, mail rate limiting, and email abuse
prevention controls on RHEL systems.
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class EmailBombingCheck(BaseModule):
    TECHNIQUE_ID = "T1667"
    TECHNIQUE_NAME = "Email Bombing"
    TACTIC = Tactic.IMPACT
    SEVERITY = Severity.HIGH
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        self._check_mail_services(session)
        self._check_open_relay(session)
        self._check_rate_limiting(session)
        self._check_mail_queue(session)

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def _check_mail_services(self, session: Session) -> None:
        services = {"postfix": "Postfix MTA", "sendmail": "Sendmail MTA",
                     "exim": "Exim MTA"}
        for svc, desc in services.items():
            result = session.execute(f"systemctl is-active {svc} 2>/dev/null")
            if result.success and result.output.strip() == "active":
                # Check if listening on external interfaces
                smtp_listen = session.execute("ss -tuln 2>/dev/null | grep ':25 '")
                if smtp_listen.success and "0.0.0.0" in smtp_listen.output:
                    self.add_finding(
                        title=f"{desc} listening on all interfaces",
                        description=f"{desc} accepts SMTP connections on 0.0.0.0:25 — potential relay abuse",
                        severity=Severity.HIGH,
                        evidence=smtp_listen.output.strip()[:300],
                        remediation=f"Bind {svc} to localhost unless external delivery is required: inet_interfaces = loopback-only",
                    )

    def _check_open_relay(self, session: Session) -> None:
        # Postfix relay check
        postfix = session.execute("postconf inet_interfaces mynetworks 2>/dev/null")
        if postfix.success and postfix.output.strip():
            if "all" in postfix.output.lower():
                networks = ""
                for line in postfix.output.strip().splitlines():
                    if "mynetworks" in line:
                        networks = line
                self.add_finding(
                    title="Postfix inet_interfaces = all",
                    description="Postfix listens on all interfaces — verify mynetworks restricts relaying",
                    severity=Severity.MEDIUM,
                    evidence=postfix.output.strip()[:500],
                    remediation="Set inet_interfaces = loopback-only or restrict mynetworks",
                )

        # Sendmail relay check
        sendmail_cf = session.execute("grep -i 'relay' /etc/mail/sendmail.cf 2>/dev/null | head -5")
        if sendmail_cf.success and sendmail_cf.output.strip():
            if "promiscuous_relay" in sendmail_cf.output.lower():
                self.add_finding(
                    title="Sendmail promiscuous relay detected",
                    description="Sendmail is configured to relay mail from any source",
                    severity=Severity.CRITICAL,
                    evidence=sendmail_cf.output.strip()[:300],
                    remediation="Remove promiscuous relay feature from sendmail.mc and rebuild",
                )

    def _check_rate_limiting(self, session: Session) -> None:
        # Postfix rate limits
        rate = session.execute(
            "postconf smtpd_client_message_rate_limit smtpd_client_connection_rate_limit 2>/dev/null"
        )
        if rate.success and rate.output.strip():
            for line in rate.output.strip().splitlines():
                if "= 0" in line:
                    param = line.split("=")[0].strip()
                    self.add_finding(
                        title=f"No mail rate limit: {param}",
                        description=f"Postfix {param} is 0 (unlimited) — email bombing is unrestricted",
                        severity=Severity.MEDIUM,
                        evidence=line.strip(),
                        remediation=f"Set {param} = 50 or appropriate value in main.cf",
                    )

    def _check_mail_queue(self, session: Session) -> None:
        result = session.execute("mailq 2>/dev/null | tail -1")
        if result.success and result.output.strip():
            output = result.output.strip()
            if "empty" not in output.lower():
                # Try to parse queue size
                try:
                    parts = output.split()
                    for p in parts:
                        if p.isdigit() and int(p) > 1000:
                            self.add_finding(
                                title=f"Large mail queue detected ({p} messages)",
                                description="Unusually large mail queue may indicate ongoing email bombing or spam relay",
                                severity=Severity.HIGH,
                                evidence=output[:300],
                                remediation="Investigate queued messages; flush legitimate mail and block abusers",
                            )
                            break
                except (ValueError, IndexError):
                    pass

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Bind mail services to localhost unless external delivery is required",
            "Configure mynetworks/access restrictions to prevent open relay",
            "Set SMTP rate limits (smtpd_client_message_rate_limit)",
            "Deploy SPF, DKIM, and DMARC records for domain protection",
            "Monitor mail queue size for anomalies indicating abuse",
        ]

"""T1657 — Financial Theft.

Checks for access to financial systems, payment processing configurations,
database connections, and sensitive financial data on RHEL systems.
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class FinancialTheftCheck(BaseModule):
    TECHNIQUE_ID = "T1657"
    TECHNIQUE_NAME = "Financial Theft"
    TACTIC = Tactic.IMPACT
    SEVERITY = Severity.CRITICAL
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        self._check_financial_configs(session)
        self._check_database_access(session)
        self._check_payment_ports(session)
        self._check_sensitive_envvars(session)

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def _check_financial_configs(self, session: Session) -> None:
        patterns = ["*payment*", "*billing*", "*invoice*", "*transaction*",
                    "*merchant*", "*stripe*", "*paypal*"]
        for pattern in patterns:
            result = session.execute(
                f"find /etc /opt /var/www /srv -iname '{pattern}.conf' -o -iname '{pattern}.yaml' "
                f"-o -iname '{pattern}.yml' -o -iname '{pattern}.json' 2>/dev/null | head -5"
            )
            if result.success and result.output.strip():
                self.add_finding(
                    title=f"Financial configuration files found: {pattern}",
                    description="Configuration files related to financial/payment systems are accessible",
                    severity=Severity.HIGH,
                    evidence=result.output.strip()[:500],
                    remediation="Restrict access to financial configs; encrypt sensitive values",
                )

    def _check_database_access(self, session: Session) -> None:
        db_files = [".pgpass", ".my.cnf", ".dbshell"]
        for f in db_files:
            result = session.execute(f"find /root /home -name '{f}' -readable 2>/dev/null")
            if result.success and result.output.strip():
                self.add_finding(
                    title=f"Database credential file readable: {f}",
                    description=f"Found readable {f} — may contain credentials to financial databases",
                    severity=Severity.HIGH,
                    evidence=result.output.strip()[:300],
                    remediation=f"Set strict permissions: chmod 600 {f}; restrict to db admin users only",
                )

    def _check_payment_ports(self, session: Session) -> None:
        financial_ports = {
            "3306": "MySQL (potential financial DB)",
            "5432": "PostgreSQL (potential financial DB)",
            "8443": "HTTPS alt (payment gateway)",
        }
        listening = session.execute("ss -tuln 2>/dev/null")
        if listening.success:
            for port, desc in financial_ports.items():
                if f":{port} " in listening.output or f":{port}\n" in listening.output:
                    bind_check = session.execute(
                        f"ss -tuln 2>/dev/null | grep ':{port} '"
                    )
                    if bind_check.success and "0.0.0.0" in bind_check.output:
                        self.add_finding(
                            title=f"Financial service on all interfaces: port {port}",
                            description=f"{desc} is listening on 0.0.0.0:{port} — exposed to all networks",
                            severity=Severity.HIGH,
                            evidence=bind_check.output.strip()[:300],
                            remediation=f"Bind {desc.split('(')[0].strip()} to localhost or internal interface only",
                        )

    def _check_sensitive_envvars(self, session: Session) -> None:
        keywords = ["STRIPE_KEY", "PAYPAL", "MERCHANT_ID", "PAYMENT_SECRET",
                     "BILLING_API", "SQUARE_TOKEN"]
        result = session.execute("env 2>/dev/null")
        if result.success:
            for kw in keywords:
                if kw in result.output:
                    self.add_finding(
                        title=f"Financial secret in environment: {kw}",
                        description=f"Environment variable {kw} is set — secrets in env are visible to child processes",
                        severity=Severity.CRITICAL,
                        evidence=f"{kw}=***REDACTED***",
                        remediation="Move secrets to a vault (HashiCorp Vault, AWS Secrets Manager)",
                    )

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Store financial secrets in a dedicated vault, not env vars or config files",
            "Restrict database credential files to service accounts only",
            "Bind financial databases to internal interfaces, not 0.0.0.0",
            "Encrypt financial configuration files at rest",
            "Implement network segmentation for payment processing systems",
        ]

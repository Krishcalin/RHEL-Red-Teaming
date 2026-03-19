"""T1558 — Steal or Forge Kerberos Tickets.

Checks for accessible Kerberos ticket caches and keytab files.
Sub-technique: T1558.005 (Ccache Files).
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class KerberosTicketsCheck(BaseModule):
    TECHNIQUE_ID = "T1558"
    TECHNIQUE_NAME = "Steal or Forge Kerberos Tickets"
    TACTIC = Tactic.CREDENTIAL_ACCESS
    SEVERITY = Severity.HIGH
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        # T1558.005 — Ccache Files
        ccache_files = session.execute("find /tmp -name 'krb5cc_*' -readable 2>/dev/null | head -15")
        if ccache_files.success and ccache_files.output.strip():
            files = ccache_files.output.strip().splitlines()
            self.add_finding(
                title=f"Kerberos ccache files accessible: {len(files)}",
                description="Kerberos ticket caches in /tmp are readable — ticket theft possible",
                severity=Severity.HIGH,
                evidence="\n".join(files),
                remediation="Use KCM or KEYRING ccache type instead of FILE",
            )

        # Check default ccache type
        krb5_conf = session.execute("grep -i 'default_ccache_name' /etc/krb5.conf 2>/dev/null")
        if krb5_conf.success and krb5_conf.output.strip():
            if "FILE:" in krb5_conf.output.upper() or "file:" in krb5_conf.output:
                self.add_finding(
                    title="Kerberos uses FILE ccache type",
                    description="FILE-based ccache stores tickets in world-accessible /tmp",
                    severity=Severity.MEDIUM,
                    evidence=krb5_conf.output.strip(),
                    remediation="Set default_ccache_name = KCM: in /etc/krb5.conf",
                )
        else:
            # Check KRB5CCNAME environment
            env_cc = session.execute("echo $KRB5CCNAME")
            if env_cc.success and env_cc.output.strip() and "FILE:" in env_cc.output.upper():
                self.add_finding(
                    title="KRB5CCNAME set to FILE type",
                    description="Environment overrides ccache to FILE type",
                    severity=Severity.MEDIUM,
                    evidence=f"KRB5CCNAME={env_cc.output.strip()}",
                    remediation="Use KCM: or KEYRING: ccache type",
                )

        # Check keytab files
        keytab_files = ["/etc/krb5.keytab", "/etc/security/keytab"]
        for kt in keytab_files:
            check = session.execute(f"test -r {kt} && echo readable")
            if check.success and check.output.strip() == "readable":
                perms = session.execute(f"stat -c '%a %U:%G' {kt} 2>/dev/null")
                self.add_finding(
                    title=f"Keytab file readable: {kt}",
                    description="Kerberos keytab is accessible — service impersonation possible",
                    severity=Severity.CRITICAL,
                    evidence=f"{kt}: {perms.output.strip() if perms.success else 'readable'}",
                    remediation=f"Restrict keytab: chmod 600 {kt}; chown root:root {kt}",
                )

        # Check for klist availability and current tickets
        klist = session.execute("klist 2>/dev/null")
        if klist.success and klist.output.strip() and "No credentials cache" not in klist.output:
            self.add_finding(
                title="Active Kerberos tickets found",
                description="Current user has valid Kerberos tickets",
                severity=Severity.INFO,
                evidence=klist.output.strip()[:500],
            )

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Use KCM or KEYRING ccache type (not FILE)",
            "Restrict keytab files to 600 root:root",
            "Monitor ccache file access with auditd",
            "Use short ticket lifetimes in KDC policy",
        ]

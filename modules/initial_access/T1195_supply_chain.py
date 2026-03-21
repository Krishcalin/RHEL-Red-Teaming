"""T1195 — Supply Chain Compromise.

Checks package repo integrity and GPG verification on RHEL systems.
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class SupplyChainCheck(BaseModule):
    TECHNIQUE_ID = "T1195"
    TECHNIQUE_NAME = "Supply Chain Compromise"
    TACTIC = Tactic.INITIAL_ACCESS
    SEVERITY = Severity.CRITICAL
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        self._check_gpg_verification(session)
        self._check_third_party_repos(session)
        self._check_unsigned_packages(session)

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def _check_gpg_verification(self, session: Session) -> None:
        result = session.execute("grep -r 'gpgcheck' /etc/yum.repos.d/ 2>/dev/null")
        if result.success and result.output.strip():
            disabled = [l for l in result.output.strip().splitlines() if "gpgcheck=0" in l]
            if disabled:
                self.add_finding(
                    title=f"GPG check disabled in {len(disabled)} repo(s)",
                    description="Repos with gpgcheck=0 accept unsigned packages — supply chain risk",
                    severity=Severity.CRITICAL,
                    evidence="\n".join(disabled[:5]),
                    remediation="Set gpgcheck=1 in all repo files",
                )

        dnf_conf = session.execute("grep 'gpgcheck' /etc/dnf/dnf.conf 2>/dev/null")
        if dnf_conf.success and "gpgcheck=0" in dnf_conf.output:
            self.add_finding(
                title="GPG check globally disabled in dnf.conf",
                description="Global gpgcheck=0 disables signature verification for all repos",
                severity=Severity.CRITICAL,
                evidence=dnf_conf.output.strip(),
                remediation="Set gpgcheck=1 in /etc/dnf/dnf.conf",
            )

    def _check_third_party_repos(self, session: Session) -> None:
        result = session.execute("dnf repolist --enabled 2>/dev/null")
        if result.success and result.output.strip():
            lines = result.output.strip().splitlines()
            non_redhat = [l for l in lines if l.strip() and not any(
                kw in l.lower() for kw in ["redhat", "rhel", "repo id", "---"]
            )]
            if non_redhat:
                self.add_finding(
                    title=f"{len(non_redhat)} third-party repos enabled",
                    description="Third-party repos increase supply chain attack surface",
                    severity=Severity.MEDIUM,
                    evidence="\n".join(non_redhat[:10]),
                    remediation="Audit third-party repos; enable repo_gpgcheck=1",
                )

    def _check_unsigned_packages(self, session: Session) -> None:
        result = session.execute("rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE} %{SIGPGP:pgpsig}\\n' 2>/dev/null | grep -i 'not' | head -10")
        if result.success and result.output.strip():
            count = len(result.output.strip().splitlines())
            self.add_finding(
                title=f"{count} unsigned packages installed",
                description="Packages without GPG signatures may have been tampered with",
                severity=Severity.HIGH,
                evidence=result.output.strip()[:500],
                remediation="Investigate unsigned packages; reinstall from trusted repos",
            )

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Enable gpgcheck=1 globally and per-repo",
            "Audit and minimize third-party repositories",
            "Enable repo_gpgcheck=1 for repository metadata verification",
            "Investigate and replace unsigned packages",
        ]

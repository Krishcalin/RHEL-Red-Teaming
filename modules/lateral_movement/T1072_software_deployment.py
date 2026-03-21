"""T1072 — Software Deployment Tools.

Checks for configuration management tools (Ansible, Puppet, Salt, Chef)
that could be leveraged for lateral movement on RHEL systems.
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class SoftwareDeploymentCheck(BaseModule):
    TECHNIQUE_ID = "T1072"
    TECHNIQUE_NAME = "Software Deployment Tools"
    TACTIC = Tactic.LATERAL_MOVEMENT
    SEVERITY = Severity.HIGH
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        self._check_ansible(session)
        self._check_puppet(session)
        self._check_salt(session)
        self._check_chef(session)

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def _check_ansible(self, session: Session) -> None:
        result = session.execute("which ansible 2>/dev/null")
        if result.success and result.output.strip():
            inventory = session.execute("find /etc/ansible /home -name 'hosts' -o -name 'inventory*' 2>/dev/null | head -5")
            if inventory.success and inventory.output.strip():
                readable = session.execute(f"head -5 {inventory.output.strip().splitlines()[0]} 2>/dev/null")
                self.add_finding(
                    title="Ansible installed with readable inventory",
                    description="Ansible inventory files expose target hosts for lateral movement",
                    severity=Severity.HIGH,
                    evidence=inventory.output.strip()[:300],
                    remediation="Restrict Ansible inventory file permissions to automation accounts only",
                )
            else:
                self.add_finding(
                    title="Ansible is installed",
                    description="Ansible can execute commands on remote hosts if credentials are available",
                    severity=Severity.MEDIUM,
                    evidence=result.output.strip(),
                    remediation="Remove Ansible from non-management hosts",
                )

    def _check_puppet(self, session: Session) -> None:
        puppet = session.execute("systemctl is-active puppet 2>/dev/null")
        if puppet.success and puppet.output.strip() == "active":
            certs = session.execute("find /etc/puppetlabs -name '*.pem' -readable 2>/dev/null | head -5")
            if certs.success and certs.output.strip():
                self.add_finding(
                    title="Puppet agent active with readable certificates",
                    description="Puppet certificates could be used to impersonate nodes",
                    severity=Severity.HIGH,
                    evidence=certs.output.strip()[:300],
                    remediation="Restrict Puppet certificate permissions to puppet user only",
                )

    def _check_salt(self, session: Session) -> None:
        salt = session.execute("systemctl is-active salt-minion 2>/dev/null")
        if salt.success and salt.output.strip() == "active":
            master = session.execute("grep -i 'master:' /etc/salt/minion 2>/dev/null")
            self.add_finding(
                title="Salt minion is active",
                description="Salt minion connects to a master — compromising the master enables lateral movement",
                severity=Severity.MEDIUM,
                evidence=master.output.strip()[:300] if master.success else "salt-minion active",
                remediation="Restrict Salt master access; use encrypted pillar data",
            )

    def _check_chef(self, session: Session) -> None:
        chef = session.execute("which chef-client 2>/dev/null")
        if chef.success and chef.output.strip():
            keys = session.execute("find /etc/chef -name '*.pem' -readable 2>/dev/null | head -5")
            if keys.success and keys.output.strip():
                self.add_finding(
                    title="Chef client installed with readable keys",
                    description="Chef client keys could be used to access the Chef server",
                    severity=Severity.HIGH,
                    evidence=keys.output.strip()[:300],
                    remediation="Restrict Chef client key permissions to root only",
                )

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Remove deployment tools (Ansible, Puppet, Salt, Chef) from non-management hosts",
            "Restrict configuration management credentials and certificates",
            "Use separate service accounts for deployment tools",
            "Monitor deployment tool executions with auditd",
            "Segment management networks from application networks",
        ]

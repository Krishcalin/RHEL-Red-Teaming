"""T1072 — Software Deployment Tools.

Checks security posture of configuration management and deployment tools
on RHEL systems. Covers Ansible, Puppet, Chef, Salt, SSH authorized_keys,
package manager security, and deployment-related cron jobs.
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class SoftwareDeploymentCheck(BaseModule):
    TECHNIQUE_ID = "T1072"
    TECHNIQUE_NAME = "Software Deployment Tools"
    TACTIC = Tactic.EXECUTION
    SEVERITY = Severity.MEDIUM
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    DEPLOYMENT_AGENTS = [
        ("puppet", "Puppet agent"),
        ("chef-client", "Chef client"),
        ("salt-minion", "Salt minion"),
    ]

    def check(self, session: Session) -> ModuleResult:
        self._check_ansible(session)
        self._check_deployment_agents(session)
        self._check_ssh_authorized_keys(session)
        self._check_package_manager_gpg(session)
        self._check_deployment_config_permissions(session)
        self._check_cron_deployment_scripts(session)

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def _check_ansible(self, session: Session) -> None:
        """Check if Ansible is installed and its configuration permissions."""
        ansible_bin = session.execute("which ansible 2>/dev/null")
        if ansible_bin.success and ansible_bin.output.strip():
            self.add_finding(
                title="Ansible is installed",
                description=(
                    "Ansible is available on this system. If compromised, it can be used "
                    "to execute commands across managed hosts."
                ),
                severity=Severity.LOW,
                evidence=ansible_bin.output.strip(),
                remediation="Remove Ansible from systems that are not management nodes.",
            )

            # Check Ansible configuration file permissions
            ansible_cfg_paths = [
                "/etc/ansible/ansible.cfg",
                "/etc/ansible/hosts",
            ]
            for cfg_path in ansible_cfg_paths:
                perms = session.execute(f"stat -c '%a %U:%G' {cfg_path} 2>/dev/null")
                if perms.success and perms.output.strip():
                    perm_bits = perms.output.strip().split()[0]
                    if int(perm_bits[-1]) >= 4:  # world-readable
                        self.add_finding(
                            title=f"Ansible config world-readable: {cfg_path}",
                            description=(
                                f"{cfg_path} is world-readable. It may contain inventory "
                                "details, credentials, or sensitive configuration."
                            ),
                            severity=Severity.MEDIUM,
                            evidence=perms.output.strip(),
                            remediation=f"chmod 640 {cfg_path} && chown root:ansible {cfg_path}",
                        )

    def _check_deployment_agents(self, session: Session) -> None:
        """Check if Puppet, Chef, or Salt agents are running."""
        for binary, desc in self.DEPLOYMENT_AGENTS:
            # Check if installed
            which_result = session.execute(f"which {binary} 2>/dev/null")
            if not which_result.success or not which_result.output.strip():
                continue

            # Check if service is running
            service_name = binary.replace("-", "")
            active = session.execute(f"systemctl is-active {service_name} 2>/dev/null")
            if active.success and active.output.strip() == "active":
                self.add_finding(
                    title=f"{desc} service is running",
                    description=(
                        f"{desc} is active on this system. A compromised management server "
                        "could push malicious configurations to this host."
                    ),
                    severity=Severity.MEDIUM,
                    evidence=f"{service_name}: active",
                    remediation=(
                        f"Ensure {desc} communicates over TLS with certificate pinning. "
                        f"Restrict {service_name} service account privileges."
                    ),
                )
            else:
                self.add_finding(
                    title=f"{desc} is installed but not running",
                    description=f"{desc} binary found at {which_result.output.strip()} but service is not active.",
                    severity=Severity.LOW,
                    evidence=which_result.output.strip(),
                    remediation=f"Remove {binary} if the agent is no longer needed.",
                )

    def _check_ssh_authorized_keys(self, session: Session) -> None:
        """Check SSH authorized_keys files for command restrictions."""
        # Find authorized_keys files
        auth_keys = session.execute(
            "find /root/.ssh /home/*/.ssh -name 'authorized_keys' -type f 2>/dev/null"
        )
        if auth_keys.success and auth_keys.output.strip():
            for keyfile in auth_keys.output.strip().splitlines():
                keyfile = keyfile.strip()
                if not keyfile:
                    continue

                # Read file content
                content = session.execute(f"cat '{keyfile}' 2>/dev/null")
                if not content.success or not content.output.strip():
                    continue

                keys = [
                    l for l in content.output.splitlines()
                    if l.strip() and not l.strip().startswith("#")
                ]

                unrestricted = [
                    l[:80] for l in keys
                    if not l.strip().startswith("command=")
                    and not l.strip().startswith("restrict")
                    and not l.strip().startswith("no-pty")
                ]

                if unrestricted:
                    self.add_finding(
                        title=f"SSH keys without command restriction in {keyfile}",
                        description=(
                            f"{len(unrestricted)} SSH key(s) in {keyfile} lack command= "
                            "restrictions, granting full shell access."
                        ),
                        severity=Severity.MEDIUM,
                        evidence="\n".join(unrestricted[:5]),
                        remediation=(
                            "Add command= restrictions to deployment keys: "
                            'command="/usr/local/bin/deploy.sh" ssh-rsa ...'
                        ),
                    )

    def _check_package_manager_gpg(self, session: Session) -> None:
        """Check if yum/dnf repos have GPG checking disabled."""
        # Check for gpgcheck=0 in repo files
        gpg_disabled = session.execute(
            "grep -rl 'gpgcheck=0' /etc/yum.repos.d/ 2>/dev/null"
        )
        if gpg_disabled.success and gpg_disabled.output.strip():
            files = gpg_disabled.output.strip().splitlines()
            self.add_finding(
                title=f"GPG checking disabled in {len(files)} repo file(s)",
                description=(
                    "Package repositories with gpgcheck=0 accept unsigned packages, "
                    "allowing man-in-the-middle or supply-chain attacks."
                ),
                severity=Severity.HIGH,
                evidence="\n".join(files),
                remediation="Set gpgcheck=1 in all repo files under /etc/yum.repos.d/.",
            )

        # Check global dnf/yum config
        global_gpg = session.execute(
            "grep -i 'gpgcheck' /etc/dnf/dnf.conf /etc/yum.conf 2>/dev/null"
        )
        if global_gpg.success and global_gpg.output.strip():
            if "gpgcheck=0" in global_gpg.output:
                self.add_finding(
                    title="GPG checking disabled globally in dnf/yum config",
                    description="The global package manager configuration has gpgcheck=0.",
                    severity=Severity.HIGH,
                    evidence=global_gpg.output[:500],
                    remediation="Set gpgcheck=1 in /etc/dnf/dnf.conf (or /etc/yum.conf).",
                )

    def _check_deployment_config_permissions(self, session: Session) -> None:
        """Check if deployment tool configuration files are world-readable."""
        config_paths = [
            "/etc/puppet",
            "/etc/chef",
            "/etc/salt",
            "/etc/ansible",
        ]
        for cfg_dir in config_paths:
            world_readable = session.execute(
                f"find {cfg_dir} -type f -perm -o=r 2>/dev/null | head -10"
            )
            if world_readable.success and world_readable.output.strip():
                self.add_finding(
                    title=f"World-readable config files in {cfg_dir}",
                    description=(
                        f"Configuration files in {cfg_dir} are world-readable. "
                        "They may contain credentials, API keys, or infrastructure details."
                    ),
                    severity=Severity.MEDIUM,
                    evidence=world_readable.output[:500],
                    remediation=f"chmod -R o-r {cfg_dir} to remove world-read access.",
                )

    def _check_cron_deployment_scripts(self, session: Session) -> None:
        """Check for cron jobs that run deployment or provisioning scripts."""
        deploy_patterns = "deploy|provision|puppet|chef|ansible|salt|pull|update"
        cron_deploy = session.execute(
            f"grep -rhi '{deploy_patterns}' /etc/crontab /etc/cron.d/ /var/spool/cron/ 2>/dev/null "
            "| grep -v '^#'"
        )
        if cron_deploy.success and cron_deploy.output.strip():
            self.add_finding(
                title="Cron-based deployment scripts found",
                description=(
                    "Cron jobs referencing deployment or configuration management tools "
                    "were found. These could be hijacked if their scripts are writable."
                ),
                severity=Severity.MEDIUM,
                evidence=cron_deploy.output[:500],
                remediation=(
                    "Ensure deployment scripts referenced in cron are owned by root, "
                    "not world-writable, and stored in a protected directory."
                ),
            )

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Enable gpgcheck=1 in all yum/dnf repository configurations.",
            "Remove deployment tools (Ansible, Puppet, Chef, Salt) from non-management systems.",
            "Add command= restrictions to SSH authorized_keys used for automated deployments.",
            "Ensure deployment tool configs (/etc/ansible, /etc/puppet, etc.) are not world-readable.",
            "Audit cron-based deployment scripts for writable paths and enforce root ownership.",
        ]

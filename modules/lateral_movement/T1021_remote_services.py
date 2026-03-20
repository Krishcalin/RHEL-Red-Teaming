"""T1021 — Remote Services.

Audits remote service configurations that could enable lateral movement:
- T1021.004 SSH configuration and hardening
- T1021.002 SMB/NFS shares accessible from network
- T1021.006 VNC/XRDP remote desktop services
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class RemoteServicesCheck(BaseModule):
    TECHNIQUE_ID = "T1021"
    TECHNIQUE_NAME = "Remote Services"
    TACTIC = Tactic.LATERAL_MOVEMENT
    SEVERITY = Severity.HIGH
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        self._check_ssh(session)
        self._check_smb_nfs(session)
        self._check_remote_desktop(session)
        self._check_rsh_legacy(session)

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def _check_ssh(self, session: Session) -> None:
        """T1021.004 — SSH configuration hardening."""
        sshd_config = session.execute("cat /etc/ssh/sshd_config 2>/dev/null")
        if not sshd_config.success:
            return

        config = sshd_config.output

        # Root login
        if "PermitRootLogin yes" in config or "PermitRootLogin without-password" in config:
            self.add_finding(
                title="SSH permits root login",
                description="Direct root login via SSH is allowed, enabling lateral movement with root credentials",
                severity=Severity.HIGH,
                evidence="PermitRootLogin is not set to 'no'",
                remediation="Set 'PermitRootLogin no' in /etc/ssh/sshd_config",
            )

        # Password authentication
        if "PasswordAuthentication yes" in config:
            self.add_finding(
                title="SSH password authentication enabled",
                description="Password-based SSH auth allows credential reuse and brute force attacks",
                severity=Severity.MEDIUM,
                evidence="PasswordAuthentication yes",
                remediation="Set 'PasswordAuthentication no' and use key-based auth only",
            )

        # Agent forwarding
        if "AllowAgentForwarding yes" in config:
            self.add_finding(
                title="SSH agent forwarding enabled",
                description="Agent forwarding allows an attacker on a compromised host to reuse SSH keys",
                severity=Severity.MEDIUM,
                evidence="AllowAgentForwarding yes",
                remediation="Set 'AllowAgentForwarding no' unless explicitly needed",
            )

        # X11 forwarding
        if "X11Forwarding yes" in config:
            self.add_finding(
                title="SSH X11 forwarding enabled",
                description="X11 forwarding can be abused for keylogging and screen capture",
                severity=Severity.LOW,
                evidence="X11Forwarding yes",
                remediation="Set 'X11Forwarding no' in sshd_config",
            )

        # Weak ciphers / MACs
        weak_ciphers = ["3des-cbc", "arcfour", "blowfish-cbc", "cast128-cbc"]
        cipher_line = session.execute("grep -i '^Ciphers' /etc/ssh/sshd_config 2>/dev/null")
        if cipher_line.success and cipher_line.output.strip():
            for cipher in weak_ciphers:
                if cipher in cipher_line.output.lower():
                    self.add_finding(
                        title=f"Weak SSH cipher allowed: {cipher}",
                        description="Weak ciphers can be exploited for credential interception",
                        severity=Severity.MEDIUM,
                        evidence=cipher_line.output.strip(),
                        remediation="Remove weak ciphers from sshd_config Ciphers directive",
                    )
                    break

        # Check for authorized_keys with permissive access
        auth_keys = session.execute(
            "find /home -name 'authorized_keys' -perm /077 2>/dev/null | head -10"
        )
        if auth_keys.success and auth_keys.output.strip():
            self.add_finding(
                title="SSH authorized_keys files with permissive access",
                description="Authorized keys files are writable by non-owners, enabling key injection",
                severity=Severity.HIGH,
                evidence=auth_keys.output.strip(),
                remediation="Set authorized_keys to mode 600 owned by the respective user",
            )

    def _check_smb_nfs(self, session: Session) -> None:
        """T1021.002 — SMB/NFS shares."""
        # Samba shares
        smb_conf = session.execute("testparm -s 2>/dev/null | grep -A3 '\\[' | head -40")
        if smb_conf.success and smb_conf.output.strip():
            shares = [
                line.strip()
                for line in smb_conf.output.splitlines()
                if line.strip().startswith("[") and line.strip() not in ("[global]", "[printers]")
            ]
            if shares:
                self.add_finding(
                    title=f"Samba shares configured: {len(shares)}",
                    description="SMB shares can be used for lateral movement and data staging",
                    severity=Severity.MEDIUM,
                    evidence="\n".join(shares[:10]),
                    remediation="Remove unnecessary shares; require SMB signing and encryption",
                )

            # Guest access
            guest_check = session.execute(
                "testparm -s 2>/dev/null | grep -i 'guest ok = yes'"
            )
            if guest_check.success and guest_check.output.strip():
                self.add_finding(
                    title="Samba shares allow guest access",
                    description="Anonymous access to SMB shares enables unauthenticated lateral movement",
                    severity=Severity.HIGH,
                    evidence=guest_check.output.strip(),
                    remediation="Set 'guest ok = no' for all shares",
                )

        # NFS exports
        nfs_exports = session.execute("cat /etc/exports 2>/dev/null")
        if nfs_exports.success and nfs_exports.output.strip():
            exports = [
                line.strip()
                for line in nfs_exports.output.splitlines()
                if line.strip() and not line.strip().startswith("#")
            ]
            if exports:
                self.add_finding(
                    title=f"NFS exports configured: {len(exports)}",
                    description="NFS exports can be mounted by remote hosts for lateral movement",
                    severity=Severity.MEDIUM,
                    evidence="\n".join(exports[:10]),
                )

                # Check for wildcard or no_root_squash
                for export in exports:
                    if "*" in export or "no_root_squash" in export:
                        self.add_finding(
                            title="NFS export with dangerous options",
                            description="Wildcard exports or no_root_squash allow privilege abuse",
                            severity=Severity.HIGH,
                            evidence=export,
                            remediation="Restrict exports to specific hosts; always use root_squash",
                        )

    def _check_remote_desktop(self, session: Session) -> None:
        """T1021.006 — VNC/XRDP remote desktop."""
        for svc in ("vncserver", "xrdp", "xvnc"):
            running = session.execute(f"systemctl is-active {svc} 2>/dev/null")
            if running.success and running.output.strip() == "active":
                self.add_finding(
                    title=f"Remote desktop service running: {svc}",
                    description=f"{svc} provides GUI access and can be leveraged for lateral movement",
                    severity=Severity.MEDIUM,
                    evidence=f"{svc} is active",
                    remediation=f"Disable {svc} if not required: systemctl disable --now {svc}",
                )

        # Check VNC password files
        vnc_passwd = session.execute(
            "find /home -name '.vnc' -type d 2>/dev/null | head -5"
        )
        if vnc_passwd.success and vnc_passwd.output.strip():
            self.add_finding(
                title="VNC configuration directories found",
                description="VNC password files use weak DES-based encryption and are trivially crackable",
                severity=Severity.MEDIUM,
                evidence=vnc_passwd.output.strip(),
                remediation="Remove VNC configurations or migrate to TigerVNC with stronger auth",
            )

    def _check_rsh_legacy(self, session: Session) -> None:
        """Check for legacy remote shell services."""
        for svc in ("rsh", "rlogin", "rexec"):
            result = session.execute(f"systemctl is-active {svc}.socket 2>/dev/null")
            if result.success and result.output.strip() == "active":
                self.add_finding(
                    title=f"Legacy remote service active: {svc}",
                    description=f"{svc} transmits credentials in cleartext — trivial interception",
                    severity=Severity.CRITICAL,
                    evidence=f"{svc}.socket is active",
                    remediation=f"Disable immediately: systemctl disable --now {svc}.socket",
                )

        # Check .rhosts files
        rhosts = session.execute("find /home -name '.rhosts' 2>/dev/null | head -5")
        if rhosts.success and rhosts.output.strip():
            self.add_finding(
                title=".rhosts files found",
                description=".rhosts allows passwordless remote access — severe lateral movement risk",
                severity=Severity.CRITICAL,
                evidence=rhosts.output.strip(),
                remediation="Delete all .rhosts files and disable rsh services",
            )

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Disable root SSH login; use key-based authentication only",
            "Disable SSH agent forwarding and X11 forwarding",
            "Remove unnecessary SMB/NFS shares; enforce signing and encryption",
            "Disable legacy remote shell services (rsh, rlogin, rexec)",
            "Remove VNC/XRDP unless required; use SSH tunneling instead",
            "Set authorized_keys permissions to 600",
            "Use AllowUsers/AllowGroups in sshd_config to restrict access",
        ]

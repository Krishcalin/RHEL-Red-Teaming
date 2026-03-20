"""T1562 — Impair Defenses.

Checks for weakened or disabled security tools, firewalls, audit systems,
command history controls, and protocol downgrade risks on RHEL systems.
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class ImpairDefensesCheck(BaseModule):
    TECHNIQUE_ID = "T1562"
    TECHNIQUE_NAME = "Impair Defenses"
    TACTIC = Tactic.DEFENSE_EVASION
    SEVERITY = Severity.CRITICAL
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        self._check_disable_modify_tools(session)
        self._check_impair_command_history(session)
        self._check_disable_firewall(session)
        self._check_downgrade_attack(session)
        self._check_spoof_security_alerting(session)
        self._check_disable_audit_system(session)

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    # -- T1562.001 Disable / Modify Tools ----------------------------------

    def _check_disable_modify_tools(self, session: Session) -> None:
        # SELinux
        selinux = session.execute("getenforce 2>/dev/null")
        if selinux.success and selinux.output.strip().lower() in ("permissive", "disabled"):
            self.add_finding(
                title="SELinux not enforcing",
                description=f"SELinux is {selinux.output.strip()} — protection is weakened",
                severity=Severity.CRITICAL,
                evidence=selinux.output.strip(),
                remediation="Set SELinux to enforcing: setenforce 1 and SELINUX=enforcing in /etc/selinux/config",
            )

        # auditd
        auditd = session.execute("systemctl is-active auditd 2>/dev/null")
        if auditd.success and auditd.output.strip() != "active":
            self.add_finding(
                title="auditd is not running",
                description="The Linux audit daemon is not active — system auditing is disabled",
                severity=Severity.CRITICAL,
                evidence=auditd.output.strip(),
                remediation="Enable auditd: systemctl enable --now auditd",
            )

        # firewalld / iptables
        fw = session.execute("systemctl is-active firewalld 2>/dev/null")
        ipt = session.execute("iptables -L -n 2>/dev/null | wc -l")
        if fw.success and fw.output.strip() != "active":
            if ipt.success and int(ipt.output.strip() or "0") < 10:
                self.add_finding(
                    title="No active firewall detected",
                    description="Neither firewalld nor iptables rules are actively protecting the host",
                    severity=Severity.HIGH,
                    evidence=f"firewalld: {fw.output.strip()}, iptables rules: {ipt.output.strip()}",
                    remediation="Enable firewalld: systemctl enable --now firewalld",
                )

        # AV / EDR agents
        agents = {
            "ClamAV": "clamd",
            "CrowdStrike Falcon": "falcon-sensor",
            "Carbon Black": "cbagentd",
        }
        for name, proc in agents.items():
            result = session.execute(f"pgrep -x {proc} >/dev/null 2>&1; echo $?")
            if result.success and result.output.strip() == "1":
                self.add_finding(
                    title=f"{name} agent not running",
                    description=f"The {name} process ({proc}) is not detected on this host",
                    severity=Severity.MEDIUM,
                    evidence=f"pgrep -x {proc} returned no match",
                    remediation=f"Verify {name} is installed and running; consult vendor documentation",
                )

    # -- T1562.003 Impair Command History ----------------------------------

    def _check_impair_command_history(self, session: Session) -> None:
        histcontrol = session.execute("echo $HISTCONTROL")
        if histcontrol.success and histcontrol.output.strip():
            val = histcontrol.output.strip()
            if "ignorespace" in val or "ignoreboth" in val:
                self.add_finding(
                    title="HISTCONTROL allows hiding commands",
                    description="Commands prefixed with a space will not be recorded in history",
                    severity=Severity.MEDIUM,
                    evidence=f"HISTCONTROL={val}",
                    remediation="Set HISTCONTROL=ignoredups in /etc/profile.d/ to prevent history evasion",
                )

        for var in ("HISTSIZE", "HISTFILESIZE"):
            result = session.execute(f"echo ${var}")
            if result.success and result.output.strip():
                try:
                    size = int(result.output.strip())
                    if size < 500:
                        self.add_finding(
                            title=f"{var} is set very low ({size})",
                            description=f"Low {var} limits forensic history retention",
                            severity=Severity.LOW,
                            evidence=f"{var}={size}",
                            remediation=f"Set {var}=10000 or higher in /etc/profile.d/history.sh",
                        )
                except ValueError:
                    pass

        histfile = session.execute("echo $HISTFILE")
        if histfile.success and histfile.output.strip() == "/dev/null":
            self.add_finding(
                title="HISTFILE points to /dev/null",
                description="Command history is being discarded — all commands are unrecorded",
                severity=Severity.HIGH,
                evidence="HISTFILE=/dev/null",
                remediation="Remove HISTFILE override and ensure it defaults to ~/.bash_history",
            )

        # Check profiles for unset HISTFILE
        profiles = ["/etc/profile", "/etc/bashrc", "/etc/profile.d/*.sh"]
        for pattern in profiles:
            result = session.execute(f"grep -r 'unset HISTFILE' {pattern} 2>/dev/null")
            if result.success and result.output.strip():
                self.add_finding(
                    title="HISTFILE unset in system profile",
                    description="A system-wide profile script unsets HISTFILE, disabling history",
                    severity=Severity.HIGH,
                    evidence=result.output.strip()[:500],
                    remediation="Remove 'unset HISTFILE' from system profiles",
                )

    # -- T1562.004 Disable Firewall ----------------------------------------

    def _check_disable_firewall(self, session: Session) -> None:
        fw_status = session.execute("firewall-cmd --state 2>/dev/null")
        if fw_status.success and "running" not in fw_status.output.strip().lower():
            self.add_finding(
                title="firewalld is not running",
                description="firewall-cmd reports the firewall is not in a running state",
                severity=Severity.HIGH,
                evidence=fw_status.output.strip(),
                remediation="Start firewalld: systemctl enable --now firewalld",
            )

        ipt = session.execute("iptables -L -n 2>/dev/null | grep -c '^[A-Z]'")
        if ipt.success:
            try:
                chain_count = int(ipt.output.strip())
                if chain_count <= 3:
                    self.add_finding(
                        title="iptables has no custom rules",
                        description="Only default chains exist — no filtering rules are in place",
                        severity=Severity.HIGH,
                        evidence=f"Chain header count: {chain_count}",
                        remediation="Configure iptables rules or enable firewalld",
                    )
            except ValueError:
                pass

        nft = session.execute("nft list ruleset 2>/dev/null | wc -l")
        if nft.success:
            try:
                if int(nft.output.strip() or "0") < 3:
                    self.add_finding(
                        title="nftables ruleset is empty or minimal",
                        description="nftables has very few or no rules configured",
                        severity=Severity.MEDIUM,
                        evidence=f"nftables ruleset lines: {nft.output.strip()}",
                        remediation="Configure nftables rules or use firewalld as a frontend",
                    )
            except ValueError:
                pass

    # -- T1562.010 Downgrade Attack ----------------------------------------

    def _check_downgrade_attack(self, session: Session) -> None:
        # Older TLS versions
        tls_check = session.execute(
            "grep -ri 'TLSv1\\b\\|TLSv1.0\\|TLSv1.1\\|SSLv3' /etc/crypto-policies/ /etc/ssl/ 2>/dev/null"
        )
        if tls_check.success and tls_check.output.strip():
            self.add_finding(
                title="Legacy TLS/SSL versions may be enabled",
                description="Configuration files reference TLSv1.0, TLSv1.1, or SSLv3",
                severity=Severity.HIGH,
                evidence=tls_check.output.strip()[:500],
                remediation="Use update-crypto-policies --set FUTURE or DEFAULT:NO-SHA1 to disable weak protocols",
            )

        # SSH protocol version
        ssh_proto = session.execute("grep -i 'Protocol' /etc/ssh/sshd_config 2>/dev/null")
        if ssh_proto.success and ssh_proto.output.strip():
            if "1" in ssh_proto.output and "2" not in ssh_proto.output:
                self.add_finding(
                    title="SSH Protocol version 1 may be enabled",
                    description="sshd_config references Protocol 1 which is insecure",
                    severity=Severity.CRITICAL,
                    evidence=ssh_proto.output.strip(),
                    remediation="Set Protocol 2 in /etc/ssh/sshd_config",
                )

    # -- T1562.011 Spoof Security Alerting ---------------------------------

    def _check_spoof_security_alerting(self, session: Session) -> None:
        # Check remote syslog forwarding
        rsyslog_fwd = session.execute("grep -E '^[^#]*@@?' /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null")
        if not rsyslog_fwd.success or not rsyslog_fwd.output.strip():
            self.add_finding(
                title="No remote syslog forwarding configured",
                description="Logs are only stored locally — an attacker could tamper with them undetected",
                severity=Severity.MEDIUM,
                evidence="No remote forwarding rules found in rsyslog configuration",
                remediation="Configure rsyslog to forward critical logs to a remote SIEM or log aggregator",
            )

        # Check if syslog can be redirected
        syslog_perms = session.execute("ls -la /etc/rsyslog.conf 2>/dev/null")
        if syslog_perms.success and syslog_perms.output.strip():
            if "rw-rw" in syslog_perms.output or "rw-r--rw" in syslog_perms.output:
                self.add_finding(
                    title="rsyslog.conf has overly permissive permissions",
                    description="Non-root users may be able to modify syslog configuration to redirect alerts",
                    severity=Severity.HIGH,
                    evidence=syslog_perms.output.strip(),
                    remediation="Set permissions: chmod 640 /etc/rsyslog.conf",
                )

    # -- T1562.012 Disable Linux Audit System ------------------------------

    def _check_disable_audit_system(self, session: Session) -> None:
        audit_status = session.execute("auditctl -s 2>/dev/null")
        if audit_status.success and audit_status.output.strip():
            if "enabled 0" in audit_status.output:
                self.add_finding(
                    title="Audit system is disabled",
                    description="auditctl reports the audit subsystem is disabled (enabled=0)",
                    severity=Severity.CRITICAL,
                    evidence=audit_status.output.strip()[:500],
                    remediation="Enable auditing: auditctl -e 1 and ensure auditd is running",
                )
            if "backlog_limit" in audit_status.output:
                for line in audit_status.output.splitlines():
                    if "backlog_limit" in line:
                        try:
                            limit = int(line.split()[-1])
                            if limit < 320:
                                self.add_finding(
                                    title=f"Audit backlog limit is low ({limit})",
                                    description="A low backlog limit can cause audit events to be dropped",
                                    severity=Severity.MEDIUM,
                                    evidence=line.strip(),
                                    remediation="Increase backlog: auditctl -b 8192",
                                )
                        except ValueError:
                            pass

        rules = session.execute("auditctl -l 2>/dev/null | wc -l")
        if rules.success:
            try:
                count = int(rules.output.strip())
                if count == 0:
                    self.add_finding(
                        title="No audit rules are configured",
                        description="auditctl reports zero audit rules — no file or syscall auditing is active",
                        severity=Severity.HIGH,
                        evidence="auditctl -l returned 0 rules",
                        remediation="Deploy audit rules from /usr/share/audit/sample-rules/ or use augenrules",
                    )
            except ValueError:
                pass

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Enable and enforce SELinux in enforcing mode across all hosts",
            "Ensure auditd is running with comprehensive rules from CIS benchmarks",
            "Configure firewalld or nftables and deny by default",
            "Forward all logs to a remote SIEM to prevent local tampering",
            "Use RHEL crypto-policies (update-crypto-policies --set FUTURE) to disable weak protocols",
        ]

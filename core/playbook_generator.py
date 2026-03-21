"""Ansible playbook generator for automated remediation.

Converts scan findings into executable Ansible playbooks that remediate
detected vulnerabilities on RHEL 8/9 systems.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

import structlog
import yaml

from core.models import Finding, ModuleResult, ScanResult, Severity

log = structlog.get_logger("playbook_generator")


# ---------------------------------------------------------------------------
# Technique → Ansible task mappings
# Each entry maps a technique ID to a list of remediation tasks.
# Tasks are standard Ansible module calls.
# ---------------------------------------------------------------------------

REMEDIATION_TASKS: dict[str, list[dict[str, Any]]] = {
    # -- Credential Access / Authentication ----------------------------------
    "T1003": [
        {
            "name": "Ensure /etc/shadow has mode 0000",
            "ansible.builtin.file": {"path": "/etc/shadow", "mode": "0000", "owner": "root", "group": "root"},
            "tags": ["credentials", "shadow", "cis"],
        },
        {
            "name": "Ensure /etc/gshadow has mode 0000",
            "ansible.builtin.file": {"path": "/etc/gshadow", "mode": "0000", "owner": "root", "group": "root"},
            "tags": ["credentials", "shadow", "cis"],
        },
        {
            "name": "Set password hashing algorithm to SHA-512",
            "ansible.builtin.lineinfile": {
                "path": "/etc/login.defs",
                "regexp": "^ENCRYPT_METHOD",
                "line": "ENCRYPT_METHOD SHA512",
            },
            "tags": ["credentials", "hashing", "stig"],
        },
    ],
    "T1003.008": [
        {
            "name": "Ensure /etc/shadow permissions are 0000",
            "ansible.builtin.file": {"path": "/etc/shadow", "mode": "0000", "owner": "root", "group": "root"},
            "tags": ["shadow", "stig"],
        },
        {
            "name": "Ensure password hashing uses SHA-512 in PAM",
            "ansible.builtin.lineinfile": {
                "path": "/etc/pam.d/system-auth",
                "regexp": "^password\\s+sufficient\\s+pam_unix.so",
                "line": "password    sufficient    pam_unix.so sha512 shadow nullok use_authtok",
            },
            "tags": ["pam", "hashing", "stig"],
        },
    ],
    "T1078": [
        {
            "name": "Set PASS_MAX_DAYS to 90",
            "ansible.builtin.lineinfile": {
                "path": "/etc/login.defs",
                "regexp": "^PASS_MAX_DAYS",
                "line": "PASS_MAX_DAYS   90",
            },
            "tags": ["accounts", "password-policy", "stig"],
        },
        {
            "name": "Set PASS_MIN_DAYS to 1",
            "ansible.builtin.lineinfile": {
                "path": "/etc/login.defs",
                "regexp": "^PASS_MIN_DAYS",
                "line": "PASS_MIN_DAYS   1",
            },
            "tags": ["accounts", "password-policy"],
        },
        {
            "name": "Set INACTIVE period to 35 days",
            "ansible.builtin.command": {"cmd": "useradd -D -f 35"},
            "changed_when": True,
            "tags": ["accounts", "stig"],
        },
    ],
    "T1110": [
        {
            "name": "Configure pam_faillock for account lockout",
            "ansible.builtin.copy": {
                "dest": "/etc/security/faillock.conf",
                "content": "deny = 3\nunlock_time = 900\nfail_interval = 900\neven_deny_root\nroot_unlock_time = 60\n",
                "mode": "0644",
                "owner": "root",
                "group": "root",
            },
            "tags": ["authentication", "lockout", "stig"],
        },
    ],

    # -- SSH / Remote Access -------------------------------------------------
    "T1021": [
        {
            "name": "Disable SSH root login",
            "ansible.builtin.lineinfile": {
                "path": "/etc/ssh/sshd_config",
                "regexp": "^#?PermitRootLogin",
                "line": "PermitRootLogin no",
            },
            "notify": "restart sshd",
            "tags": ["ssh", "stig", "cis"],
        },
        {
            "name": "Disable SSH password authentication",
            "ansible.builtin.lineinfile": {
                "path": "/etc/ssh/sshd_config",
                "regexp": "^#?PasswordAuthentication",
                "line": "PasswordAuthentication no",
            },
            "notify": "restart sshd",
            "tags": ["ssh", "stig"],
        },
        {
            "name": "Disable SSH empty passwords",
            "ansible.builtin.lineinfile": {
                "path": "/etc/ssh/sshd_config",
                "regexp": "^#?PermitEmptyPasswords",
                "line": "PermitEmptyPasswords no",
            },
            "notify": "restart sshd",
            "tags": ["ssh", "stig"],
        },
        {
            "name": "Set SSH strong ciphers",
            "ansible.builtin.lineinfile": {
                "path": "/etc/ssh/sshd_config",
                "regexp": "^#?Ciphers",
                "line": "Ciphers aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr",
            },
            "notify": "restart sshd",
            "tags": ["ssh", "crypto", "stig"],
        },
    ],
    "T1133": [
        {
            "name": "Disable SSH root login",
            "ansible.builtin.lineinfile": {
                "path": "/etc/ssh/sshd_config",
                "regexp": "^#?PermitRootLogin",
                "line": "PermitRootLogin no",
            },
            "notify": "restart sshd",
            "tags": ["ssh", "stig"],
        },
        {
            "name": "Disable SSH TCP forwarding",
            "ansible.builtin.lineinfile": {
                "path": "/etc/ssh/sshd_config",
                "regexp": "^#?AllowTcpForwarding",
                "line": "AllowTcpForwarding no",
            },
            "notify": "restart sshd",
            "tags": ["ssh", "hardening"],
        },
    ],

    # -- SELinux / Defense ---------------------------------------------------
    "T1059": [
        {
            "name": "Set SELinux to enforcing mode",
            "ansible.posix.selinux": {"policy": "targeted", "state": "enforcing"},
            "tags": ["selinux", "stig", "cis"],
        },
        {
            "name": "Ensure SELinux is enforcing in config",
            "ansible.builtin.lineinfile": {
                "path": "/etc/selinux/config",
                "regexp": "^SELINUX=",
                "line": "SELINUX=enforcing",
            },
            "tags": ["selinux", "stig"],
        },
    ],
    "T1190": [
        {
            "name": "Apply all security updates",
            "ansible.builtin.dnf": {"name": "*", "state": "latest", "security": True},
            "tags": ["patching", "stig"],
        },
    ],
    "T1195": [
        {
            "name": "Enable GPG check globally",
            "ansible.builtin.lineinfile": {
                "path": "/etc/dnf/dnf.conf",
                "regexp": "^gpgcheck",
                "line": "gpgcheck=1",
            },
            "tags": ["supply-chain", "stig"],
        },
    ],

    # -- Firewall / Network --------------------------------------------------
    "T1046": [
        {
            "name": "Enable and start firewalld",
            "ansible.builtin.systemd": {"name": "firewalld", "state": "started", "enabled": True},
            "tags": ["firewall", "stig", "cis"],
        },
    ],
    "T1498": [
        {
            "name": "Enable TCP SYN cookies",
            "ansible.posix.sysctl": {"name": "net.ipv4.tcp_syncookies", "value": "1", "sysctl_set": True, "reload": True},
            "tags": ["network", "dos-protection"],
        },
        {
            "name": "Enable reverse path filtering",
            "ansible.posix.sysctl": {"name": "net.ipv4.conf.all.rp_filter", "value": "1", "sysctl_set": True, "reload": True},
            "tags": ["network", "spoofing"],
        },
        {
            "name": "Ignore ICMP broadcast requests",
            "ansible.posix.sysctl": {"name": "net.ipv4.icmp_echo_ignore_broadcasts", "value": "1", "sysctl_set": True, "reload": True},
            "tags": ["network", "icmp"],
        },
    ],

    # -- Audit / Logging -----------------------------------------------------
    "T1562": [
        {
            "name": "Enable and start auditd",
            "ansible.builtin.systemd": {"name": "auditd", "state": "started", "enabled": True},
            "tags": ["audit", "stig", "cis"],
        },
        {
            "name": "Set SELinux to enforcing",
            "ansible.posix.selinux": {"policy": "targeted", "state": "enforcing"},
            "tags": ["selinux", "stig"],
        },
        {
            "name": "Enable and start firewalld",
            "ansible.builtin.systemd": {"name": "firewalld", "state": "started", "enabled": True},
            "tags": ["firewall", "stig"],
        },
    ],
    "T1070": [
        {
            "name": "Protect audit log files (mode 0600)",
            "ansible.builtin.file": {"path": "/var/log/audit/audit.log", "mode": "0600", "owner": "root", "group": "root"},
            "tags": ["audit", "logs", "stig"],
        },
        {
            "name": "Protect audit log directory (mode 0700)",
            "ansible.builtin.file": {"path": "/var/log/audit", "mode": "0700", "owner": "root", "group": "root", "state": "directory"},
            "tags": ["audit", "logs", "stig"],
        },
    ],
    "T1070.003": [
        {
            "name": "Set append-only on root bash_history",
            "ansible.builtin.command": {"cmd": "chattr +a /root/.bash_history"},
            "changed_when": True,
            "ignore_errors": True,
            "tags": ["history", "hardening"],
        },
        {
            "name": "Enforce histappend system-wide",
            "ansible.builtin.copy": {
                "dest": "/etc/profile.d/history-hardening.sh",
                "content": "shopt -s histappend\nreadonly HISTFILE\nexport HISTTIMEFORMAT='%F %T '\nexport HISTSIZE=10000\nexport HISTFILESIZE=10000\n",
                "mode": "0644",
                "owner": "root",
                "group": "root",
            },
            "tags": ["history", "hardening"],
        },
    ],

    # -- Persistence / Boot --------------------------------------------------
    "T1547": [
        {
            "name": "Set bootloader config permissions",
            "ansible.builtin.file": {"path": "/boot/grub2/grub.cfg", "mode": "0600", "owner": "root", "group": "root"},
            "tags": ["boot", "stig", "cis"],
        },
    ],
    "T1490": [
        {
            "name": "Mask Ctrl-Alt-Del target",
            "ansible.builtin.systemd": {"name": "ctrl-alt-del.target", "masked": True},
            "tags": ["boot", "stig"],
        },
    ],
    "T1543": [
        {
            "name": "Mask Ctrl-Alt-Del reboot target",
            "ansible.builtin.systemd": {"name": "ctrl-alt-del.target", "masked": True},
            "tags": ["services", "stig"],
        },
    ],
    "T1546.017": [
        {
            "name": "Set udev rules directory permissions",
            "ansible.builtin.file": {"path": "/etc/udev/rules.d", "mode": "0755", "owner": "root", "group": "root", "state": "directory"},
            "tags": ["persistence", "udev"],
        },
    ],

    # -- File Permissions / Hardening ----------------------------------------
    "T1548": [
        {
            "name": "Set default umask to 027",
            "ansible.builtin.lineinfile": {
                "path": "/etc/profile.d/umask.sh",
                "line": "umask 027",
                "create": True,
                "mode": "0644",
            },
            "tags": ["permissions", "stig", "cis"],
        },
    ],
    "T1574": [
        {
            "name": "Set secure_path in sudoers",
            "ansible.builtin.lineinfile": {
                "path": "/etc/sudoers",
                "regexp": "^Defaults\\s+secure_path",
                "line": "Defaults    secure_path = /sbin:/bin:/usr/sbin:/usr/bin",
                "validate": "visudo -cf %s",
            },
            "tags": ["path", "sudo", "stig"],
        },
    ],
    "T1574.007": [
        {
            "name": "Ensure secure_path in sudoers",
            "ansible.builtin.lineinfile": {
                "path": "/etc/sudoers",
                "regexp": "^Defaults\\s+secure_path",
                "line": "Defaults    secure_path = /sbin:/bin:/usr/sbin:/usr/bin",
                "validate": "visudo -cf %s",
            },
            "tags": ["path", "sudo"],
        },
    ],
    "T1564.002": [
        {
            "name": "Ensure only root has UID 0",
            "ansible.builtin.shell": "awk -F: '($3 == 0 && $1 != \"root\") {print $1}' /etc/passwd",
            "register": "uid0_users",
            "changed_when": False,
            "tags": ["accounts", "hidden-users"],
        },
        {
            "name": "Alert on non-root UID 0 accounts",
            "ansible.builtin.fail": {"msg": "Non-root UID 0 accounts found: {{ uid0_users.stdout_lines }}"},
            "when": "uid0_users.stdout | length > 0",
            "tags": ["accounts", "hidden-users"],
        },
    ],

    # -- Resource / DoS protection -------------------------------------------
    "T1499": [
        {
            "name": "Set max user processes limit",
            "community.general.pam_limits": {"domain": "*", "limit_type": "hard", "limit_item": "nproc", "value": "4096"},
            "tags": ["resources", "limits"],
        },
        {
            "name": "Mount /tmp with noexec,nosuid,nodev",
            "ansible.posix.mount": {
                "path": "/tmp",
                "src": "{{ ansible_mounts | selectattr('mount', 'equalto', '/tmp') | map(attribute='device') | first | default('tmpfs') }}",
                "fstype": "tmpfs",
                "opts": "defaults,noexec,nosuid,nodev,size=2G",
                "state": "mounted",
            },
            "tags": ["resources", "tmp", "cis"],
        },
    ],

    # -- USB / Physical security ---------------------------------------------
    "T1200": [
        {
            "name": "Install USBGuard",
            "ansible.builtin.dnf": {"name": "usbguard", "state": "present"},
            "tags": ["usb", "physical"],
        },
        {
            "name": "Enable USBGuard service",
            "ansible.builtin.systemd": {"name": "usbguard", "state": "started", "enabled": True},
            "tags": ["usb", "physical"],
        },
    ],
    "T1052": [
        {
            "name": "Blacklist usb_storage kernel module",
            "ansible.builtin.copy": {
                "dest": "/etc/modprobe.d/no-usb-storage.conf",
                "content": "blacklist usb_storage\ninstall usb_storage /bin/true\n",
                "mode": "0644",
                "owner": "root",
                "group": "root",
            },
            "tags": ["usb", "physical", "stig"],
        },
    ],

    # -- Crypto policy -------------------------------------------------------
    "T1027": [
        {
            "name": "Set system crypto policy to FUTURE",
            "ansible.builtin.command": {"cmd": "update-crypto-policies --set FUTURE"},
            "changed_when": True,
            "tags": ["crypto", "stig"],
        },
    ],
    "T1565": [
        {
            "name": "Install AIDE file integrity monitoring",
            "ansible.builtin.dnf": {"name": "aide", "state": "present"},
            "tags": ["integrity", "aide"],
        },
        {
            "name": "Initialize AIDE database",
            "ansible.builtin.command": {"cmd": "aide --init"},
            "args": {"creates": "/var/lib/aide/aide.db.new.gz"},
            "tags": ["integrity", "aide"],
        },
    ],

    # -- Mail / Phishing -----------------------------------------------------
    "T1566": [
        {
            "name": "Set Postfix to loopback-only",
            "ansible.builtin.lineinfile": {
                "path": "/etc/postfix/main.cf",
                "regexp": "^inet_interfaces",
                "line": "inet_interfaces = loopback-only",
            },
            "notify": "restart postfix",
            "when": "ansible_facts.services['postfix.service'] is defined",
            "tags": ["mail", "phishing"],
        },
    ],

    # -- Container Security --------------------------------------------------
    "CS001": [
        {
            "name": "Install Podman (rootless container runtime)",
            "ansible.builtin.dnf": {"name": "podman", "state": "present"},
            "tags": ["container", "runtime"],
        },
        {
            "name": "Configure subordinate UID ranges for rootless containers",
            "ansible.builtin.command": {"cmd": "usermod --add-subuids 100000-165535 --add-subgids 100000-165535 {{ ansible_user_id }}"},
            "changed_when": True,
            "tags": ["container", "rootless"],
        },
    ],
    "CS002": [
        {
            "name": "Configure container image signature policy",
            "ansible.builtin.copy": {
                "dest": "/etc/containers/policy.json",
                "content": '{\n  "default": [{"type": "reject"}],\n  "transports": {\n    "docker": {\n      "registry.redhat.io": [{"type": "signedBy", "keyType": "GPGKeys", "keyPath": "/etc/pki/rpm-gpg/RPM-GPG-KEY-redhat-release"}],\n      "registry.access.redhat.com": [{"type": "signedBy", "keyType": "GPGKeys", "keyPath": "/etc/pki/rpm-gpg/RPM-GPG-KEY-redhat-release"}],\n      "quay.io": [{"type": "insecureAcceptAnything"}]\n    }\n  }\n}\n',
                "mode": "0644",
                "backup": True,
            },
            "tags": ["container", "image-signing"],
        },
        {
            "name": "Install Trivy container vulnerability scanner",
            "ansible.builtin.dnf": {"name": "trivy", "state": "present"},
            "ignore_errors": True,
            "tags": ["container", "vulnerability-scanning"],
        },
    ],
    "CS003": [
        {
            "name": "Audit privileged containers and alert",
            "ansible.builtin.shell": "podman ps --format '{{.Names}}' --filter 'privileged=true' 2>/dev/null | head -5",
            "register": "privileged_containers",
            "changed_when": False,
            "tags": ["container", "privilege"],
        },
        {
            "name": "Warn if privileged containers found",
            "ansible.builtin.debug": {"msg": "WARNING: Privileged containers found: {{ privileged_containers.stdout_lines }}"},
            "when": "privileged_containers.stdout | length > 0",
            "tags": ["container", "privilege"],
        },
    ],
    "CS005": [
        {
            "name": "Set default seccomp profile for Podman",
            "ansible.builtin.copy": {
                "dest": "/etc/containers/containers.conf.d/seccomp.conf",
                "content": "[containers]\nseccomp_profile = \"/usr/share/containers/seccomp.json\"\n",
                "mode": "0644",
            },
            "tags": ["container", "seccomp"],
        },
    ],
    "CS006": [
        {
            "name": "Set default container PID limit",
            "ansible.builtin.copy": {
                "dest": "/etc/containers/containers.conf.d/limits.conf",
                "content": "[containers]\npids_limit = 256\n",
                "mode": "0644",
            },
            "tags": ["container", "resource-limits"],
        },
    ],
    "CS008": [
        {
            "name": "Configure default read-only rootfs for containers",
            "ansible.builtin.copy": {
                "dest": "/etc/containers/containers.conf.d/readonly.conf",
                "content": "[containers]\nread_only = true\n",
                "mode": "0644",
            },
            "tags": ["container", "filesystem"],
        },
    ],
    "CS010": [
        {
            "name": "Install cosign for container image signing",
            "ansible.builtin.get_url": {
                "url": "https://github.com/sigstore/cosign/releases/latest/download/cosign-linux-amd64",
                "dest": "/usr/local/bin/cosign",
                "mode": "0755",
            },
            "tags": ["container", "supply-chain"],
        },
    ],
}


# ---------------------------------------------------------------------------
# Handlers referenced by tasks
# ---------------------------------------------------------------------------

HANDLERS: list[dict[str, Any]] = [
    {
        "name": "restart sshd",
        "ansible.builtin.systemd": {"name": "sshd", "state": "restarted"},
    },
    {
        "name": "restart postfix",
        "ansible.builtin.systemd": {"name": "postfix", "state": "restarted"},
    },
    {
        "name": "restart auditd",
        "ansible.builtin.command": {"cmd": "service auditd restart"},
    },
]


class PlaybookGenerator:
    """Generates Ansible playbooks from scan results."""

    def __init__(self, output_dir: str = "reports") -> None:
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate(
        self,
        scan_result: ScanResult,
        severity_filter: Severity | None = None,
        tags_filter: list[str] | None = None,
    ) -> Path:
        """Generate an Ansible playbook from vulnerable scan results.

        Args:
            scan_result: The completed scan result.
            severity_filter: Only include tasks for findings at or above this severity.
            tags_filter: Only include tasks with matching tags.

        Returns:
            Path to the generated playbook YAML file.
        """
        tasks = self._collect_tasks(scan_result, severity_filter, tags_filter)
        playbook = self._build_playbook(scan_result, tasks)

        timestamp = datetime.now().strftime("%Y-%m-%d_%H%M%S")
        path = self.output_dir / f"remediate_{scan_result.scan_id}_{timestamp}.yml"

        # Use yaml.dump with custom formatting for clean output
        content = yaml.dump(
            playbook,
            default_flow_style=False,
            sort_keys=False,
            allow_unicode=True,
            width=120,
        )

        # Add header comment
        header = (
            f"# Ansible Remediation Playbook\n"
            f"# Generated by RHEL-RT (Red Team Security Scanner)\n"
            f"# Scan ID: {scan_result.scan_id}\n"
            f"# Date: {datetime.now().isoformat()}\n"
            f"# Vulnerable findings: {scan_result.vulnerable_count}\n"
            f"# Remediation tasks: {len(tasks)}\n"
            f"#\n"
            f"# REVIEW BEFORE RUNNING — some tasks restart services or modify auth config.\n"
            f"# Usage: ansible-playbook -i inventory {path.name} --check  (dry-run first)\n"
            f"#        ansible-playbook -i inventory {path.name}\n"
            f"---\n"
        )

        path.write_text(header + content, encoding="utf-8")
        log.info("playbook_generated", path=str(path), tasks=len(tasks))
        return path

    def generate_per_technique(self, scan_result: ScanResult) -> list[Path]:
        """Generate a separate playbook per vulnerable technique."""
        paths: list[Path] = []
        for result in scan_result.results:
            if not result.is_vulnerable:
                continue
            tasks = self._tasks_for_technique(result.technique_id)
            if not tasks:
                tasks = self._tasks_from_findings(result)
            if not tasks:
                continue

            playbook = [{
                "name": f"Remediate {result.technique_id} — {result.technique_name}",
                "hosts": "all",
                "become": True,
                "tasks": tasks,
                "handlers": [h for h in HANDLERS if self._handler_referenced(h["name"], tasks)],
            }]

            tid = result.technique_id.replace(".", "_")
            path = self.output_dir / f"remediate_{tid}.yml"
            content = yaml.dump(playbook, default_flow_style=False, sort_keys=False, width=120)
            path.write_text(f"# Remediation for {result.technique_id}\n---\n" + content, encoding="utf-8")
            paths.append(path)

        return paths

    def _collect_tasks(
        self,
        scan_result: ScanResult,
        severity_filter: Severity | None,
        tags_filter: list[str] | None,
    ) -> list[dict[str, Any]]:
        """Collect all remediation tasks for vulnerable results."""
        severity_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
        min_idx = severity_order.index(severity_filter) if severity_filter else len(severity_order) - 1

        seen_names: set[str] = set()
        tasks: list[dict[str, Any]] = []

        for result in scan_result.results:
            if not result.is_vulnerable:
                continue

            if severity_filter:
                result_idx = severity_order.index(result.max_severity)
                if result_idx > min_idx:
                    continue

            technique_tasks = self._tasks_for_technique(result.technique_id)

            if not technique_tasks:
                technique_tasks = self._tasks_from_findings(result)

            for task in technique_tasks:
                if tags_filter:
                    task_tags = task.get("tags", [])
                    if not any(t in task_tags for t in tags_filter):
                        continue

                name = task.get("name", "")
                if name not in seen_names:
                    seen_names.add(name)
                    tasks.append(task)

        return tasks

    def _tasks_for_technique(self, technique_id: str) -> list[dict[str, Any]]:
        """Get pre-defined remediation tasks for a technique."""
        tasks = REMEDIATION_TASKS.get(technique_id, [])
        if not tasks:
            base_id = technique_id.split(".")[0]
            tasks = REMEDIATION_TASKS.get(base_id, [])
        return [dict(t) for t in tasks]

    def _tasks_from_findings(self, result: ModuleResult) -> list[dict[str, Any]]:
        """Generate generic tasks from finding remediations when no mapping exists."""
        tasks: list[dict[str, Any]] = []
        for finding in result.findings:
            if finding.remediation:
                cmd = self._parse_remediation_command(finding.remediation)
                if cmd:
                    tasks.append({
                        "name": f"[{result.technique_id}] {finding.title}",
                        "ansible.builtin.shell": cmd,
                        "changed_when": True,
                        "tags": ["auto-generated", result.technique_id.lower()],
                    })
        return tasks

    def _parse_remediation_command(self, remediation: str) -> str | None:
        """Extract an actionable shell command from a remediation string."""
        indicators = [
            "chmod ", "chown ", "sysctl -w ", "systemctl ",
            "dnf ", "setenforce ", "chattr ", "update-crypto-policies ",
            "firewall-cmd ", "auditctl ", "usermod ", "userdel ",
        ]
        for indicator in indicators:
            if indicator in remediation:
                # Extract the command portion after the indicator
                idx = remediation.index(indicator)
                cmd = remediation[idx:].split(";")[0].strip()
                # Clean up trailing punctuation
                cmd = cmd.rstrip(".")
                if len(cmd) > 5:
                    return cmd
        return None

    def _build_playbook(
        self, scan_result: ScanResult, tasks: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Build the full Ansible playbook structure."""
        active_handlers = [
            h for h in HANDLERS
            if self._handler_referenced(h["name"], tasks)
        ]

        play: dict[str, Any] = {
            "name": f"RHEL-RT Remediation — Scan {scan_result.scan_id}",
            "hosts": "all",
            "become": True,
            "gather_facts": True,
            "vars": {
                "rhel_rt_scan_id": scan_result.scan_id,
                "rhel_rt_generated": datetime.now().isoformat(),
            },
            "tasks": tasks,
        }

        if active_handlers:
            play["handlers"] = active_handlers

        return [play]

    @staticmethod
    def _handler_referenced(handler_name: str, tasks: list[dict[str, Any]]) -> bool:
        """Check if any task references a handler by name."""
        for task in tasks:
            notify = task.get("notify")
            if notify == handler_name:
                return True
            if isinstance(notify, list) and handler_name in notify:
                return True
        return False

    def get_available_tags(self) -> set[str]:
        """Return all tags used across remediation tasks."""
        tags: set[str] = set()
        for task_list in REMEDIATION_TASKS.values():
            for task in task_list:
                tags.update(task.get("tags", []))
        return tags

    def get_technique_coverage(self) -> dict[str, int]:
        """Return how many tasks exist per mapped technique."""
        return {tid: len(tasks) for tid, tasks in REMEDIATION_TASKS.items()}

"""CIS Benchmark and NIST 800-53 compliance mapping for ATT&CK techniques.

Maps MITRE ATT&CK technique IDs to:
- CIS Controls v8
- NIST SP 800-53 Rev. 5 control families
- CIS RHEL Benchmark recommendations
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from core.models import ModuleResult, ScanResult


@dataclass
class ComplianceRef:
    """A single compliance framework reference."""
    framework: str       # "CIS Controls v8", "NIST 800-53", "CIS RHEL 9 Benchmark"
    control_id: str      # "AC-2", "5.2.1", "4.3"
    control_name: str    # Human-readable name
    description: str = ""


# ---------------------------------------------------------------------------
# ATT&CK → CIS Controls v8 mapping
# ---------------------------------------------------------------------------

CIS_CONTROLS: dict[str, list[ComplianceRef]] = {
    "T1021": [
        ComplianceRef("CIS Controls v8", "4.1", "Establish and Maintain a Secure Configuration Process"),
        ComplianceRef("CIS Controls v8", "4.7", "Manage Default Accounts on Enterprise Assets"),
        ComplianceRef("CIS Controls v8", "12.2", "Establish and Maintain a Secure Network Architecture"),
    ],
    "T1550": [
        ComplianceRef("CIS Controls v8", "6.3", "Require MFA for Externally-Exposed Applications"),
        ComplianceRef("CIS Controls v8", "6.4", "Require MFA for Remote Network Access"),
        ComplianceRef("CIS Controls v8", "6.5", "Require MFA for Administrative Access"),
    ],
    "T1570": [
        ComplianceRef("CIS Controls v8", "2.5", "Allowlist Authorized Software"),
        ComplianceRef("CIS Controls v8", "9.2", "Ensure Only Approved Ports, Protocols, and Services Are Running"),
    ],
    "T1071": [
        ComplianceRef("CIS Controls v8", "9.2", "Ensure Only Approved Ports, Protocols, and Services Are Running"),
        ComplianceRef("CIS Controls v8", "9.3", "Perform Application Layer Filtering"),
        ComplianceRef("CIS Controls v8", "13.3", "Deploy a Network Intrusion Detection Solution"),
    ],
    "T1573": [
        ComplianceRef("CIS Controls v8", "3.10", "Encrypt Sensitive Data in Transit"),
        ComplianceRef("CIS Controls v8", "9.3", "Perform Application Layer Filtering"),
        ComplianceRef("CIS Controls v8", "13.6", "Collect Network Traffic Flow Logs"),
    ],
    "T1090": [
        ComplianceRef("CIS Controls v8", "9.2", "Ensure Only Approved Ports, Protocols, and Services Are Running"),
        ComplianceRef("CIS Controls v8", "13.3", "Deploy a Network Intrusion Detection Solution"),
        ComplianceRef("CIS Controls v8", "13.4", "Perform Traffic Filtering Between Network Segments"),
    ],
    "T1048": [
        ComplianceRef("CIS Controls v8", "9.3", "Perform Application Layer Filtering"),
        ComplianceRef("CIS Controls v8", "13.3", "Deploy a Network Intrusion Detection Solution"),
        ComplianceRef("CIS Controls v8", "13.8", "Deploy a Network Intrusion Prevention Solution"),
    ],
    "T1041": [
        ComplianceRef("CIS Controls v8", "9.3", "Perform Application Layer Filtering"),
        ComplianceRef("CIS Controls v8", "13.3", "Deploy a Network Intrusion Detection Solution"),
        ComplianceRef("CIS Controls v8", "8.5", "Collect Detailed Audit Logs"),
    ],
    "T1082": [
        ComplianceRef("CIS Controls v8", "4.1", "Establish and Maintain a Secure Configuration Process"),
        ComplianceRef("CIS Controls v8", "3.3", "Configure Data Access Control Lists"),
    ],
    "T1087": [
        ComplianceRef("CIS Controls v8", "5.3", "Disable Dormant Accounts"),
        ComplianceRef("CIS Controls v8", "5.4", "Restrict Administrator Privileges to Dedicated Admin Accounts"),
    ],
    "T1069": [
        ComplianceRef("CIS Controls v8", "6.1", "Establish an Access Granting Process"),
        ComplianceRef("CIS Controls v8", "6.2", "Establish an Access Revoking Process"),
    ],
    "T1046": [
        ComplianceRef("CIS Controls v8", "9.2", "Ensure Only Approved Ports, Protocols, and Services Are Running"),
        ComplianceRef("CIS Controls v8", "12.2", "Establish and Maintain a Secure Network Architecture"),
    ],
    "T1003": [
        ComplianceRef("CIS Controls v8", "3.3", "Configure Data Access Control Lists"),
        ComplianceRef("CIS Controls v8", "3.10", "Encrypt Sensitive Data in Transit"),
        ComplianceRef("CIS Controls v8", "6.7", "Centralize Access Control"),
    ],
    "T1110": [
        ComplianceRef("CIS Controls v8", "4.10", "Enforce Automatic Device Lockout on Portable End-User Devices"),
        ComplianceRef("CIS Controls v8", "5.2", "Use Unique Passwords"),
    ],
    "T1059": [
        ComplianceRef("CIS Controls v8", "2.5", "Allowlist Authorized Software"),
        ComplianceRef("CIS Controls v8", "2.6", "Allowlist Authorized Libraries"),
        ComplianceRef("CIS Controls v8", "2.7", "Allowlist Authorized Scripts"),
    ],
    "T1053": [
        ComplianceRef("CIS Controls v8", "4.1", "Establish and Maintain a Secure Configuration Process"),
        ComplianceRef("CIS Controls v8", "8.5", "Collect Detailed Audit Logs"),
    ],
    "T1547": [
        ComplianceRef("CIS Controls v8", "4.1", "Establish and Maintain a Secure Configuration Process"),
        ComplianceRef("CIS Controls v8", "10.5", "Enable Anti-Exploitation Features"),
    ],
    "T1543": [
        ComplianceRef("CIS Controls v8", "4.1", "Establish and Maintain a Secure Configuration Process"),
        ComplianceRef("CIS Controls v8", "4.8", "Uninstall or Disable Unnecessary Services on Enterprise Assets"),
    ],
    "T1562": [
        ComplianceRef("CIS Controls v8", "8.2", "Collect Audit Logs"),
        ComplianceRef("CIS Controls v8", "8.5", "Collect Detailed Audit Logs"),
        ComplianceRef("CIS Controls v8", "10.1", "Deploy and Maintain Anti-Malware Software"),
    ],
    "T1548": [
        ComplianceRef("CIS Controls v8", "5.4", "Restrict Administrator Privileges to Dedicated Admin Accounts"),
        ComplianceRef("CIS Controls v8", "6.8", "Define and Maintain Role-Based Access Control"),
    ],
    "T1574": [
        ComplianceRef("CIS Controls v8", "2.5", "Allowlist Authorized Software"),
        ComplianceRef("CIS Controls v8", "2.6", "Allowlist Authorized Libraries"),
    ],
    "T1552": [
        ComplianceRef("CIS Controls v8", "3.3", "Configure Data Access Control Lists"),
        ComplianceRef("CIS Controls v8", "3.7", "Establish and Maintain a Data Classification Scheme"),
    ],
    "T1558": [
        ComplianceRef("CIS Controls v8", "6.3", "Require MFA for Externally-Exposed Applications"),
        ComplianceRef("CIS Controls v8", "6.5", "Require MFA for Administrative Access"),
    ],
}

# ---------------------------------------------------------------------------
# ATT&CK → NIST SP 800-53 Rev. 5 mapping
# ---------------------------------------------------------------------------

NIST_CONTROLS: dict[str, list[ComplianceRef]] = {
    "T1021": [
        ComplianceRef("NIST 800-53", "AC-17", "Remote Access"),
        ComplianceRef("NIST 800-53", "CM-7", "Least Functionality"),
        ComplianceRef("NIST 800-53", "SC-7", "Boundary Protection"),
    ],
    "T1550": [
        ComplianceRef("NIST 800-53", "IA-2", "Identification and Authentication"),
        ComplianceRef("NIST 800-53", "IA-5", "Authenticator Management"),
        ComplianceRef("NIST 800-53", "SC-12", "Cryptographic Key Establishment and Management"),
    ],
    "T1570": [
        ComplianceRef("NIST 800-53", "CM-7", "Least Functionality"),
        ComplianceRef("NIST 800-53", "CM-11", "User-Installed Software"),
        ComplianceRef("NIST 800-53", "SC-7", "Boundary Protection"),
    ],
    "T1071": [
        ComplianceRef("NIST 800-53", "AC-4", "Information Flow Enforcement"),
        ComplianceRef("NIST 800-53", "SC-7", "Boundary Protection"),
        ComplianceRef("NIST 800-53", "SI-4", "System Monitoring"),
    ],
    "T1573": [
        ComplianceRef("NIST 800-53", "SC-8", "Transmission Confidentiality and Integrity"),
        ComplianceRef("NIST 800-53", "SC-13", "Cryptographic Protection"),
        ComplianceRef("NIST 800-53", "SI-4", "System Monitoring"),
    ],
    "T1090": [
        ComplianceRef("NIST 800-53", "AC-4", "Information Flow Enforcement"),
        ComplianceRef("NIST 800-53", "SC-7", "Boundary Protection"),
        ComplianceRef("NIST 800-53", "SI-4", "System Monitoring"),
    ],
    "T1048": [
        ComplianceRef("NIST 800-53", "AC-4", "Information Flow Enforcement"),
        ComplianceRef("NIST 800-53", "SC-7", "Boundary Protection"),
        ComplianceRef("NIST 800-53", "SI-4", "System Monitoring"),
    ],
    "T1041": [
        ComplianceRef("NIST 800-53", "AC-4", "Information Flow Enforcement"),
        ComplianceRef("NIST 800-53", "AU-3", "Content of Audit Records"),
        ComplianceRef("NIST 800-53", "SC-7", "Boundary Protection"),
    ],
    "T1082": [
        ComplianceRef("NIST 800-53", "CM-6", "Configuration Settings"),
        ComplianceRef("NIST 800-53", "SC-28", "Protection of Information at Rest"),
    ],
    "T1087": [
        ComplianceRef("NIST 800-53", "AC-2", "Account Management"),
        ComplianceRef("NIST 800-53", "AC-6", "Least Privilege"),
    ],
    "T1069": [
        ComplianceRef("NIST 800-53", "AC-2", "Account Management"),
        ComplianceRef("NIST 800-53", "AC-6", "Least Privilege"),
    ],
    "T1046": [
        ComplianceRef("NIST 800-53", "CM-7", "Least Functionality"),
        ComplianceRef("NIST 800-53", "SC-7", "Boundary Protection"),
        ComplianceRef("NIST 800-53", "RA-5", "Vulnerability Monitoring and Scanning"),
    ],
    "T1003": [
        ComplianceRef("NIST 800-53", "IA-5", "Authenticator Management"),
        ComplianceRef("NIST 800-53", "SC-28", "Protection of Information at Rest"),
        ComplianceRef("NIST 800-53", "AC-3", "Access Enforcement"),
    ],
    "T1110": [
        ComplianceRef("NIST 800-53", "AC-7", "Unsuccessful Logon Attempts"),
        ComplianceRef("NIST 800-53", "IA-5", "Authenticator Management"),
    ],
    "T1059": [
        ComplianceRef("NIST 800-53", "CM-7", "Least Functionality"),
        ComplianceRef("NIST 800-53", "CM-11", "User-Installed Software"),
        ComplianceRef("NIST 800-53", "SI-16", "Memory Protection"),
    ],
    "T1053": [
        ComplianceRef("NIST 800-53", "CM-7", "Least Functionality"),
        ComplianceRef("NIST 800-53", "AU-2", "Event Logging"),
    ],
    "T1547": [
        ComplianceRef("NIST 800-53", "CM-6", "Configuration Settings"),
        ComplianceRef("NIST 800-53", "SI-7", "Software, Firmware, and Information Integrity"),
    ],
    "T1543": [
        ComplianceRef("NIST 800-53", "CM-7", "Least Functionality"),
        ComplianceRef("NIST 800-53", "CM-6", "Configuration Settings"),
    ],
    "T1562": [
        ComplianceRef("NIST 800-53", "AU-9", "Protection of Audit Information"),
        ComplianceRef("NIST 800-53", "SI-4", "System Monitoring"),
    ],
    "T1548": [
        ComplianceRef("NIST 800-53", "AC-6", "Least Privilege"),
        ComplianceRef("NIST 800-53", "CM-6", "Configuration Settings"),
    ],
    "T1574": [
        ComplianceRef("NIST 800-53", "CM-7", "Least Functionality"),
        ComplianceRef("NIST 800-53", "SI-7", "Software, Firmware, and Information Integrity"),
    ],
    "T1552": [
        ComplianceRef("NIST 800-53", "IA-5", "Authenticator Management"),
        ComplianceRef("NIST 800-53", "SC-28", "Protection of Information at Rest"),
    ],
    "T1558": [
        ComplianceRef("NIST 800-53", "IA-2", "Identification and Authentication"),
        ComplianceRef("NIST 800-53", "IA-5", "Authenticator Management"),
    ],
    "T1036": [
        ComplianceRef("NIST 800-53", "SI-4", "System Monitoring"),
        ComplianceRef("NIST 800-53", "SI-7", "Software, Firmware, and Information Integrity"),
    ],
    "T1070": [
        ComplianceRef("NIST 800-53", "AU-9", "Protection of Audit Information"),
        ComplianceRef("NIST 800-53", "AU-4", "Audit Log Storage Capacity"),
    ],
    "T1027": [
        ComplianceRef("NIST 800-53", "SI-3", "Malicious Code Protection"),
        ComplianceRef("NIST 800-53", "SI-4", "System Monitoring"),
    ],
    "T1556": [
        ComplianceRef("NIST 800-53", "IA-2", "Identification and Authentication"),
        ComplianceRef("NIST 800-53", "SI-7", "Software, Firmware, and Information Integrity"),
    ],
    "T1136": [
        ComplianceRef("NIST 800-53", "AC-2", "Account Management"),
        ComplianceRef("NIST 800-53", "IA-4", "Identifier Management"),
    ],
    "T1098": [
        ComplianceRef("NIST 800-53", "AC-2", "Account Management"),
        ComplianceRef("NIST 800-53", "AC-6", "Least Privilege"),
    ],
}

# ---------------------------------------------------------------------------
# ATT&CK → CIS RHEL 9 Benchmark mapping
# ---------------------------------------------------------------------------

CIS_RHEL_BENCHMARK: dict[str, list[ComplianceRef]] = {
    "T1021": [
        ComplianceRef("CIS RHEL 9 Benchmark", "5.2.1", "Ensure permissions on /etc/ssh/sshd_config are configured"),
        ComplianceRef("CIS RHEL 9 Benchmark", "5.2.4", "Ensure SSH root login is disabled"),
        ComplianceRef("CIS RHEL 9 Benchmark", "5.2.6", "Ensure SSH PermitEmptyPasswords is disabled"),
        ComplianceRef("CIS RHEL 9 Benchmark", "5.2.14", "Ensure only strong ciphers are used"),
    ],
    "T1003": [
        ComplianceRef("CIS RHEL 9 Benchmark", "6.1.3", "Ensure permissions on /etc/shadow are configured"),
        ComplianceRef("CIS RHEL 9 Benchmark", "6.1.4", "Ensure permissions on /etc/gshadow are configured"),
    ],
    "T1059": [
        ComplianceRef("CIS RHEL 9 Benchmark", "1.6.1.1", "Ensure SELinux is installed"),
        ComplianceRef("CIS RHEL 9 Benchmark", "1.6.1.3", "Ensure SELinux policy is configured"),
        ComplianceRef("CIS RHEL 9 Benchmark", "1.6.1.4", "Ensure the SELinux mode is not disabled"),
    ],
    "T1110": [
        ComplianceRef("CIS RHEL 9 Benchmark", "5.4.1", "Ensure password creation requirements are configured"),
        ComplianceRef("CIS RHEL 9 Benchmark", "5.4.2", "Ensure lockout for failed password attempts is configured"),
    ],
    "T1548": [
        ComplianceRef("CIS RHEL 9 Benchmark", "5.3.4", "Ensure default user umask is 027 or more restrictive"),
        ComplianceRef("CIS RHEL 9 Benchmark", "6.1.8", "Ensure no world-writable files exist"),
        ComplianceRef("CIS RHEL 9 Benchmark", "6.1.10", "Ensure no unowned files or directories exist"),
    ],
    "T1562": [
        ComplianceRef("CIS RHEL 9 Benchmark", "4.2.1.1", "Ensure rsyslog is installed"),
        ComplianceRef("CIS RHEL 9 Benchmark", "4.2.1.3", "Ensure rsyslog default file permissions are configured"),
        ComplianceRef("CIS RHEL 9 Benchmark", "4.1.1.1", "Ensure auditd is installed"),
        ComplianceRef("CIS RHEL 9 Benchmark", "4.1.1.2", "Ensure auditd service is enabled and active"),
    ],
    "T1543": [
        ComplianceRef("CIS RHEL 9 Benchmark", "2.1.1", "Ensure time synchronization is in use"),
        ComplianceRef("CIS RHEL 9 Benchmark", "2.2.1", "Ensure xinetd is not installed"),
    ],
    "T1547": [
        ComplianceRef("CIS RHEL 9 Benchmark", "1.4.1", "Ensure bootloader password is set"),
        ComplianceRef("CIS RHEL 9 Benchmark", "1.4.2", "Ensure permissions on bootloader config are configured"),
    ],
    "T1046": [
        ComplianceRef("CIS RHEL 9 Benchmark", "3.4.1.1", "Ensure firewalld is installed"),
        ComplianceRef("CIS RHEL 9 Benchmark", "3.4.1.2", "Ensure iptables-services is not installed with firewalld"),
        ComplianceRef("CIS RHEL 9 Benchmark", "3.4.1.4", "Ensure firewalld default zone is set"),
    ],
    "T1082": [
        ComplianceRef("CIS RHEL 9 Benchmark", "1.5.1", "Ensure core dump storage is disabled"),
        ComplianceRef("CIS RHEL 9 Benchmark", "1.5.2", "Ensure core dump backtraces are disabled"),
    ],
    "T1574": [
        ComplianceRef("CIS RHEL 9 Benchmark", "6.1.11", "Ensure no ungrouped files or directories exist"),
        ComplianceRef("CIS RHEL 9 Benchmark", "6.1.9", "Ensure no SUID/SGID files exist"),
    ],
    "T1053": [
        ComplianceRef("CIS RHEL 9 Benchmark", "5.1.1", "Ensure cron daemon is enabled and running"),
        ComplianceRef("CIS RHEL 9 Benchmark", "5.1.2", "Ensure permissions on /etc/crontab are configured"),
        ComplianceRef("CIS RHEL 9 Benchmark", "5.1.8", "Ensure cron is restricted to authorized users"),
    ],
    "T1556": [
        ComplianceRef("CIS RHEL 9 Benchmark", "5.4.1", "Ensure password creation requirements are configured"),
        ComplianceRef("CIS RHEL 9 Benchmark", "5.4.4", "Ensure password hashing algorithm is SHA-512 or yescrypt"),
    ],
    "T1136": [
        ComplianceRef("CIS RHEL 9 Benchmark", "5.5.2", "Ensure system accounts are secured"),
        ComplianceRef("CIS RHEL 9 Benchmark", "5.5.4", "Ensure default group for the root account is GID 0"),
    ],
}


# ---------------------------------------------------------------------------
# ATT&CK → DISA STIG RHEL 8 mapping (V1R14+)
# Rule IDs follow STIG Viewer format: V-XXXXXX / SV-XXXXXX
# ---------------------------------------------------------------------------

DISA_STIG_RHEL8: dict[str, list[ComplianceRef]] = {
    "T1003": [
        ComplianceRef("DISA STIG RHEL 8", "V-230328", "RHEL 8 must use SHA-512 for password hashing", "RHEL-08-010110"),
        ComplianceRef("DISA STIG RHEL 8", "V-230329", "RHEL 8 shadow file must be owned by root", "RHEL-08-010120"),
        ComplianceRef("DISA STIG RHEL 8", "V-230330", "RHEL 8 shadow file must have mode 0000", "RHEL-08-010130"),
    ],
    "T1021": [
        ComplianceRef("DISA STIG RHEL 8", "V-230288", "RHEL 8 must not permit root login via SSH", "RHEL-08-010550"),
        ComplianceRef("DISA STIG RHEL 8", "V-230291", "RHEL 8 must use strong SSH ciphers", "RHEL-08-010291"),
        ComplianceRef("DISA STIG RHEL 8", "V-230296", "RHEL 8 must not allow empty passwords for SSH", "RHEL-08-010300"),
        ComplianceRef("DISA STIG RHEL 8", "V-244525", "RHEL 8 SSH must use FIPS-validated ciphers", "RHEL-08-010291"),
    ],
    "T1027": [
        ComplianceRef("DISA STIG RHEL 8", "V-230487", "RHEL 8 must enable FIPS mode", "RHEL-08-010020"),
        ComplianceRef("DISA STIG RHEL 8", "V-230223", "RHEL 8 must implement NIST FIPS-validated cryptography", "RHEL-08-010030"),
    ],
    "T1036": [
        ComplianceRef("DISA STIG RHEL 8", "V-230264", "RHEL 8 must verify packages with RPM", "RHEL-08-010019"),
        ComplianceRef("DISA STIG RHEL 8", "V-230265", "RHEL 8 must validate package signatures", "RHEL-08-010020"),
    ],
    "T1046": [
        ComplianceRef("DISA STIG RHEL 8", "V-230505", "RHEL 8 must enable firewalld", "RHEL-08-040090"),
        ComplianceRef("DISA STIG RHEL 8", "V-230507", "RHEL 8 must control network traffic", "RHEL-08-040110"),
    ],
    "T1053": [
        ComplianceRef("DISA STIG RHEL 8", "V-230346", "RHEL 8 must restrict cron to authorized users", "RHEL-08-010380"),
        ComplianceRef("DISA STIG RHEL 8", "V-230347", "RHEL 8 must restrict at to authorized users", "RHEL-08-010390"),
    ],
    "T1059": [
        ComplianceRef("DISA STIG RHEL 8", "V-230234", "RHEL 8 must enforce SELinux targeted policy", "RHEL-08-010170"),
        ComplianceRef("DISA STIG RHEL 8", "V-230235", "RHEL 8 must be in SELinux enforcing mode", "RHEL-08-010180"),
        ComplianceRef("DISA STIG RHEL 8", "V-244526", "RHEL 8 must disable user namespaces", "RHEL-08-010121"),
    ],
    "T1068": [
        ComplianceRef("DISA STIG RHEL 8", "V-230269", "RHEL 8 must apply security patches", "RHEL-08-010010"),
        ComplianceRef("DISA STIG RHEL 8", "V-230480", "RHEL 8 must enable kernel page-table isolation", "RHEL-08-040004"),
    ],
    "T1070": [
        ComplianceRef("DISA STIG RHEL 8", "V-230386", "RHEL 8 audit logs must be owned by root", "RHEL-08-030080"),
        ComplianceRef("DISA STIG RHEL 8", "V-230387", "RHEL 8 audit logs must have mode 0600 or less", "RHEL-08-030090"),
        ComplianceRef("DISA STIG RHEL 8", "V-230388", "RHEL 8 audit log directory must have mode 0700", "RHEL-08-030100"),
        ComplianceRef("DISA STIG RHEL 8", "V-230395", "RHEL 8 must protect audit log from unauthorized deletion", "RHEL-08-030170"),
    ],
    "T1078": [
        ComplianceRef("DISA STIG RHEL 8", "V-230332", "RHEL 8 must disable account identifiers after 35 days of inactivity", "RHEL-08-010150"),
        ComplianceRef("DISA STIG RHEL 8", "V-230340", "RHEL 8 must assign a valid home directory to all accounts", "RHEL-08-010340"),
        ComplianceRef("DISA STIG RHEL 8", "V-230376", "RHEL 8 must set an expiration date for temporary accounts", "RHEL-08-020270"),
    ],
    "T1082": [
        ComplianceRef("DISA STIG RHEL 8", "V-230221", "RHEL 8 must display a DoD-approved login banner", "RHEL-08-010060"),
        ComplianceRef("DISA STIG RHEL 8", "V-230269", "RHEL 8 must be a vendor-supported release", "RHEL-08-010010"),
    ],
    "T1087": [
        ComplianceRef("DISA STIG RHEL 8", "V-230334", "RHEL 8 must ensure only root has UID 0", "RHEL-08-010170"),
        ComplianceRef("DISA STIG RHEL 8", "V-230341", "RHEL 8 must not have unnecessary accounts", "RHEL-08-010350"),
    ],
    "T1098": [
        ComplianceRef("DISA STIG RHEL 8", "V-230333", "RHEL 8 must automatically expire temporary accounts", "RHEL-08-010160"),
        ComplianceRef("DISA STIG RHEL 8", "V-230339", "RHEL 8 must ensure users are in assigned groups", "RHEL-08-010330"),
    ],
    "T1110": [
        ComplianceRef("DISA STIG RHEL 8", "V-230333", "RHEL 8 must lock accounts after 3 failed attempts", "RHEL-08-020010"),
        ComplianceRef("DISA STIG RHEL 8", "V-230356", "RHEL 8 must enforce password complexity", "RHEL-08-020100"),
        ComplianceRef("DISA STIG RHEL 8", "V-230357", "RHEL 8 must require minimum 15-character passwords", "RHEL-08-020110"),
        ComplianceRef("DISA STIG RHEL 8", "V-230369", "RHEL 8 must enforce 60-day maximum password lifetime", "RHEL-08-020200"),
    ],
    "T1133": [
        ComplianceRef("DISA STIG RHEL 8", "V-230288", "RHEL 8 must not permit root login via SSH", "RHEL-08-010550"),
        ComplianceRef("DISA STIG RHEL 8", "V-230527", "RHEL 8 must restrict remote access sessions", "RHEL-08-040340"),
    ],
    "T1136": [
        ComplianceRef("DISA STIG RHEL 8", "V-230379", "RHEL 8 must audit account creation actions", "RHEL-08-030490"),
        ComplianceRef("DISA STIG RHEL 8", "V-230334", "RHEL 8 must not allow duplicate UIDs", "RHEL-08-010170"),
    ],
    "T1190": [
        ComplianceRef("DISA STIG RHEL 8", "V-230269", "RHEL 8 must apply security-relevant patches", "RHEL-08-010010"),
        ComplianceRef("DISA STIG RHEL 8", "V-230270", "RHEL 8 GPG keys must be verified", "RHEL-08-010019"),
    ],
    "T1195": [
        ComplianceRef("DISA STIG RHEL 8", "V-230264", "RHEL 8 must verify all packages with RPM", "RHEL-08-010019"),
        ComplianceRef("DISA STIG RHEL 8", "V-230265", "RHEL 8 must validate GPG signatures for packages", "RHEL-08-010020"),
        ComplianceRef("DISA STIG RHEL 8", "V-230266", "RHEL 8 must enable gpgcheck globally", "RHEL-08-010021"),
    ],
    "T1485": [
        ComplianceRef("DISA STIG RHEL 8", "V-230386", "RHEL 8 must protect system data integrity", "RHEL-08-030080"),
    ],
    "T1489": [
        ComplianceRef("DISA STIG RHEL 8", "V-230505", "RHEL 8 must enable firewalld to protect services", "RHEL-08-040090"),
    ],
    "T1490": [
        ComplianceRef("DISA STIG RHEL 8", "V-230268", "RHEL 8 must require GRUB 2 bootloader password", "RHEL-08-010140"),
    ],
    "T1543": [
        ComplianceRef("DISA STIG RHEL 8", "V-230281", "RHEL 8 must disable Ctrl-Alt-Del burst action", "RHEL-08-040170"),
        ComplianceRef("DISA STIG RHEL 8", "V-230529", "RHEL 8 must disable Ctrl-Alt-Del reboot", "RHEL-08-040171"),
    ],
    "T1547": [
        ComplianceRef("DISA STIG RHEL 8", "V-230268", "RHEL 8 must set GRUB 2 bootloader password", "RHEL-08-010140"),
        ComplianceRef("DISA STIG RHEL 8", "V-230267", "RHEL 8 must configure bootloader permissions", "RHEL-08-010141"),
    ],
    "T1548": [
        ComplianceRef("DISA STIG RHEL 8", "V-230271", "RHEL 8 must require authentication for single-user mode", "RHEL-08-010151"),
        ComplianceRef("DISA STIG RHEL 8", "V-230478", "RHEL 8 must restrict SUID/SGID files", "RHEL-08-040002"),
    ],
    "T1550": [
        ComplianceRef("DISA STIG RHEL 8", "V-230527", "RHEL 8 must use MFA for remote access", "RHEL-08-040340"),
        ComplianceRef("DISA STIG RHEL 8", "V-230231", "RHEL 8 must implement DoD-approved encryption for SSH", "RHEL-08-010160"),
    ],
    "T1552": [
        ComplianceRef("DISA STIG RHEL 8", "V-230329", "RHEL 8 must protect credentials at rest", "RHEL-08-010120"),
        ComplianceRef("DISA STIG RHEL 8", "V-230342", "RHEL 8 must prohibit password reuse for 5 generations", "RHEL-08-020220"),
    ],
    "T1556": [
        ComplianceRef("DISA STIG RHEL 8", "V-230236", "RHEL 8 must use approved PAM modules", "RHEL-08-010190"),
        ComplianceRef("DISA STIG RHEL 8", "V-230356", "RHEL 8 must enforce password complexity via pam_pwquality", "RHEL-08-020100"),
    ],
    "T1558": [
        ComplianceRef("DISA STIG RHEL 8", "V-230223", "RHEL 8 must use FIPS-validated crypto for Kerberos", "RHEL-08-010030"),
    ],
    "T1562": [
        ComplianceRef("DISA STIG RHEL 8", "V-230234", "RHEL 8 must enforce SELinux targeted policy", "RHEL-08-010170"),
        ComplianceRef("DISA STIG RHEL 8", "V-230383", "RHEL 8 must enable auditd", "RHEL-08-030060"),
        ComplianceRef("DISA STIG RHEL 8", "V-230505", "RHEL 8 must enable firewalld", "RHEL-08-040090"),
        ComplianceRef("DISA STIG RHEL 8", "V-230395", "RHEL 8 must protect audit configuration", "RHEL-08-030170"),
    ],
    "T1574": [
        ComplianceRef("DISA STIG RHEL 8", "V-230478", "RHEL 8 must restrict world-writable directories", "RHEL-08-040002"),
        ComplianceRef("DISA STIG RHEL 8", "V-230264", "RHEL 8 must verify package integrity", "RHEL-08-010019"),
    ],
}


# ---------------------------------------------------------------------------
# ATT&CK → DISA STIG RHEL 9 mapping (V1R2+)
# ---------------------------------------------------------------------------

DISA_STIG_RHEL9: dict[str, list[ComplianceRef]] = {
    "T1003": [
        ComplianceRef("DISA STIG RHEL 9", "V-257791", "RHEL 9 must use SHA-512 or yescrypt for password hashing", "RHEL-09-611070"),
        ComplianceRef("DISA STIG RHEL 9", "V-257843", "RHEL 9 shadow file must be mode 0000", "RHEL-09-232035"),
        ComplianceRef("DISA STIG RHEL 9", "V-257844", "RHEL 9 shadow file must be owned by root", "RHEL-09-232040"),
    ],
    "T1021": [
        ComplianceRef("DISA STIG RHEL 9", "V-257982", "RHEL 9 must not permit root login via SSH", "RHEL-09-255040"),
        ComplianceRef("DISA STIG RHEL 9", "V-257985", "RHEL 9 SSH must use FIPS 140-3 compliant ciphers", "RHEL-09-255070"),
        ComplianceRef("DISA STIG RHEL 9", "V-257988", "RHEL 9 SSH must not allow empty passwords", "RHEL-09-255100"),
    ],
    "T1027": [
        ComplianceRef("DISA STIG RHEL 9", "V-257777", "RHEL 9 must enable FIPS mode", "RHEL-09-671010"),
        ComplianceRef("DISA STIG RHEL 9", "V-257778", "RHEL 9 must implement NIST FIPS-validated cryptography", "RHEL-09-671015"),
    ],
    "T1036": [
        ComplianceRef("DISA STIG RHEL 9", "V-257779", "RHEL 9 must validate RPM package signatures", "RHEL-09-214015"),
        ComplianceRef("DISA STIG RHEL 9", "V-257780", "RHEL 9 must verify all installed packages", "RHEL-09-214020"),
    ],
    "T1046": [
        ComplianceRef("DISA STIG RHEL 9", "V-258001", "RHEL 9 must enable firewalld", "RHEL-09-251010"),
        ComplianceRef("DISA STIG RHEL 9", "V-258002", "RHEL 9 must configure a firewall default deny policy", "RHEL-09-251015"),
    ],
    "T1053": [
        ComplianceRef("DISA STIG RHEL 9", "V-257845", "RHEL 9 must restrict cron to authorized users", "RHEL-09-232050"),
        ComplianceRef("DISA STIG RHEL 9", "V-257846", "RHEL 9 must restrict at to authorized users", "RHEL-09-232055"),
    ],
    "T1059": [
        ComplianceRef("DISA STIG RHEL 9", "V-257774", "RHEL 9 must enforce SELinux targeted policy", "RHEL-09-431010"),
        ComplianceRef("DISA STIG RHEL 9", "V-257775", "RHEL 9 must be in SELinux enforcing mode", "RHEL-09-431015"),
    ],
    "T1068": [
        ComplianceRef("DISA STIG RHEL 9", "V-257776", "RHEL 9 must apply vendor-supported security patches", "RHEL-09-211010"),
        ComplianceRef("DISA STIG RHEL 9", "V-257958", "RHEL 9 must enable kernel address space layout randomization", "RHEL-09-213010"),
    ],
    "T1070": [
        ComplianceRef("DISA STIG RHEL 9", "V-257895", "RHEL 9 audit logs must be owned by root", "RHEL-09-653010"),
        ComplianceRef("DISA STIG RHEL 9", "V-257896", "RHEL 9 audit logs must have mode 0600 or less permissive", "RHEL-09-653015"),
        ComplianceRef("DISA STIG RHEL 9", "V-257897", "RHEL 9 audit log directory must be 0700", "RHEL-09-653020"),
    ],
    "T1078": [
        ComplianceRef("DISA STIG RHEL 9", "V-257847", "RHEL 9 must disable accounts after 35 days of inactivity", "RHEL-09-611160"),
        ComplianceRef("DISA STIG RHEL 9", "V-257849", "RHEL 9 must set expiration on temporary accounts", "RHEL-09-611175"),
    ],
    "T1082": [
        ComplianceRef("DISA STIG RHEL 9", "V-257770", "RHEL 9 must display a DoD-approved login banner", "RHEL-09-271010"),
        ComplianceRef("DISA STIG RHEL 9", "V-257776", "RHEL 9 must be a vendor-supported release", "RHEL-09-211010"),
    ],
    "T1087": [
        ComplianceRef("DISA STIG RHEL 9", "V-257850", "RHEL 9 must ensure only root has UID 0", "RHEL-09-411010"),
        ComplianceRef("DISA STIG RHEL 9", "V-257851", "RHEL 9 must not have unnecessary accounts", "RHEL-09-411015"),
    ],
    "T1098": [
        ComplianceRef("DISA STIG RHEL 9", "V-257852", "RHEL 9 must audit account modification", "RHEL-09-654010"),
    ],
    "T1110": [
        ComplianceRef("DISA STIG RHEL 9", "V-257793", "RHEL 9 must lock accounts after 3 failed attempts", "RHEL-09-411075"),
        ComplianceRef("DISA STIG RHEL 9", "V-257794", "RHEL 9 must enforce 15-character minimum password length", "RHEL-09-611010"),
        ComplianceRef("DISA STIG RHEL 9", "V-257795", "RHEL 9 must enforce password complexity", "RHEL-09-611020"),
        ComplianceRef("DISA STIG RHEL 9", "V-257796", "RHEL 9 must enforce 60-day maximum password lifetime", "RHEL-09-611030"),
    ],
    "T1133": [
        ComplianceRef("DISA STIG RHEL 9", "V-257982", "RHEL 9 must not permit root login via SSH", "RHEL-09-255040"),
        ComplianceRef("DISA STIG RHEL 9", "V-258004", "RHEL 9 must restrict SSH access", "RHEL-09-255050"),
    ],
    "T1136": [
        ComplianceRef("DISA STIG RHEL 9", "V-257853", "RHEL 9 must audit account creation", "RHEL-09-654015"),
        ComplianceRef("DISA STIG RHEL 9", "V-257850", "RHEL 9 must not allow duplicate UIDs", "RHEL-09-411010"),
    ],
    "T1190": [
        ComplianceRef("DISA STIG RHEL 9", "V-257776", "RHEL 9 must apply security patches", "RHEL-09-211010"),
        ComplianceRef("DISA STIG RHEL 9", "V-257779", "RHEL 9 must verify GPG signatures", "RHEL-09-214015"),
    ],
    "T1195": [
        ComplianceRef("DISA STIG RHEL 9", "V-257779", "RHEL 9 must validate GPG signatures for packages", "RHEL-09-214015"),
        ComplianceRef("DISA STIG RHEL 9", "V-257780", "RHEL 9 must verify all installed packages", "RHEL-09-214020"),
        ComplianceRef("DISA STIG RHEL 9", "V-257781", "RHEL 9 must enable gpgcheck for all repos", "RHEL-09-214025"),
    ],
    "T1485": [
        ComplianceRef("DISA STIG RHEL 9", "V-257895", "RHEL 9 must protect critical data from destruction", "RHEL-09-653010"),
    ],
    "T1489": [
        ComplianceRef("DISA STIG RHEL 9", "V-258001", "RHEL 9 must enable firewalld to protect services", "RHEL-09-251010"),
    ],
    "T1490": [
        ComplianceRef("DISA STIG RHEL 9", "V-257771", "RHEL 9 must require bootloader password", "RHEL-09-212010"),
    ],
    "T1543": [
        ComplianceRef("DISA STIG RHEL 9", "V-257959", "RHEL 9 must disable Ctrl-Alt-Del reboot activation", "RHEL-09-211045"),
        ComplianceRef("DISA STIG RHEL 9", "V-257960", "RHEL 9 must disable Ctrl-Alt-Del burst action", "RHEL-09-211050"),
    ],
    "T1547": [
        ComplianceRef("DISA STIG RHEL 9", "V-257771", "RHEL 9 must set bootloader password", "RHEL-09-212010"),
        ComplianceRef("DISA STIG RHEL 9", "V-257772", "RHEL 9 must configure bootloader permissions", "RHEL-09-212015"),
    ],
    "T1548": [
        ComplianceRef("DISA STIG RHEL 9", "V-257773", "RHEL 9 must require auth for single-user mode", "RHEL-09-212020"),
        ComplianceRef("DISA STIG RHEL 9", "V-257961", "RHEL 9 must restrict SUID/SGID files", "RHEL-09-232010"),
    ],
    "T1550": [
        ComplianceRef("DISA STIG RHEL 9", "V-258004", "RHEL 9 must use MFA for remote access", "RHEL-09-255050"),
        ComplianceRef("DISA STIG RHEL 9", "V-257985", "RHEL 9 SSH must use FIPS 140-3 compliant crypto", "RHEL-09-255070"),
    ],
    "T1552": [
        ComplianceRef("DISA STIG RHEL 9", "V-257843", "RHEL 9 must protect credential files", "RHEL-09-232035"),
        ComplianceRef("DISA STIG RHEL 9", "V-257797", "RHEL 9 must prohibit password reuse for 5 generations", "RHEL-09-611040"),
    ],
    "T1556": [
        ComplianceRef("DISA STIG RHEL 9", "V-257798", "RHEL 9 must use approved PAM modules", "RHEL-09-611050"),
        ComplianceRef("DISA STIG RHEL 9", "V-257791", "RHEL 9 must use SHA-512 or yescrypt for hashing", "RHEL-09-611070"),
    ],
    "T1558": [
        ComplianceRef("DISA STIG RHEL 9", "V-257777", "RHEL 9 must use FIPS-validated crypto for Kerberos", "RHEL-09-671010"),
    ],
    "T1562": [
        ComplianceRef("DISA STIG RHEL 9", "V-257774", "RHEL 9 must enforce SELinux targeted policy", "RHEL-09-431010"),
        ComplianceRef("DISA STIG RHEL 9", "V-257893", "RHEL 9 must enable auditd", "RHEL-09-651010"),
        ComplianceRef("DISA STIG RHEL 9", "V-258001", "RHEL 9 must enable firewalld", "RHEL-09-251010"),
        ComplianceRef("DISA STIG RHEL 9", "V-257894", "RHEL 9 must protect audit config from modification", "RHEL-09-653005"),
    ],
    "T1574": [
        ComplianceRef("DISA STIG RHEL 9", "V-257961", "RHEL 9 must restrict world-writable directories", "RHEL-09-232010"),
        ComplianceRef("DISA STIG RHEL 9", "V-257779", "RHEL 9 must verify package integrity", "RHEL-09-214015"),
    ],
}


class ComplianceMapper:
    """Maps scan results to compliance framework controls."""

    def get_refs(self, technique_id: str) -> list[ComplianceRef]:
        """Get all compliance references for a technique."""
        # Strip sub-technique (T1021.004 → T1021)
        base_id = technique_id.split(".")[0]

        refs: list[ComplianceRef] = []
        refs.extend(CIS_CONTROLS.get(base_id, []))
        refs.extend(NIST_CONTROLS.get(base_id, []))
        refs.extend(CIS_RHEL_BENCHMARK.get(base_id, []))
        refs.extend(DISA_STIG_RHEL8.get(base_id, []))
        refs.extend(DISA_STIG_RHEL9.get(base_id, []))
        return refs

    def get_refs_by_framework(self, technique_id: str) -> dict[str, list[ComplianceRef]]:
        """Get compliance references grouped by framework."""
        refs = self.get_refs(technique_id)
        grouped: dict[str, list[ComplianceRef]] = {}
        for ref in refs:
            grouped.setdefault(ref.framework, []).append(ref)
        return grouped

    def enrich_result(self, result: ModuleResult) -> dict[str, Any]:
        """Enrich a ModuleResult with compliance references."""
        refs = self.get_refs_by_framework(result.technique_id)
        return {
            "result": result,
            "compliance": refs,
            "has_compliance": bool(refs),
        }

    def enrich_scan(self, scan_result: ScanResult) -> list[dict[str, Any]]:
        """Enrich all results in a scan with compliance data."""
        return [self.enrich_result(r) for r in scan_result.results]

    def get_compliance_summary(self, scan_result: ScanResult) -> dict[str, dict[str, int]]:
        """Generate a summary of compliance control coverage.

        Returns a dict of framework → { "total": N, "violated": M, "controls": set }.
        """
        summary: dict[str, dict[str, Any]] = {}

        for result in scan_result.results:
            refs = self.get_refs(result.technique_id)
            for ref in refs:
                fw = ref.framework
                if fw not in summary:
                    summary[fw] = {"total_controls": set(), "violated_controls": set()}
                summary[fw]["total_controls"].add(ref.control_id)
                if result.is_vulnerable:
                    summary[fw]["violated_controls"].add(ref.control_id)

        # Convert sets to counts
        return {
            fw: {
                "total": len(data["total_controls"]),
                "violated": len(data["violated_controls"]),
                "compliant": len(data["total_controls"]) - len(data["violated_controls"]),
            }
            for fw, data in summary.items()
        }

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

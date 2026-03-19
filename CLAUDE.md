# CLAUDE.md — RHEL Red Teaming Tool

## Project Overview

An open-source Python-based active scanning tool for red team security testing on Red Hat Enterprise
Linux systems, aligned with the MITRE ATT&CK Framework (Linux Enterprise matrix). The tool tests
security controls across RHEL 8 and RHEL 9.

**Repository**: https://github.com/Krishcalin/RHEL-Red-Teaming
**License**: MIT
**Python**: 3.10+
**ATT&CK Matrix**: https://attack.mitre.org/matrices/enterprise/linux/
**Current Phase**: Phase 2 (Discovery Modules) — Complete

---

## Architecture

### Directory Structure

```
RHEL-Red-Teaming/
├── config/                        # Configuration files
│   ├── settings.yaml              # Global config (targets, credentials, scope)
│   ├── techniques.yaml            # Enable/disable specific ATT&CK techniques
│   └── profiles/                  # Scan profiles
│       ├── quick.yaml             # Fast top-priority checks
│       ├── full.yaml              # All modules, all tactics
│       └── stealth.yaml           # Low-noise, slower cadence
├── core/                          # Core engine components
│   ├── __init__.py
│   ├── engine.py                  # Main orchestrator — loads modules, runs scans
│   ├── session.py                 # Target session management (SSH/local)
│   ├── logger.py                  # Structured logging + evidence chain
│   ├── reporter.py                # Report generation (HTML/JSON/CSV)
│   ├── mitre_mapper.py            # Maps results → ATT&CK Navigator JSON layers
│   └── models.py                  # Data models (ModuleResult, Finding, Target)
├── modules/                       # One package per MITRE ATT&CK tactic
│   ├── __init__.py
│   ├── base.py                    # Abstract BaseModule class (all modules inherit)
│   ├── initial_access/            # TA0001 — 10 techniques
│   ├── execution/                 # TA0002 — 10 techniques
│   ├── persistence/               # TA0003 — 18 techniques
│   ├── privilege_escalation/      # TA0004 — 12 techniques
│   ├── defense_evasion/           # TA0005 — 26 techniques
│   ├── credential_access/         # TA0006 — 15 techniques
│   ├── discovery/                 # TA0007 — 26 techniques
│   ├── lateral_movement/          # TA0008 — 8 techniques
│   ├── collection/                # TA0009 — 14 techniques
│   ├── command_and_control/       # TA0011 — 18 techniques
│   ├── exfiltration/              # TA0010 — 8 techniques
│   └── impact/                    # TA0040 — 15 techniques
├── templates/                     # Jinja2 report templates
│   └── report.html
├── reports/                       # Generated report output (gitignored)
├── evidence/                      # Collected artifacts (gitignored)
├── tests/                         # pytest tests
│   ├── conftest.py
│   ├── test_engine.py
│   ├── test_session.py
│   └── test_modules/
├── main.py                        # CLI entry point (click-based)
├── pyproject.toml                 # Project metadata + dependencies
├── requirements.txt               # Pinned dependencies
├── CLAUDE.md                      # This file
└── README.md
```

### Core Design Principles

1. **Module-per-technique** — each ATT&CK technique is a self-contained Python module
2. **Safe by default** — `check()` mode is passive/read-only; `simulate()` requires explicit `--simulate` flag
3. **OS-aware** — modules declare `SUPPORTED_OS` (rhel8, rhel9) and auto-skip unsupported targets
4. **Auto-discovery** — engine discovers modules by scanning `modules/` packages at runtime
5. **Evidence chain** — every action logged with timestamp, target, technique ID, result

### BaseModule Contract

All technique modules inherit from `modules/base.py:BaseModule` and must implement:

- `check(session) -> ModuleResult` — passive detection (read-only, no system changes)
- `simulate(session) -> ModuleResult` — active simulation (requires --simulate flag)
- `cleanup(session)` — revert any changes made during simulate
- `get_mitigations() -> list[str]` — recommended remediations

Required class attributes: `TECHNIQUE_ID`, `TECHNIQUE_NAME`, `TACTIC`, `SEVERITY`,
`SUPPORTED_OS`, `REQUIRES_ROOT`, `SAFE_MODE`.

### Session Management

- **Local**: Direct execution via `subprocess`, `os`, `ctypes`
- **Remote SSH**: Via `paramiko` — command execution, file transfer, tunneling
- **Remote SSH+sudo**: Elevated execution over SSH for privileged checks

---

## Complete MITRE ATT&CK Linux Matrix Coverage

### Initial Access — TA0001 (10 techniques)

| Technique | Sub-technique | ID | Module File | Check Description |
|-----------|--------------|-----|-------------|-------------------|
| Content Injection | — | T1659 | `T1659_content_injection.py` | Check for injectable web content served by the host |
| Drive-by Compromise | — | T1189 | `T1189_driveby_compromise.py` | Audit exposed web services for drive-by vectors |
| Exploit Public-Facing Application | — | T1190 | `T1190_exploit_public_app.py` | Scan for known CVEs in exposed services (Apache, Nginx, etc.) |
| External Remote Services | — | T1133 | `T1133_external_remote_services.py` | Audit SSH, VPN, RDP exposure and config |
| Hardware Additions | — | T1200 | `T1200_hardware_additions.py` | Check USB device policies, udev rules |
| Phishing | Spearphishing Attachment | T1566.001 | `T1566_phishing.py` | Mail server config, attachment filtering |
| Phishing | Spearphishing Link | T1566.002 | — | URL filtering policies |
| Phishing | Spearphishing via Service | T1566.003 | — | Third-party service exposure |
| Phishing | Spearphishing Voice | T1566.004 | — | VoIP service exposure |
| Supply Chain Compromise | Software Dependencies | T1195.001 | `T1195_supply_chain.py` | Package repo integrity, GPG verification |
| Supply Chain Compromise | Software Supply Chain | T1195.002 | — | Third-party repo audit |
| Supply Chain Compromise | Hardware Supply Chain | T1195.003 | — | Hardware attestation checks |
| Trusted Relationship | — | T1199 | `T1199_trusted_relationship.py` | Trust relationships, SSH keys, NFS exports |
| Valid Accounts | Default Accounts | T1078.001 | `T1078_valid_accounts.py` | Default/vendor accounts still active |
| Valid Accounts | Domain Accounts | T1078.002 | — | SSSD/IPA/LDAP account enumeration |
| Valid Accounts | Local Accounts | T1078.003 | — | Local account password policy audit |
| Wi-Fi Networks | — | T1669 | `T1669_wifi_networks.py` | Wireless interface exposure, WPA config |

### Execution — TA0002 (10 techniques)

| Technique | Sub-technique | ID | Module File | Check Description |
|-----------|--------------|-----|-------------|-------------------|
| Command and Scripting Interpreter | Unix Shell | T1059.004 | `T1059_command_scripting.py` | Shell restrictions (rbash), chsh controls |
| Command and Scripting Interpreter | Python | T1059.006 | — | Python availability, restricted execution |
| Command and Scripting Interpreter | JavaScript | T1059.007 | — | Node.js availability and restrictions |
| Command and Scripting Interpreter | Lua | T1059.011 | — | Lua interpreter availability |
| Command and Scripting Interpreter | Visual Basic | T1059.005 | — | Mono/VB runtime availability |
| Exploitation for Client Execution | — | T1203 | `T1203_exploitation_client.py` | Client app CVE exposure (browsers, readers) |
| Input Injection | — | T1674 | `T1674_input_injection.py` | X11/Wayland input injection feasibility |
| Inter-Process Communication | — | T1559 | `T1559_ipc.py` | D-Bus policy, shared memory permissions |
| Native API | — | T1106 | `T1106_native_api.py` | Syscall filtering (seccomp), ptrace scope |
| Scheduled Task/Job | At | T1053.002 | `T1053_scheduled_tasks.py` | `at` daemon status, pending jobs |
| Scheduled Task/Job | Cron | T1053.003 | — | User crontabs, `/etc/cron.*`, anacron |
| Scheduled Task/Job | Systemd Timers | T1053.006 | — | Writable timer units, user timers |
| Shared Modules | — | T1129 | `T1129_shared_modules.py` | Shared library loading policy (ldconfig) |
| Software Deployment Tools | — | T1072 | `T1072_software_deployment.py` | Ansible, Puppet, Salt agent exposure |
| System Services | Systemctl | T1569.003 | `T1569_system_services.py` | Systemctl access, service start/stop perms |
| User Execution | Malicious File | T1204.002 | `T1204_user_execution.py` | Executable file in world-writable dirs |
| User Execution | Malicious Library | T1204.005 | — | LD_PRELOAD exploitability |

### Persistence — TA0003 (18 techniques)

| Technique | Sub-technique | ID | Module File | Check Description |
|-----------|--------------|-----|-------------|-------------------|
| Account Manipulation | SSH Authorized Keys | T1098.004 | `T1098_account_manipulation.py` | Unauthorized SSH keys, key permissions |
| Account Manipulation | Additional Groups | T1098.007 | — | Group membership changes, wheel/sudo |
| Boot/Logon Autostart | Kernel Modules | T1547.006 | `T1547_boot_autostart.py` | Unsigned kernel modules, modprobe.d |
| Boot/Logon Autostart | XDG Autostart | T1547.013 | — | XDG autostart entries in user dirs |
| Boot/Logon Init Scripts | RC Scripts | T1037.004 | `T1037_init_scripts.py` | Legacy rc.local, init.d scripts |
| Compromise Host Software Binary | — | T1554 | `T1554_compromise_binary.py` | Binary integrity (rpm -Va), trojanized bins |
| Create Account | Local Account | T1136.001 | `T1136_create_account.py` | Account creation feasibility, useradd perms |
| Create Account | Domain Account | T1136.002 | — | IPA/LDAP account creation controls |
| Create/Modify System Process | Systemd Service | T1543.002 | `T1543_systemd_service.py` | Writable unit files, user service dirs |
| Event Triggered Execution | Shell Config Modification | T1546.004 | `T1546_event_triggered.py` | `.bashrc`/`.profile` injection vectors |
| Event Triggered Execution | Trap | T1546.005 | — | Shell trap command persistence |
| Event Triggered Execution | Installer Packages | T1546.016 | — | RPM scriptlet abuse (pre/post scripts) |
| Event Triggered Execution | Udev Rules | T1546.017 | — | Writable udev rules, device triggers |
| Event Triggered Execution | Python Startup Hooks | T1546.018 | — | PYTHONSTARTUP, sitecustomize.py |
| Exclusive Control | — | T1668 | `T1668_exclusive_control.py` | Lock file manipulation, PID file abuse |
| External Remote Services | — | T1133 | `T1133_external_remote_services.py` | SSH, VPN, remote access persistence |
| Hijack Execution Flow | Dynamic Linker Hijacking | T1574.006 | `T1574_hijack_execution.py` | `LD_PRELOAD`, `ld.so.preload`, `RPATH` |
| Hijack Execution Flow | PATH Variable | T1574.007 | — | PATH manipulation, writable PATH dirs |
| Modify Auth Process | PAM | T1556.003 | `T1556_modify_auth.py` | PAM module stack integrity |
| Modify Auth Process | MFA | T1556.006 | — | MFA bypass vectors |
| Power Settings | — | T1653 | `T1653_power_settings.py` | Wake-on-LAN, ACPI, suspend policy |
| Pre-OS Boot | Component Firmware | T1542.002 | `T1542_pre_os_boot.py` | UEFI Secure Boot status, firmware updates |
| Pre-OS Boot | Bootkit | T1542.003 | — | Boot loader integrity (GRUB2) |
| Server Software Component | Web Shell | T1505.003 | `T1505_server_component.py` | Web shell detection in document roots |
| Server Software Component | SQL Stored Procedures | T1505.001 | — | Database stored procedure audit |
| Software Extensions | Browser Extensions | T1176.001 | `T1176_software_extensions.py` | Browser extension inventory |
| Software Extensions | IDE Extensions | T1176.002 | — | IDE plugin audit |
| Traffic Signaling | Port Knocking | T1205.001 | `T1205_traffic_signaling.py` | Port knocking service detection |
| Traffic Signaling | Socket Filters | T1205.002 | — | BPF/socket filter audit |

### Privilege Escalation — TA0004 (12 techniques)

| Technique | Sub-technique | ID | Module File | Check Description |
|-----------|--------------|-----|-------------|-------------------|
| Abuse Elevation Control | Setuid/Setgid | T1548.001 | `T1548_elevation_control.py` | SUID/SGID binary audit vs CIS baseline |
| Abuse Elevation Control | Sudo/Sudo Caching | T1548.003 | — | `sudoers` NOPASSWD, wildcard abuse, timestamp |
| Account Manipulation | SSH Authorized Keys | T1098.004 | `T1098_account_manipulation.py` | Key-based privilege escalation |
| Account Manipulation | Additional Groups | T1098.007 | — | Unauthorized group additions |
| Boot/Logon Autostart | Kernel Modules | T1547.006 | `T1547_boot_autostart.py` | Kernel module loading as root |
| Boot/Logon Autostart | XDG Autostart | T1547.013 | — | Autostart escalation vectors |
| Boot/Logon Init Scripts | RC Scripts | T1037.004 | `T1037_init_scripts.py` | Init script writable by non-root |
| Create/Modify System Process | Systemd Service | T1543.002 | `T1543_systemd_service.py` | Service file privilege escalation |
| Escape to Host | — | T1611 | `T1611_escape_to_host.py` | Container escape (Podman/Docker) |
| Event Triggered Execution | Shell Config | T1546.004 | `T1546_event_triggered.py` | Profile script privilege escalation |
| Event Triggered Execution | Trap | T1546.005 | — | Trap-based escalation |
| Event Triggered Execution | Udev Rules | T1546.017 | — | Udev rule escalation (root execution) |
| Event Triggered Execution | Python Hooks | T1546.018 | — | Python startup hook escalation |
| Exploitation for Privilege Escalation | — | T1068 | `T1068_exploitation_privesc.py` | Kernel CVE checks, exploit availability |
| Hijack Execution Flow | Dynamic Linker | T1574.006 | `T1574_hijack_execution.py` | LD_PRELOAD privilege escalation |
| Hijack Execution Flow | PATH Variable | T1574.007 | — | PATH-based binary hijacking |
| Process Injection | Ptrace System Calls | T1055.008 | `T1055_process_injection.py` | ptrace_scope, YAMA LSM settings |
| Process Injection | Proc Memory | T1055.009 | — | `/proc/[pid]/mem` access controls |
| Process Injection | VDSO Hijacking | T1055.014 | — | VDSO exploitation feasibility |
| Scheduled Task/Job | At | T1053.002 | `T1053_scheduled_tasks.py` | `at` access controls |
| Scheduled Task/Job | Cron | T1053.003 | — | Cron-based privilege escalation |
| Scheduled Task/Job | Systemd Timers | T1053.006 | — | Timer unit privilege escalation |
| Valid Accounts | Default Accounts | T1078.001 | `T1078_valid_accounts.py` | Default privileged accounts |
| Valid Accounts | Domain Accounts | T1078.002 | — | Domain admin account exposure |
| Valid Accounts | Local Accounts | T1078.003 | — | Local privileged account audit |

### Defense Evasion — TA0005 (26 techniques)

| Technique | Sub-technique | ID | Module File | Check Description |
|-----------|--------------|-----|-------------|-------------------|
| Debugger Evasion | — | T1622 | `T1622_debugger_evasion.py` | Anti-debug technique detection |
| Delay Execution | — | T1678 | `T1678_delay_execution.py` | Sleep/timer-based execution delay vectors |
| Deobfuscate/Decode Files | — | T1140 | `T1140_deobfuscate.py` | Base64/XOR decode tool availability |
| Execution Guardrails | Environmental Keying | T1480.001 | `T1480_execution_guardrails.py` | Environment-specific execution checks |
| Execution Guardrails | Mutual Exclusion | T1480.002 | — | Mutex/lock-based guardrails |
| Exploitation for Defense Evasion | — | T1211 | `T1211_exploit_defense_evasion.py` | Security tool bypass CVEs |
| File/Dir Permissions Modification | Linux Perms | T1222.002 | `T1222_permissions_modification.py` | World-writable dirs, sticky bit, umask |
| Hide Artifacts | Hidden Files/Dirs | T1564.001 | `T1564_hide_artifacts.py` | Dot-file abuse, hidden directories |
| Hide Artifacts | Hidden Users | T1564.002 | — | UID manipulation, /etc/passwd hiding |
| Hide Artifacts | Hidden File System | T1564.005 | — | Loopback mounts, hidden partitions |
| Hide Artifacts | Run Virtual Instance | T1564.006 | — | Hidden VM/container detection |
| Hide Artifacts | Ignore Process Interrupts | T1564.011 | — | Signal masking, nohup abuse |
| Hide Artifacts | File/Path Exclusions | T1564.012 | — | AV/scanner exclusion paths |
| Hide Artifacts | Bind Mounts | T1564.013 | — | Bind mount overlay attacks |
| Hide Artifacts | Extended Attributes | T1564.014 | — | xattr-based data hiding |
| Hijack Execution Flow | Dynamic Linker | T1574.006 | `T1574_hijack_execution.py` | LD_PRELOAD evasion |
| Hijack Execution Flow | PATH Variable | T1574.007 | — | PATH manipulation for evasion |
| Impair Defenses | Disable/Modify Tools | T1562.001 | `T1562_impair_defenses.py` | SELinux, auditd, AV status |
| Impair Defenses | Impair Command History | T1562.003 | — | HISTFILE, HISTSIZE manipulation |
| Impair Defenses | Disable System Firewall | T1562.004 | — | Firewalld/iptables/nftables disable |
| Impair Defenses | Indicator Blocking | T1562.006 | — | Log forwarding disruption |
| Impair Defenses | Downgrade Attack | T1562.010 | — | Crypto policy downgrade, TLS fallback |
| Impair Defenses | Spoof Security Alerting | T1562.011 | — | Alert suppression/spoofing |
| Impair Defenses | Disable Linux Audit System | T1562.012 | — | auditd kill, rule flushing |
| Indicator Removal | Clear Linux Logs | T1070.002 | `T1070_indicator_removal.py` | `/var/log` permissions, log rotation |
| Indicator Removal | Clear Command History | T1070.003 | — | History file deletion/truncation |
| Indicator Removal | File Deletion | T1070.004 | — | `shred`, secure delete availability |
| Indicator Removal | Timestomp | T1070.006 | — | `touch` timestamp manipulation |
| Indicator Removal | Clear Network History | T1070.007 | — | Network config/connection log clearing |
| Indicator Removal | Clear Persistence | T1070.009 | — | Persistence artifact cleanup |
| Indicator Removal | Relocate Malware | T1070.010 | — | Binary relocation detection |
| Masquerading | Rename Utilities | T1036.003 | `T1036_masquerading.py` | Binary name spoofing detection |
| Masquerading | Masquerade Task/Service | T1036.004 | — | Service name impersonation |
| Masquerading | Match Legitimate Name | T1036.005 | — | Legitimate binary name mimicry |
| Masquerading | Space After Filename | T1036.006 | — | Trailing space filename abuse |
| Masquerading | Masquerade File Type | T1036.008 | — | Extension spoofing |
| Masquerading | Break Process Trees | T1036.009 | — | Double-fork, setsid process hiding |
| Masquerading | Overwrite Process Args | T1036.011 | — | `/proc/[pid]/cmdline` manipulation |
| Modify Auth Process | PAM | T1556.003 | `T1556_modify_auth.py` | PAM backdoor detection |
| Modify Auth Process | MFA | T1556.006 | — | MFA bypass vectors |
| Obfuscated Files | Binary Padding | T1027.001 | `T1027_obfuscated_files.py` | Padded binary detection |
| Obfuscated Files | Software Packing | T1027.002 | — | UPX/packed ELF detection |
| Obfuscated Files | Compile After Delivery | T1027.004 | — | gcc/make availability for compilation |
| Obfuscated Files | Command Obfuscation | T1027.010 | — | Bash obfuscation techniques |
| Obfuscated Files | Fileless Storage | T1027.011 | — | memfd_create, /dev/shm abuse |
| Obfuscated Files | Encrypted/Encoded File | T1027.013 | — | Encrypted payload detection |
| Pre-OS Boot | Component Firmware | T1542.002 | `T1542_pre_os_boot.py` | Firmware integrity checks |
| Pre-OS Boot | Bootkit | T1542.003 | — | GRUB2/boot loader integrity |
| Process Injection | Ptrace | T1055.008 | `T1055_process_injection.py` | ptrace_scope, YAMA LSM |
| Process Injection | Proc Memory | T1055.009 | — | /proc/[pid]/mem protections |
| Process Injection | VDSO Hijacking | T1055.014 | — | VDSO exploitation checks |
| Reflective Code Loading | — | T1620 | `T1620_reflective_loading.py` | memfd_create, dlopen from memory |
| Rootkit | — | T1014 | `T1014_rootkit.py` | Rootkit detection (chkrootkit, rkhunter) |
| Subvert Trust Controls | Install Root Cert | T1553.004 | `T1553_subvert_trust.py` | CA certificate store audit |
| System Binary Proxy Execution | Electron Apps | T1218.015 | `T1218_proxy_execution.py` | Electron app abuse vectors |
| Traffic Signaling | Port Knocking | T1205.001 | `T1205_traffic_signaling.py` | Port knocking detection |
| Traffic Signaling | Socket Filters | T1205.002 | — | BPF filter audit |
| Valid Accounts | Default/Domain/Local | T1078 | `T1078_valid_accounts.py` | Account policy audit |
| Virtualization/Sandbox Evasion | System/Time Checks | T1497 | `T1497_sandbox_evasion.py` | VM/sandbox detection techniques |

### Credential Access — TA0006 (15 techniques)

| Technique | Sub-technique | ID | Module File | Check Description |
|-----------|--------------|-----|-------------|-------------------|
| Adversary-in-the-Middle | ARP Cache Poisoning | T1557.002 | `T1557_aitm.py` | ARP spoofing feasibility, arpwatch |
| Adversary-in-the-Middle | DHCP Spoofing | T1557.003 | — | DHCP snooping, rogue DHCP detection |
| Brute Force | Password Guessing | T1110.001 | `T1110_brute_force.py` | PAM faillock config, account lockout |
| Brute Force | Password Cracking | T1110.002 | — | Password hash algorithm strength |
| Brute Force | Password Spraying | T1110.003 | — | Rate limiting, account lockout policy |
| Brute Force | Credential Stuffing | T1110.004 | — | Multi-service auth policy |
| Credentials from Password Stores | Web Browsers | T1555.003 | `T1555_credential_stores.py` | Browser credential storage audit |
| Credentials from Password Stores | Password Managers | T1555.005 | — | Password manager agent exposure |
| Exploitation for Credential Access | — | T1212 | `T1212_exploit_cred_access.py` | Auth service CVE checks |
| Forge Web Credentials | Web Cookies | T1606.001 | `T1606_forge_credentials.py` | Cookie security flags, session management |
| Input Capture | Keylogging | T1056.001 | `T1056_input_capture.py` | Keylogger feasibility, X11/evdev access |
| Input Capture | Credential API Hooking | T1056.004 | — | LD_PRELOAD credential interception |
| Modify Auth Process | PAM | T1556.003 | `T1556_modify_auth.py` | PAM module integrity audit |
| Modify Auth Process | MFA | T1556.006 | — | MFA bypass vectors |
| MFA Interception | — | T1111 | `T1111_mfa_interception.py` | MFA token interception feasibility |
| MFA Request Generation | — | T1621 | `T1621_mfa_request_gen.py` | MFA fatigue/push spam feasibility |
| Network Sniffing | — | T1040 | `T1040_network_sniffing.py` | Promiscuous mode, tcpdump/tshark access |
| OS Credential Dumping | Cached Domain Creds | T1003.005 | `T1003_credential_dumping.py` | SSSD cache, Kerberos ticket cache |
| OS Credential Dumping | Proc Filesystem | T1003.007 | — | `/proc/[pid]/maps` credential exposure |
| OS Credential Dumping | /etc/passwd and /etc/shadow | T1003.008 | — | Shadow file access controls |
| Steal/Forge Auth Certificates | — | T1649 | `T1649_auth_certificates.py` | PKI certificate store, private key perms |
| Steal/Forge Kerberos Tickets | Ccache Files | T1558.005 | `T1558_kerberos_tickets.py` | Kerberos ccache file permissions |
| Steal Web Session Cookie | — | T1539 | `T1539_web_session_cookie.py` | Browser cookie extraction feasibility |
| Unsecured Credentials | In Files | T1552.001 | `T1552_unsecured_credentials.py` | Config files with plaintext credentials |
| Unsecured Credentials | Shell History | T1552.003 | — | Bash/Zsh history credential leakage |
| Unsecured Credentials | Private Keys | T1552.004 | — | SSH keys with weak permissions |

### Discovery — TA0007 (26 techniques)

| Technique | Sub-technique | ID | Module File | Check Description |
|-----------|--------------|-----|-------------|-------------------|
| Account Discovery | Local Account | T1087.001 | `T1087_account_discovery.py` | `/etc/passwd`, `getent passwd` |
| Account Discovery | Domain Account | T1087.002 | — | SSSD/IPA/LDAP enumeration |
| Application Window Discovery | — | T1010 | `T1010_window_discovery.py` | X11/Wayland window enumeration |
| Browser Information Discovery | — | T1217 | `T1217_browser_discovery.py` | Browser history, bookmarks, profiles |
| Debugger Evasion | — | T1622 | `T1622_debugger_evasion.py` | Anti-debug technique audit |
| Device Driver Discovery | — | T1652 | `T1652_driver_discovery.py` | `lsmod`, `/sys/module` enumeration |
| File and Directory Discovery | — | T1083 | `T1083_file_discovery.py` | Sensitive file enumeration |
| Local Storage Discovery | — | T1680 | `T1680_local_storage.py` | Browser local storage, app data |
| Log Enumeration | — | T1654 | `T1654_log_enumeration.py` | Log file access, journald permissions |
| Network Service Discovery | — | T1046 | `T1046_network_service_discovery.py` | `ss`, `nmap`, open port scanning |
| Network Share Discovery | — | T1135 | `T1135_network_share.py` | NFS exports, Samba shares |
| Network Sniffing | — | T1040 | `T1040_network_sniffing.py` | Sniffing capability audit |
| Password Policy Discovery | — | T1201 | `T1201_password_policy.py` | PAM policy, pwquality.conf, aging |
| Peripheral Device Discovery | — | T1120 | `T1120_peripheral_discovery.py` | USB, PCI, serial device enumeration |
| Permission Groups Discovery | Local Groups | T1069.001 | `T1069_permission_groups.py` | `/etc/group`, wheel, sudo groups |
| Permission Groups Discovery | Domain Groups | T1069.002 | — | IPA/LDAP group enumeration |
| Process Discovery | — | T1057 | `T1057_process_discovery.py` | `/proc`, `ps`, process enumeration |
| Remote System Discovery | — | T1018 | `T1018_remote_system_discovery.py` | ARP cache, DNS, network scanning |
| Software Discovery | Security Software | T1518.001 | `T1518_software_discovery.py` | AV/EDR/IDS detection |
| Software Discovery | Backup Software | T1518.002 | — | Backup agent enumeration |
| System Information Discovery | — | T1082 | `T1082_system_info.py` | `uname`, `/etc/os-release`, kernel, hardware |
| System Language Discovery | — | T1614.001 | `T1614_language_discovery.py` | Locale settings, language packs |
| System Network Config Discovery | — | T1016 | `T1016_network_config.py` | `ip addr`, routes, DNS, resolv.conf |
| System Network Config Discovery | Internet Connection | T1016.001 | — | Internet connectivity check |
| System Network Config Discovery | Wi-Fi Discovery | T1016.002 | — | Wireless interface enumeration |
| System Network Connections | — | T1049 | `T1049_network_connections.py` | `ss -tulnp`, established connections |
| System Owner/User Discovery | — | T1033 | `T1033_owner_discovery.py` | `whoami`, `id`, logged-in users |
| System Service Discovery | — | T1007 | `T1007_service_discovery.py` | `systemctl list-units`, service enum |
| System Time Discovery | — | T1124 | `T1124_time_discovery.py` | NTP config, time zone, chrony |
| Virtual Machine Discovery | — | T1673 | `T1673_vm_discovery.py` | VM/hypervisor detection (systemd-detect-virt) |
| Virtualization/Sandbox Evasion | System/User/Time Checks | T1497 | `T1497_sandbox_evasion.py` | VM artifact detection techniques |

### Lateral Movement — TA0008 (8 techniques)

| Technique | Sub-technique | ID | Module File | Check Description |
|-----------|--------------|-----|-------------|-------------------|
| Exploitation of Remote Services | — | T1210 | `T1210_exploit_remote.py` | Remote service CVE exposure |
| Internal Spearphishing | — | T1534 | `T1534_internal_spearphishing.py` | Internal mail relay, user trust |
| Lateral Tool Transfer | — | T1570 | `T1570_lateral_tool_transfer.py` | SCP/rsync/netcat/wget availability |
| Remote Service Session Hijacking | SSH Hijacking | T1563.001 | `T1563_session_hijacking.py` | SSH agent forwarding, ControlMaster |
| Remote Services | SSH | T1021.004 | `T1021_remote_services.py` | SSH config audit (PermitRootLogin, key-only) |
| Remote Services | VNC | T1021.005 | — | VNC service exposure and auth |
| Software Deployment Tools | — | T1072 | `T1072_software_deployment.py` | Ansible/Puppet/Salt lateral movement |
| Taint Shared Content | — | T1080 | `T1080_taint_shared_content.py` | NFS/Samba shared writable content |
| Use Alternate Auth Material | — | T1550 | `T1550_alternate_auth.py` | SSH agent, Kerberos keytabs, tokens |

### Collection — TA0009 (14 techniques)

| Technique | Sub-technique | ID | Module File | Check Description |
|-----------|--------------|-----|-------------|-------------------|
| Adversary-in-the-Middle | ARP/DHCP | T1557 | `T1557_aitm.py` | Traffic interception feasibility |
| Archive Collected Data | Via Utility | T1560.001 | `T1560_archive_data.py` | tar/gzip/zip availability |
| Archive Collected Data | Via Library | T1560.002 | — | Python/Perl archive module access |
| Archive Collected Data | Custom Method | T1560.003 | — | Custom compression tool detection |
| Audio Capture | — | T1123 | `T1123_audio_capture.py` | Microphone access, PulseAudio/ALSA |
| Automated Collection | — | T1119 | `T1119_automated_collection.py` | Scripted data collection feasibility |
| Clipboard Data | — | T1115 | `T1115_clipboard_data.py` | X11/Wayland clipboard access |
| Data from Information Repositories | Databases | T1213.006 | `T1213_data_repositories.py` | Database access, credentials |
| Data from Local System | — | T1005 | `T1005_data_local_system.py` | Sensitive file access audit |
| Data from Network Shared Drive | — | T1039 | `T1039_network_shared_drive.py` | NFS/Samba mount enumeration |
| Data from Removable Media | — | T1025 | `T1025_removable_media.py` | USB auto-mount, media access policy |
| Data Staged | Local Data Staging | T1074.001 | `T1074_data_staged.py` | World-writable staging directories |
| Data Staged | Remote Data Staging | T1074.002 | — | Remote staging point detection |
| Email Collection | Email Forwarding Rule | T1114.003 | `T1114_email_collection.py` | Mail forwarding rules audit |
| Input Capture | Keylogging | T1056.001 | `T1056_input_capture.py` | Keylogger feasibility |
| Screen Capture | — | T1113 | `T1113_screen_capture.py` | Screenshot tool access, X11 perms |
| Video Capture | — | T1125 | `T1125_video_capture.py` | Camera/video device access |

### Command and Control — TA0011 (18 techniques)

| Technique | Sub-technique | ID | Module File | Check Description |
|-----------|--------------|-----|-------------|-------------------|
| Application Layer Protocol | Web Protocols | T1071.001 | `T1071_app_layer_protocol.py` | Outbound HTTP/HTTPS policy |
| Application Layer Protocol | File Transfer | T1071.002 | — | FTP/SFTP outbound access |
| Application Layer Protocol | Mail Protocols | T1071.003 | — | SMTP outbound access |
| Application Layer Protocol | DNS | T1071.004 | — | DNS tunneling feasibility |
| Application Layer Protocol | Pub/Sub | T1071.005 | — | MQTT/AMQP protocol access |
| Communication Through Removable Media | — | T1092 | `T1092_removable_media_c2.py` | USB C2 feasibility |
| Content Injection | — | T1659 | `T1659_content_injection.py` | Man-in-the-middle content injection |
| Data Encoding | Standard/Non-Standard | T1132 | `T1132_data_encoding.py` | Base64/custom encoding detection |
| Data Obfuscation | Junk/Stego/Impersonation | T1001 | `T1001_data_obfuscation.py` | Protocol impersonation feasibility |
| Dynamic Resolution | Fast Flux/DGA/DNS Calc | T1568 | `T1568_dynamic_resolution.py` | DNS resolution policy, RPZ |
| Encrypted Channel | Symmetric/Asymmetric | T1573 | `T1573_encrypted_channel.py` | TLS inspection, crypto policy |
| Fallback Channels | — | T1008 | `T1008_fallback_channels.py` | Alternate outbound channel detection |
| Hide Infrastructure | — | T1665 | `T1665_hide_infrastructure.py` | CDN/cloud fronting detection |
| Ingress Tool Transfer | — | T1105 | `T1105_ingress_tool_transfer.py` | curl/wget/fetch tool availability |
| Multi-Stage Channels | — | T1104 | `T1104_multi_stage.py` | Staged download feasibility |
| Non-Application Layer Protocol | — | T1095 | `T1095_non_app_protocol.py` | Raw socket, ICMP tunneling access |
| Non-Standard Port | — | T1571 | `T1571_non_standard_port.py` | Outbound port filtering policy |
| Protocol Tunneling | — | T1572 | `T1572_protocol_tunneling.py` | SSH tunneling, socat, chisel |
| Proxy | Internal/External/Multi-hop | T1090 | `T1090_proxy.py` | SOCKS, HTTP proxy, NAT rules |
| Proxy | Domain Fronting | T1090.004 | — | CDN domain fronting feasibility |
| Remote Access Tools | IDE/Desktop/Hardware | T1219 | `T1219_remote_access_tools.py` | Remote access tool detection |
| Traffic Signaling | Port Knocking/Socket Filters | T1205 | `T1205_traffic_signaling.py` | Covert signaling detection |
| Web Service | Dead Drop/Bidirectional | T1102 | `T1102_web_service.py` | Cloud service C2 feasibility |

### Exfiltration — TA0010 (8 techniques)

| Technique | Sub-technique | ID | Module File | Check Description |
|-----------|--------------|-----|-------------|-------------------|
| Automated Exfiltration | — | T1020 | `T1020_automated_exfil.py` | Automated data transfer detection |
| Data Transfer Size Limits | — | T1030 | `T1030_data_size_limits.py` | Data transfer throttling/monitoring |
| Exfiltration Over Alternative Protocol | Encrypted/Unencrypted | T1048 | `T1048_exfil_alt_protocol.py` | DNS, ICMP, raw socket exfiltration |
| Exfiltration Over C2 Channel | — | T1041 | `T1041_exfil_c2_channel.py` | C2 channel data exfiltration |
| Exfiltration Over Other Network Medium | Bluetooth | T1011.001 | `T1011_exfil_other_medium.py` | Bluetooth exfiltration feasibility |
| Exfiltration Over Physical Medium | USB | T1052.001 | `T1052_exfil_physical.py` | USB write policy, device control |
| Exfiltration Over Web Service | Code Repo/Cloud/Webhook | T1567 | `T1567_exfil_web_service.py` | Cloud storage, webhook, pastebin access |
| Scheduled Transfer | — | T1029 | `T1029_scheduled_transfer.py` | Timed data exfiltration feasibility |

### Impact — TA0040 (15 techniques)

| Technique | Sub-technique | ID | Module File | Check Description |
|-----------|--------------|-----|-------------|-------------------|
| Account Access Removal | — | T1531 | `T1531_account_access_removal.py` | Account deletion/lockout feasibility |
| Data Destruction | — | T1485 | `T1485_data_destruction.py` | `rm -rf`, `shred` access, backup status |
| Data Encrypted for Impact | — | T1486 | `T1486_data_encrypted.py` | Ransomware feasibility, backup isolation |
| Data Manipulation | Stored/Transmitted/Runtime | T1565 | `T1565_data_manipulation.py` | Data integrity monitoring (AIDE) |
| Defacement | Internal/External | T1491 | `T1491_defacement.py` | Web content write access |
| Disk Wipe | Content/Structure | T1561 | `T1561_disk_wipe.py` | Disk write access, dd availability |
| Email Bombing | — | T1667 | `T1667_email_bombing.py` | Mail relay abuse, rate limiting |
| Endpoint Denial of Service | OS/Service/App Exhaustion | T1499 | `T1499_endpoint_dos.py` | Resource limits, cgroups, ulimits |
| Financial Theft | — | T1657 | `T1657_financial_theft.py` | Financial system access audit |
| Firmware Corruption | — | T1495 | `T1495_firmware_corruption.py` | Firmware write access, flashrom |
| Inhibit System Recovery | — | T1490 | `T1490_inhibit_recovery.py` | Backup destruction feasibility |
| Network Denial of Service | Direct Flood/Reflection | T1498 | `T1498_network_dos.py` | Amplification vector detection |
| Resource Hijacking | Compute/Bandwidth | T1496 | `T1496_resource_hijacking.py` | Cryptomining feasibility, GPU access |
| Service Stop | — | T1489 | `T1489_service_stop.py` | Critical service stop permissions |
| System Shutdown/Reboot | — | T1529 | `T1529_system_shutdown.py` | Reboot/shutdown permissions |

---

## Target OS Compatibility

| Feature | RHEL 8 | RHEL 9 |
|---------|--------|--------|
| SSH | Yes | Yes |
| SELinux | Enforcing (default) | Enforcing (default) |
| Firewalld | Yes | Yes |
| SystemD | Yes | Yes |
| auditd | Yes | Yes |
| FIPS mode | Optional | Optional |
| Podman/Containers | Yes | Enhanced |
| Kernel version | 4.18 | 5.14 |
| Python default | 3.6 (platform), 3.8/3.9 (module) | 3.9 |
| OpenSSL | 1.1.1 | 3.0 |
| AIDE/IDS | Optional | Optional |
| nftables | Backend via firewalld | Default |

---

## Development Phases

### Phase 1 — Foundation (COMPLETE)
- [x] Project scaffolding: `pyproject.toml`, `requirements.txt`, `.gitignore`
- [x] Core engine (`core/engine.py`) with module auto-discovery
- [x] Session manager (`core/session.py`) — local + SSH (paramiko)
- [x] BaseModule abstract class (`modules/base.py`)
- [x] Data models (`core/models.py`) — ModuleResult, Finding, Target
- [x] Structured logger (`core/logger.py`) + evidence chain
- [x] CLI entry point (`main.py`) with click (scan, report, list-modules, list-tactics)
- [x] Config system (YAML loading + quick/full/stealth profiles)
- [x] Report generation (`core/reporter.py`) — HTML, JSON, CSV
- [x] MITRE ATT&CK Navigator layer export (`core/mitre_mapper.py`)
- [x] Professional ASCII banner (`core/banner.py`) with authorization warning
- [x] HTML report template (`templates/report.html`) — dark-themed, expandable findings
- [x] Test fixtures and initial unit tests

### Phase 2 — Discovery Modules (26 techniques) (COMPLETE)
- [x] T1082 System Information Discovery
- [x] T1087 Account Discovery (local + domain)
- [x] T1069 Permission Groups Discovery
- [x] T1046 Network Service Discovery
- [x] T1083 File and Directory Discovery
- [x] T1057 Process Discovery
- [x] T1049 System Network Connections Discovery
- [x] T1016 System Network Configuration Discovery
- [x] T1518 Software Discovery (security + backup)
- [x] T1007 System Service Discovery
- [x] T1033 System Owner/User Discovery
- [x] T1018 Remote System Discovery
- [x] T1135 Network Share Discovery
- [x] T1201 Password Policy Discovery
- [x] T1124 System Time Discovery
- [x] T1120 Peripheral Device Discovery
- [x] T1010 Application Window Discovery
- [x] T1217 Browser Information Discovery
- [x] T1652 Device Driver Discovery
- [x] T1654 Log Enumeration
- [x] T1680 Local Storage Discovery
- [x] T1614.001 System Language Discovery
- [x] T1673 Virtual Machine Discovery
- [x] T1622 Debugger Evasion
- [x] T1040 Network Sniffing
- [x] T1497 Virtualization/Sandbox Evasion

### Phase 3 — Credential Access (15 techniques)
- [ ] T1003 OS Credential Dumping (/etc/shadow, proc, ccache)
- [ ] T1552 Unsecured Credentials (files, history, private keys)
- [ ] T1110 Brute Force policy audit
- [ ] T1556 Modify Authentication Process (PAM, MFA)
- [ ] T1557 Adversary-in-the-Middle (ARP, DHCP)
- [ ] T1555 Credentials from Password Stores
- [ ] T1558 Kerberos Tickets (ccache files)
- [ ] T1056 Input Capture (keylogging)
- [ ] T1040 Network Sniffing
- [ ] T1212 Exploitation for Credential Access
- [ ] T1606 Forge Web Credentials
- [ ] T1649 Steal/Forge Auth Certificates
- [ ] T1539 Steal Web Session Cookie
- [ ] T1111 MFA Interception
- [ ] T1621 MFA Request Generation

### Phase 4 — Privilege Escalation (12 techniques)
- [ ] T1548 Abuse Elevation Control (SUID/SGID, sudo)
- [ ] T1068 Exploitation for Privilege Escalation (kernel CVEs)
- [ ] T1055 Process Injection (ptrace, proc memory, VDSO)
- [ ] T1574 Hijack Execution Flow (LD_PRELOAD, PATH)
- [ ] T1611 Escape to Host (container escape)
- [ ] T1547 Boot/Logon Autostart (kernel modules, XDG)
- [ ] T1546 Event Triggered Execution (shell config, udev, trap)
- [ ] T1543 Create/Modify System Process (systemd)
- [ ] T1037 Boot/Logon Init Scripts (RC scripts)
- [ ] T1053 Scheduled Task/Job (at, cron, systemd timers)
- [ ] T1098 Account Manipulation
- [ ] T1078 Valid Accounts

### Phase 5 — Execution & Persistence (28 techniques)
- [ ] T1059 Command and Scripting Interpreter (bash, python, JS, Lua)
- [ ] T1053 Scheduled Tasks (cron, at, systemd timers)
- [ ] T1543 Systemd Service persistence
- [ ] T1546 Event Triggered Execution (all sub-techniques)
- [ ] T1098 Account Manipulation (SSH keys, groups)
- [ ] T1136 Create Account (local, domain)
- [ ] T1574 Hijack Execution Flow (linker, PATH)
- [ ] T1556 Modify Auth Process (PAM, MFA)
- [ ] T1554 Compromise Host Software Binary
- [ ] T1547 Boot/Logon Autostart (kernel modules, XDG)
- [ ] T1037 Boot/Logon Init Scripts
- [ ] T1668 Exclusive Control
- [ ] T1653 Power Settings
- [ ] T1542 Pre-OS Boot (firmware, bootkit)
- [ ] T1505 Server Software Component (web shell, SQL)
- [ ] T1176 Software Extensions (browser, IDE)
- [ ] T1205 Traffic Signaling (port knocking, socket filters)
- [ ] T1106 Native API
- [ ] T1129 Shared Modules
- [ ] T1072 Software Deployment Tools
- [ ] T1569 System Services
- [ ] T1204 User Execution
- [ ] T1203 Exploitation for Client Execution
- [ ] T1674 Input Injection
- [ ] T1559 Inter-Process Communication

### Phase 6 — Defense Evasion (26 techniques)
- [ ] T1562 Impair Defenses (SELinux, auditd, firewall, history, audit system)
- [ ] T1070 Indicator Removal (logs, history, files, timestamps)
- [ ] T1036 Masquerading (rename, process trees, file type, args)
- [ ] T1027 Obfuscated Files (packing, encoding, fileless)
- [ ] T1222 File Permissions Modification
- [ ] T1564 Hide Artifacts (hidden files, bind mounts, xattrs, VMs)
- [ ] T1574 Hijack Execution Flow
- [ ] T1055 Process Injection
- [ ] T1556 Modify Auth Process
- [ ] T1014 Rootkit detection
- [ ] T1553 Subvert Trust Controls (root certs)
- [ ] T1620 Reflective Code Loading
- [ ] T1542 Pre-OS Boot
- [ ] T1218 System Binary Proxy Execution
- [ ] T1205 Traffic Signaling
- [ ] T1078 Valid Accounts
- [ ] T1497 Virtualization/Sandbox Evasion
- [ ] T1622 Debugger Evasion
- [ ] T1678 Delay Execution
- [ ] T1140 Deobfuscate/Decode Files
- [ ] T1480 Execution Guardrails
- [ ] T1211 Exploitation for Defense Evasion
- [ ] T1656 Impersonation
- [ ] T1672 Email Spoofing

### Phase 7 — Lateral Movement, C2, Exfiltration & Collection (48 techniques)
- [ ] T1021 Remote Services (SSH, VNC)
- [ ] T1563 Remote Service Session Hijacking (SSH)
- [ ] T1570 Lateral Tool Transfer
- [ ] T1550 Alternate Authentication Material
- [ ] T1210 Exploitation of Remote Services
- [ ] T1534 Internal Spearphishing
- [ ] T1072 Software Deployment Tools
- [ ] T1080 Taint Shared Content
- [ ] T1071 Application Layer Protocol (HTTP/DNS/Mail/FTP)
- [ ] T1573 Encrypted Channel
- [ ] T1572 Protocol Tunneling
- [ ] T1090 Proxy (internal, external, domain fronting)
- [ ] T1095 Non-Application Layer Protocol
- [ ] T1571 Non-Standard Port
- [ ] T1105 Ingress Tool Transfer
- [ ] T1219 Remote Access Tools
- [ ] T1102 Web Service C2
- [ ] T1001 Data Obfuscation
- [ ] T1132 Data Encoding
- [ ] T1568 Dynamic Resolution
- [ ] T1008 Fallback Channels
- [ ] T1104 Multi-Stage Channels
- [ ] T1665 Hide Infrastructure
- [ ] T1205 Traffic Signaling
- [ ] T1092 Communication Through Removable Media
- [ ] T1659 Content Injection
- [ ] T1048 Exfiltration Over Alternative Protocol
- [ ] T1041 Exfiltration Over C2 Channel
- [ ] T1567 Exfiltration Over Web Service
- [ ] T1011 Exfiltration Over Other Network Medium
- [ ] T1052 Exfiltration Over Physical Medium
- [ ] T1020 Automated Exfiltration
- [ ] T1030 Data Transfer Size Limits
- [ ] T1029 Scheduled Transfer
- [ ] T1005 Data from Local System
- [ ] T1039 Data from Network Shared Drive
- [ ] T1025 Data from Removable Media
- [ ] T1560 Archive Collected Data
- [ ] T1074 Data Staged
- [ ] T1056 Input Capture
- [ ] T1113 Screen Capture
- [ ] T1125 Video Capture
- [ ] T1123 Audio Capture
- [ ] T1115 Clipboard Data
- [ ] T1119 Automated Collection
- [ ] T1213 Data from Information Repositories
- [ ] T1114 Email Collection
- [ ] T1557 Adversary-in-the-Middle

### Phase 8 — Impact (15 techniques)
- [ ] T1485 Data Destruction
- [ ] T1486 Data Encrypted for Impact (ransomware feasibility)
- [ ] T1565 Data Manipulation (stored, transmitted, runtime)
- [ ] T1489 Service Stop
- [ ] T1529 System Shutdown/Reboot
- [ ] T1490 Inhibit System Recovery
- [ ] T1531 Account Access Removal
- [ ] T1491 Defacement (internal, external)
- [ ] T1561 Disk Wipe (content, structure)
- [ ] T1499 Endpoint Denial of Service
- [ ] T1498 Network Denial of Service
- [ ] T1496 Resource Hijacking (compute, bandwidth)
- [ ] T1495 Firmware Corruption
- [ ] T1657 Financial Theft
- [ ] T1667 Email Bombing

### Phase 9 — Reporting & ATT&CK Integration
- [ ] ATT&CK Navigator JSON layer export (Linux platform)
- [ ] HTML report with executive summary
- [ ] JSON/CSV machine-readable output
- [ ] Per-technique detail pages with mitigations
- [ ] CIS RHEL Benchmark mapping (CIS RHEL 8 / RHEL 9)
- [ ] NIST 800-53 / STIG mapping (DISA RHEL STIG)

### Phase 10 — Testing & Hardening
- [ ] Unit tests per module
- [ ] Integration tests against lab VMs (RHEL 8, RHEL 9)
- [ ] Safety controls validation (dry-run, rollback)
- [ ] CI/CD pipeline (GitHub Actions)
- [ ] User documentation

---

## Technique Count Summary

| Tactic | Techniques | Sub-techniques | Total Checks |
|--------|-----------|---------------|-------------|
| Initial Access | 10 | 10 | 17 |
| Execution | 10 | 13 | 17 |
| Persistence | 18 | 18 | 28 |
| Privilege Escalation | 12 | 18 | 25 |
| Defense Evasion | 26 | 55 | 64 |
| Credential Access | 15 | 16 | 26 |
| Discovery | 26 | 8 | 30 |
| Lateral Movement | 8 | 3 | 10 |
| Collection | 14 | 9 | 17 |
| Command & Control | 18 | 20 | 30 |
| Exfiltration | 8 | 8 | 14 |
| Impact | 15 | 9 | 19 |
| **Total** | **180** | **187** | **297** |

---

## Key Dependencies

```
paramiko>=3.0             # SSH connections and remote execution
mitreattack-python        # Official MITRE ATT&CK STIX data
click>=8.0                # CLI framework
pyyaml>=6.0               # YAML config parsing
jinja2>=3.1               # Report templating
rich>=13.0                # Terminal UI, tables, progress bars
structlog>=23.0           # Structured logging
cryptography>=41.0        # Encryption utilities
python-nmap>=0.7          # Nmap wrapper for port scanning
psutil>=5.9               # Process and system utilities
```

---

## Coding Conventions

- Python 3.10+ (use `match/case`, `X | Y` union types where appropriate)
- Type hints on all public functions
- Module file naming: `T{id}_{short_name}.py` (e.g., `T1059_command_scripting.py`)
- One class per module file, class name matches technique (e.g., `UnixShellCheck`)
- Use `structlog` for all logging — never bare `print()`
- Tests mirror source layout under `tests/test_modules/`
- All config via YAML — no hardcoded values

---

## Safety & Authorization

- Targets must be explicitly whitelisted in `config/settings.yaml`
- Default mode is **check-only** (passive, read-only)
- Active simulation requires `--simulate` CLI flag
- Authorization banner displayed before any scan
- Every action produces an audit log entry
- `cleanup()` must be implemented for every simulate-capable module
- OS guard: modules auto-skip if target OS not in `SUPPORTED_OS`

---

## Running the Tool

```bash
# Quick passive scan (check-only, safe)
python main.py scan --target 192.168.1.20 --profile quick

# Full scan with active simulation
python main.py scan --target 192.168.1.20 --profile full --simulate

# Scan specific tactic only
python main.py scan --target 192.168.1.20 --tactic discovery

# Scan specific technique
python main.py scan --target 192.168.1.20 --technique T1082

# Local machine scan
python main.py scan --target localhost

# Generate report from previous scan
python main.py report --input reports/scan_2026-03-19.json --format html
```

---

## RHEL-Specific Security Controls Tested

| Control | Check |
|---------|-------|
| SELinux | Mode (enforcing/permissive/disabled), policy, booleans, confined domains |
| Firewalld / nftables | Active zones, open ports, rich rules, direct rules |
| auditd | Rules loaded, key events monitored, log integrity, immutable flag |
| PAM | Module stack, faillock config, password complexity, pam_tally2 |
| FIPS mode | `fips-mode-setup --check`, crypto policies |
| SSH hardening | Ciphers, MACs, key exchange, PermitRootLogin, AllowUsers |
| Sudo | NOPASSWD entries, wildcard abuse, env_keep, secure_path |
| SUID/SGID | Unexpected SUID binaries vs CIS baseline |
| Kernel parameters | `sysctl` hardening (ASLR, ptrace_scope, dmesg_restrict, core dumps) |
| Systemd | Service isolation, ProtectSystem, NoNewPrivileges, sandboxing |
| Package integrity | `rpm -Va`, GPG key verification, repo signing |
| Crypto policies | `update-crypto-policies`, TLS minimum version, allowed ciphers |
| Container security | Podman rootless, namespace isolation, seccomp profiles |
| Kernel module controls | Module signing, blacklisting, modprobe restrictions |

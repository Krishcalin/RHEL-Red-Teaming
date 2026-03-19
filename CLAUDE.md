# CLAUDE.md — RHEL Red Teaming Tool

## Project Overview

An open-source Python-based active scanning tool for red team security testing on Red Hat Enterprise
Linux systems, aligned with the MITRE ATT&CK Framework (Linux matrix). The tool tests security
controls across RHEL 8 and RHEL 9.

**Repository**: https://github.com/Krishcalin/RHEL-Red-Teaming
**License**: MIT
**Python**: 3.10+

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
│   ├── reconnaissance/            # TA0043
│   ├── initial_access/            # TA0001
│   ├── execution/                 # TA0002
│   ├── persistence/               # TA0003
│   ├── privilege_escalation/      # TA0004
│   ├── defense_evasion/           # TA0005
│   ├── credential_access/         # TA0006
│   ├── discovery/                 # TA0007
│   ├── lateral_movement/          # TA0008
│   ├── collection/                # TA0009
│   ├── command_and_control/       # TA0011
│   ├── exfiltration/              # TA0010
│   └── impact/                    # TA0040
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

## MITRE ATT&CK Tactic Coverage (Linux Matrix)

| Tactic | ID | Module Package | Priority Techniques |
|--------|----|----------------|---------------------|
| Reconnaissance | TA0043 | `modules/reconnaissance/` | T1595, T1592 |
| Initial Access | TA0001 | `modules/initial_access/` | T1078, T1190, T1133 |
| Execution | TA0002 | `modules/execution/` | T1059.004 (Bash), T1053.003 (Cron), T1059.006 (Python), T1203 |
| Persistence | TA0003 | `modules/persistence/` | T1053.003, T1543.002, T1546.004, T1098, T1136 |
| Privilege Escalation | TA0004 | `modules/privilege_escalation/` | T1548.001, T1548.003, T1068, T1574.006, T1611 |
| Defense Evasion | TA0005 | `modules/defense_evasion/` | T1562.001, T1070.002, T1036, T1027, T1222.002 |
| Credential Access | TA0006 | `modules/credential_access/` | T1003.008, T1552.001, T1552.003, T1110, T1556.003 |
| Discovery | TA0007 | `modules/discovery/` | T1087.001, T1082, T1046, T1083, T1057, T1016 |
| Lateral Movement | TA0008 | `modules/lateral_movement/` | T1021.004, T1550, T1570 |
| Collection | TA0009 | `modules/collection/` | T1005, T1560, T1074.001 |
| Command & Control | TA0011 | `modules/command_and_control/` | T1071, T1573, T1090, T1572 |
| Exfiltration | TA0010 | `modules/exfiltration/` | T1048, T1041 |
| Impact | TA0040 | `modules/impact/` | T1485, T1486, T1489, T1529 |

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

### Phase 1 — Foundation
- [ ] Project scaffolding: `pyproject.toml`, `requirements.txt`, `.gitignore`
- [ ] Core engine (`core/engine.py`) with module auto-discovery
- [ ] Session manager (`core/session.py`) — local + SSH (paramiko)
- [ ] BaseModule abstract class (`modules/base.py`)
- [ ] Data models (`core/models.py`) — ModuleResult, Finding, Target
- [ ] Structured logger (`core/logger.py`)
- [ ] CLI entry point (`main.py`) with click
- [ ] Config system (YAML loading + profiles)

### Phase 2 — Discovery & Reconnaissance Modules
- [ ] T1082 System Information Discovery (`uname`, `/etc/os-release`, kernel version)
- [ ] T1087.001 Local Account Discovery (`/etc/passwd`, `getent passwd`)
- [ ] T1087.002 Domain Account Discovery (SSSD/IPA/LDAP enumeration)
- [ ] T1069.001 Local Groups Discovery (`/etc/group`, `getent group`)
- [ ] T1046 Network Service Discovery (`ss`, `nmap`, open ports)
- [ ] T1083 File and Directory Discovery (sensitive file enumeration)
- [ ] T1057 Process Discovery (`/proc`, `ps aux`)
- [ ] T1049 System Network Connections Discovery (`ss -tulnp`, `netstat`)
- [ ] T1016 System Network Configuration Discovery (`ip addr`, routes, DNS)
- [ ] T1518 Software Discovery (installed packages, `rpm -qa`)
- [ ] T1595 Active Scanning (port scan, service banner grab)

### Phase 3 — Credential Access & Privilege Escalation
- [ ] T1003.008 `/etc/passwd` and `/etc/shadow` access check
- [ ] T1552.001 Credentials in Files (config files, history, keys in world-readable paths)
- [ ] T1552.003 Bash History credential leakage
- [ ] T1552.004 Private Keys — SSH keys with weak permissions
- [ ] T1110 Brute Force policy check (PAM `faillock`, `pam_tally2`)
- [ ] T1556.003 Pluggable Authentication Modules (PAM) backdoor check
- [ ] T1548.001 SUID/SGID binary audit (find SUID binaries, check known exploitables)
- [ ] T1548.003 Sudo misconfiguration (`sudoers` NOPASSWD, wildcard abuse)
- [ ] T1068 Exploitation for Privilege Escalation (kernel CVE checks)
- [ ] T1574.006 Dynamic Linker Hijacking (`LD_PRELOAD`, `ld.so.preload`, `RPATH`)
- [ ] T1611 Escape to Host (container escape checks — Podman/Docker)

### Phase 4 — Execution, Persistence & Defense Evasion
- [ ] T1059.004 Unix Shell restrictions (rbash, `chsh` controls)
- [ ] T1059.006 Python availability and restrictions
- [ ] T1053.003 Cron job audit (user crontabs, `/etc/cron.*`, anacron)
- [ ] T1053.002 At job audit (`at` daemon status, pending jobs)
- [ ] T1543.002 Systemd service persistence (writable unit files, user services)
- [ ] T1546.004 `.bashrc`/`.profile` trap persistence (profile script injection)
- [ ] T1098 Account Manipulation (SSH authorized_keys audit)
- [ ] T1136.001 Create Local Account feasibility
- [ ] T1562.001 Disable/Modify Security Tools (SELinux status, auditd, firewalld)
- [ ] T1562.002 Disable Logging (rsyslog, journald, auditd kill checks)
- [ ] T1070.002 Clear Linux Logs (`/var/log` permissions, log rotation abuse)
- [ ] T1070.004 File Deletion (secure delete tools, `shred` availability)
- [ ] T1036 Masquerading detection (binary name spoofing, PATH manipulation)
- [ ] T1222.002 Linux File Permissions Modification (world-writable dirs, sticky bit)
- [ ] T1027 Obfuscated Files (Base64 encoded scripts, packed ELF binaries)

### Phase 5 — Lateral Movement, C2 & Exfiltration
- [ ] T1021.004 SSH configuration audit (PermitRootLogin, PasswordAuth, key-only)
- [ ] T1550 Use Alternate Authentication Material (SSH agent forwarding, Kerberos keytabs)
- [ ] T1570 Lateral Tool Transfer (SCP/rsync/netcat availability)
- [ ] T1071.001 Web Protocol C2 (outbound HTTP/S checks, proxy config)
- [ ] T1071.004 DNS Protocol C2 (DNS tunneling feasibility)
- [ ] T1572 Protocol Tunneling (SSH tunneling, socat, chisel availability)
- [ ] T1090 Proxy detection (SOCKS, HTTP proxy, iptables NAT rules)
- [ ] T1048 Exfiltration Over Alternative Protocol (DNS, ICMP, raw sockets)
- [ ] T1041 Exfiltration Over C2 Channel

### Phase 6 — Reporting & ATT&CK Integration
- [ ] ATT&CK Navigator JSON layer export (Linux platform)
- [ ] HTML report with executive summary
- [ ] JSON/CSV machine-readable output
- [ ] Per-technique detail pages with mitigations
- [ ] CIS RHEL Benchmark mapping (CIS RHEL 8 / RHEL 9)
- [ ] NIST 800-53 / STIG mapping (DISA RHEL STIG)

### Phase 7 — Testing & Hardening
- [ ] Unit tests per module
- [ ] Integration tests against lab VMs (RHEL 8, RHEL 9)
- [ ] Safety controls validation (dry-run, rollback)
- [ ] CI/CD pipeline (GitHub Actions)
- [ ] User documentation

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
- Module file naming: `T{id}_{short_name}.py` (e.g., `T1059_unix_shell.py`)
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
| SELinux | Mode (enforcing/permissive/disabled), policy, booleans |
| Firewalld / nftables | Active zones, open ports, rich rules |
| auditd | Rules loaded, key events monitored, log integrity |
| PAM | Module stack, faillock config, password complexity |
| FIPS mode | `fips-mode-setup --check`, crypto policies |
| SSH hardening | Ciphers, MACs, key exchange algorithms, config drift |
| Sudo | NOPASSWD entries, wildcard abuse, env_keep dangers |
| SUID/SGID | Unexpected SUID binaries vs CIS baseline |
| Kernel parameters | `sysctl` hardening (`ASLR`, `ptrace_scope`, `dmesg_restrict`) |
| Systemd | Service isolation, `ProtectSystem`, `NoNewPrivileges` |
| Package integrity | `rpm -Va`, GPG key verification |
| Crypto policies | `update-crypto-policies`, TLS minimum version |

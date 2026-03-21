# RHEL-RT — Red Hat Enterprise Linux Red Teaming Tool

<p align="center">
  <img src="banner.svg?v=3" alt="RHEL-RT Banner" width="100%"/>
</p>

An open-source Python-based active scanning tool for red team security testing on Red Hat Enterprise Linux, aligned with the [MITRE ATT&CK Framework (Linux Matrix)](https://attack.mitre.org/matrices/enterprise/linux/).

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://python.org)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-v16-red.svg)](https://attack.mitre.org)
[![Modules](https://img.shields.io/badge/Modules-190-e94560.svg)](#mitre-attck-coverage)
[![Compliance](https://img.shields.io/badge/Compliance-5%20Frameworks-4ecca3.svg)](#compliance-frameworks)

---

## Overview

RHEL-RT is a security validation and verification tool that systematically tests security controls on RHEL 8 and RHEL 9 systems. It maps every check to a specific MITRE ATT&CK technique, providing security teams with actionable insights, ATT&CK Navigator heatmaps, and **auto-generated Ansible remediation playbooks**.

### Key Features

- **190 modules** — 180 ATT&CK technique modules across all 12 tactics + 10 container security modules
- **Safe by default** — passive, read-only checks; active simulation requires explicit `--simulate` flag
- **Ansible playbook generator** — auto-generates remediation playbooks from scan findings with severity/tag filtering
- **ATT&CK Navigator export** — JSON layers for visual heatmap analysis
- **Multi-format reporting** — HTML (dark-themed with per-technique detail pages), JSON, CSV
- **5 compliance frameworks** — CIS Controls v8, NIST SP 800-53, CIS RHEL 9 Benchmark, DISA STIG RHEL 8, DISA STIG RHEL 9
- **Container security** — Podman/Docker hardening (10 modules: runtime, images, privileges, networking, seccomp, secrets, filesystem, logging, supply chain)
- **Local & remote scanning** — direct execution or SSH (paramiko)
- **RHEL-specific controls** — SELinux, firewalld, auditd, PAM, FIPS, crypto policies, systemd sandboxing
- **Module auto-discovery** — drop a technique module into `modules/` and it's automatically loaded
- **Evidence chain** — every action logged with timestamp, target, technique ID, and result
- **CI/CD** — GitHub Actions pipeline with Python 3.10-3.12, ruff linting, mypy, pytest + coverage

---

## Quick Start

### Prerequisites

- Python 3.10+
- Target: RHEL 8 or RHEL 9 (local or remote via SSH)
- Proper authorization to test the target system

### Installation

```bash
git clone https://github.com/Krishcalin/RHEL-Red-Teaming.git
cd RHEL-Red-Teaming
pip install -r requirements.txt
```

### Usage

```bash
# Quick passive scan on localhost (check-only, safe)
python main.py scan --target localhost --profile quick

# Full scan against a remote host
python main.py scan --target 192.168.1.20 -u admin -k ~/.ssh/id_rsa --profile full

# Active simulation mode (requires explicit flag)
python main.py scan --target 192.168.1.20 -u admin --profile full --simulate

# Scan a specific tactic
python main.py scan --target localhost --tactic discovery

# Scan a specific technique
python main.py scan --target localhost --technique T1082

# Generate HTML report from a previous scan
python main.py report --input reports/scan_abc123_2026-03-19.json --format html

# Generate Ansible remediation playbook from scan results
python main.py remediate --input reports/scan_abc123.json

# Generate playbook for critical findings only, filtered by STIG tags
python main.py remediate --input scan.json --severity critical --tags stig

# Generate one playbook per vulnerable technique
python main.py remediate --input scan.json --per-technique

# List all available modules
python main.py list-modules

# List supported tactics
python main.py list-tactics
```

---

## Architecture

```
RHEL-Red-Teaming/
├── config/                        # YAML configuration
│   ├── settings.yaml              # Global settings (targets, credentials)
│   ├── techniques.yaml            # Enable/disable specific techniques
│   └── profiles/                  # Scan profiles (quick, full, stealth)
├── core/                          # Core engine
│   ├── engine.py                  # Orchestrator with module auto-discovery
│   ├── session.py                 # Local + SSH session management
│   ├── models.py                  # Data models (Target, Finding, ModuleResult)
│   ├── banner.py                  # Professional ASCII banner
│   ├── logger.py                  # Structured logging + evidence chain
│   ├── reporter.py                # Report generation (HTML/JSON/CSV)
│   ├── mitre_mapper.py            # ATT&CK Navigator JSON layer export
│   ├── compliance.py              # CIS/NIST/STIG compliance mapping
│   └── playbook_generator.py      # Ansible remediation playbook generator
├── modules/                       # Technique modules (one per ATT&CK technique)
│   ├── base.py                    # BaseModule abstract class
│   ├── initial_access/            # TA0001 — 10 techniques
│   ├── execution/                 # TA0002 — 10 techniques
│   ├── persistence/               # TA0003 — 17 techniques
│   ├── privilege_escalation/      # TA0004 — 12 techniques
│   ├── defense_evasion/           # TA0005 — 26 techniques
│   ├── credential_access/         # TA0006 — 16 techniques
│   ├── discovery/                 # TA0007 — 26 techniques
│   ├── lateral_movement/          # TA0008 — 8 techniques
│   ├── collection/                # TA0009 — 14 techniques
│   ├── command_and_control/       # TA0011 — 18 techniques
│   ├── exfiltration/              # TA0010 — 8 techniques
│   ├── impact/                    # TA0040 — 15 techniques
│   └── container_security/        # CS001–CS010 — 10 container modules
├── templates/                     # Jinja2 HTML report template
├── tests/                         # pytest test suite (30+ test files)
├── main.py                        # CLI entry point (click)
└── pyproject.toml                 # Project metadata
```

### How It Works

1. **Engine** loads all technique modules from `modules/` via auto-discovery
2. **Session** connects to the target (local subprocess or SSH via paramiko)
3. Each **module** runs `check()` (passive) or `simulate()` (active) against the target
4. Results are collected as `ModuleResult` objects with `Finding` details
5. **Reporter** outputs HTML/JSON/CSV reports with compliance data
6. **MitreMapper** exports ATT&CK Navigator JSON layers for visual analysis
7. **ComplianceMapper** enriches results with CIS Controls, NIST 800-53, CIS RHEL Benchmark, and DISA STIG refs
8. **PlaybookGenerator** creates Ansible remediation playbooks from vulnerable findings

### Writing a Module

Every module inherits from `BaseModule` and implements four methods:

```python
from modules.base import BaseModule
from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session


class SystemInfoCheck(BaseModule):
    TECHNIQUE_ID = "T1082"
    TECHNIQUE_NAME = "System Information Discovery"
    TACTIC = Tactic.DISCOVERY
    SEVERITY = Severity.INFO
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        result = session.execute("uname -a")
        if result.success:
            self.add_finding(
                title="System information is accessible",
                description="Any user can enumerate system details",
                evidence=result.output,
                remediation="Restrict access via kernel parameters",
            )
            return self.make_result(Status.VULNERABLE, raw_output=result.output)
        return self.make_result(Status.NOT_VULNERABLE)

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)  # Same as check for read-only modules

    def get_mitigations(self) -> list[str]:
        return [
            "Set kernel.dmesg_restrict = 1",
            "Restrict /proc visibility with hidepid=2",
        ]
```

Save as `modules/discovery/T1082_system_info.py` — the engine discovers it automatically.

---

## MITRE ATT&CK Coverage

| Tactic | ID | Modules | Key Checks |
|--------|----|---------|------------|
| Initial Access | TA0001 | 10 | Valid accounts, public app exploits, SSH exposure, supply chain, phishing, WiFi |
| Execution | TA0002 | 10 | Shell restrictions, cron/at/systemd, scripting interpreters |
| Persistence | TA0003 | 17 | Systemd services, cron, SSH keys, PAM, udev rules, XDG autostart |
| Privilege Escalation | TA0004 | 12 | SUID/SGID, sudo misconfig, kernel CVEs, container escape |
| Defense Evasion | TA0005 | 26 | SELinux, auditd, rootkits, log tampering, masquerading, PATH hijacking, hidden users |
| Credential Access | TA0006 | 16 | /etc/shadow, SSH keys, PAM, Kerberos, network sniffing, credential files |
| Discovery | TA0007 | 26 | System info, accounts, network, processes, services |
| Lateral Movement | TA0008 | 8 | SSH hardening, SMB/NFS, session hijacking, deployment tools, shared content |
| Collection | TA0009 | 14 | Screen/audio/video capture, clipboard, email, data staging, input capture |
| Command & Control | TA0011 | 18 | Egress filtering, DNS tunneling, encrypted channels, proxy, remote access tools |
| Exfiltration | TA0010 | 8 | DNS/ICMP exfil, cloud storage, USB, scheduled transfers, web services |
| Impact | TA0040 | 15 | Data destruction, ransomware, service stop, DoS, firmware, resource hijacking |

**180 ATT&CK technique modules + 10 container security modules = 190 total**

### Container Security Modules (CS001–CS010)

| Module | Area | Key Checks |
|--------|------|------------|
| CS001 | Runtime Config | Podman vs Docker, rootless mode, Docker socket, registries |
| CS002 | Image Security | Signature policy, vulnerability scanners, untrusted images |
| CS003 | Privilege Escalation | --privileged, dangerous capabilities, host namespaces/mounts |
| CS004 | Network Security | Port exposure, host network mode, inter-container communication |
| CS005 | Seccomp & SELinux | seccomp profiles, SELinux labels, no-new-privileges |
| CS006 | Resource Limits | Memory, CPU, PID limits per container |
| CS007 | Secrets Management | Env var secrets, build ARG leaks, secret mount paths |
| CS008 | Filesystem Security | Read-only rootfs, volume permissions, storage driver |
| CS009 | Logging & Monitoring | Log driver, health checks, log rotation |
| CS010 | Supply Chain | Stale images, cosign signing, Containerfile best practices |

---

## Ansible Remediation Playbooks

RHEL-RT auto-generates Ansible playbooks from scan findings:

```bash
# Generated automatically after scan if vulnerabilities found
python main.py scan --target 192.168.1.20 --profile full

# Or generate from saved scan results
python main.py remediate --input reports/scan_abc123.json

# Filter by severity
python main.py remediate --input scan.json --severity critical

# Filter by compliance tags (stig, cis, ssh, audit, etc.)
python main.py remediate --input scan.json --tags stig,ssh

# One playbook per vulnerable technique
python main.py remediate --input scan.json --per-technique
```

**30+ technique mappings** to proper Ansible modules (lineinfile, file, systemd, sysctl, selinux, pam_limits, dnf, etc.) plus auto-generated tasks from finding remediations.

---

## RHEL-Specific Security Controls

| Control | What We Test |
|---------|-------------|
| **SELinux** | Mode, policy, booleans, confined domains |
| **Firewalld / nftables** | Zones, ports, rich rules, direct rules |
| **auditd** | Rules, key events, log integrity, immutable flag |
| **PAM** | Module stack, faillock, password complexity |
| **FIPS mode** | Compliance status, crypto policies |
| **SSH hardening** | Ciphers, MACs, PermitRootLogin, key-only auth |
| **Sudo** | NOPASSWD, wildcard abuse, env_keep, secure_path |
| **SUID/SGID** | Binary audit vs CIS baseline |
| **Kernel hardening** | ASLR, ptrace_scope, dmesg_restrict, core dumps |
| **Systemd sandboxing** | ProtectSystem, NoNewPrivileges, service isolation |
| **Package integrity** | rpm -Va, GPG verification, repo signing |
| **Crypto policies** | TLS minimum version, allowed ciphers |
| **Container security** | Podman rootless, namespaces, seccomp, image signing |

---

## Compliance Frameworks

Each technique is mapped to relevant controls from 5 frameworks:

| Framework | Techniques Mapped | Controls |
|-----------|------------------|----------|
| **CIS Controls v8** | 24 | ~60 controls |
| **NIST SP 800-53 Rev. 5** | 28 | ~55 controls |
| **CIS RHEL 9 Benchmark** | 14 | ~35 recommendations |
| **DISA STIG RHEL 8** (V1R14+) | 30 | 75+ rule IDs |
| **DISA STIG RHEL 9** (V1R2+) | 30 | 70+ rule IDs |

---

## Scan Profiles

| Profile | Tactics | Speed | Use Case |
|---------|---------|-------|----------|
| **quick** | Discovery, Credential Access, Privilege Escalation | Fast | Rapid assessment |
| **full** | All tactics | Thorough | Comprehensive audit |
| **stealth** | Discovery, Credential Access | Low-noise | Passive-only recon |

---

## Reports & Output

### HTML Report
Dark-themed, interactive HTML report with:
- Executive summary (total checks, vulnerable, secure, errors)
- Severity breakdown bar chart (critical/high/medium/low/info)
- Compliance dashboard with per-framework coverage meters
- Results grouped by ATT&CK tactic with clickable technique links
- Per-technique detail pages with findings, evidence, remediation, mitigations, and compliance mapping

### ATT&CK Navigator Layer
JSON layer file importable into [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/):
- Color-coded by status (red = vulnerable, green = secure)
- Scored by severity (critical = 100, high = 75, medium = 50)

### Ansible Playbook
Auto-generated YAML playbook with:
- Proper Ansible modules (not raw shell commands)
- Severity and tag filtering
- Per-technique or consolidated output
- Service restart handlers

### JSON / CSV
Machine-readable output with compliance columns for all 5 frameworks.

---

## Development Status

| Phase | Description | Status |
|-------|-------------|--------|
| 1 | Foundation (engine, session, CLI, config, reporting) | Done |
| 2 | Discovery Modules (26 techniques) | Done |
| 3 | Credential Access (16 techniques) | Done |
| 4 | Privilege Escalation (12 techniques) | Done |
| 5 | Execution & Persistence (27 techniques) | Done |
| 6 | Defense Evasion (26 techniques) | Done |
| 7 | Lateral Movement, C2 & Exfiltration (34 modules) | Done |
| 8 | Impact (15 techniques) | Done |
| 9 | Initial Access & Collection (24 modules) | Done |
| 10 | Reporting & Compliance (5 frameworks) | Done |
| 11 | Testing & CI/CD (30+ test files, GitHub Actions) | Done |
| 12 | Ansible Remediation Playbook Generator | Done |
| 13 | Container Security (10 modules) | Done |

**190 modules implemented. All phases complete.**

---

## Contributing

Contributions are welcome. To add a new technique module:

1. Create a file in the appropriate tactic directory: `modules/{tactic}/T{id}_{name}.py`
2. Inherit from `BaseModule` and implement `check()`, `simulate()`, `cleanup()`, `get_mitigations()`
3. Set required class attributes (`TECHNIQUE_ID`, `TECHNIQUE_NAME`, `TACTIC`, etc.)
4. Add tests in `tests/test_modules/`
5. The engine auto-discovers your module — no registration needed

---

## Disclaimer

This tool is intended for **authorized security testing only**. Unauthorized use against systems you do not own or have explicit written permission to test is illegal and unethical. The authors are not responsible for misuse.

Always ensure you have proper authorization before running any security scan.

---

## License

[MIT](LICENSE)

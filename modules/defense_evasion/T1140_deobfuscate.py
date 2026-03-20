"""T1140 — Deobfuscate/Decode Files or Information.

Checks for availability of decoding tools, recent base64 decode usage in
bash history, encoded payloads in temp directories, openssl enc usage in
scripts, and decode commands in shell history on RHEL systems.
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class DeobfuscateCheck(BaseModule):
    TECHNIQUE_ID = "T1140"
    TECHNIQUE_NAME = "Deobfuscate/Decode Files or Information"
    TACTIC = Tactic.DEFENSE_EVASION
    SEVERITY = Severity.MEDIUM
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        self._check_decode_tools(session)
        self._check_base64_history(session)
        self._check_encoded_payloads(session)
        self._check_openssl_enc_scripts(session)
        self._check_decode_commands_history(session)

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    # -- Decoding tool availability -------------------------------------------

    def _check_decode_tools(self, session: Session) -> None:
        tools = {
            "base64": "Base64 encoding/decoding",
            "xxd": "Hex dump and reverse",
            "openssl": "OpenSSL encryption/decryption",
            "certutil": "Certificate utility (decode capability)",
            "uudecode": "UU encoding/decoding",
        }
        found = []
        for tool, desc in tools.items():
            result = session.execute(f"which {tool} 2>/dev/null")
            if result.success and result.output.strip():
                found.append(f"{tool} ({desc}): {result.output.strip()}")

        if found:
            self.add_finding(
                title=f"Decoding/deobfuscation tools available ({len(found)} tools)",
                description="Standard decoding tools are available and could be used to decode obfuscated payloads",
                severity=Severity.LOW,
                evidence="\n".join(found),
                remediation="Remove unnecessary encoding/decoding tools from production systems where possible",
            )

    # -- Base64 decode in bash history ----------------------------------------

    def _check_base64_history(self, session: Session) -> None:
        result = session.execute(
            "grep -h 'base64.*-d\\|base64.*--decode' /home/*/.bash_history "
            "/root/.bash_history 2>/dev/null | tail -10"
        )
        if result.success and result.output.strip():
            entries = result.output.strip().splitlines()
            self.add_finding(
                title=f"Base64 decode commands found in bash history ({len(entries)} entries)",
                description="Recent base64 decode operations may indicate payload deobfuscation activity",
                severity=Severity.MEDIUM,
                evidence="\n".join(entries[:10]),
                remediation="Investigate base64 decode commands in history; audit what was decoded",
            )

    # -- Encoded payloads in temp directories ---------------------------------

    def _check_encoded_payloads(self, session: Session) -> None:
        # Look for files with high base64 content density
        result = session.execute(
            "find /tmp /dev/shm /var/tmp -type f -size +0 -size -10M 2>/dev/null | "
            "while read f; do "
            "head -1 \"$f\" 2>/dev/null | grep -qE '^[A-Za-z0-9+/]{40,}={0,2}$' && echo \"$f\"; "
            "done | head -10"
        )
        if result.success and result.output.strip():
            files = result.output.strip().splitlines()
            self.add_finding(
                title=f"Potential base64-encoded payloads in temp directories ({len(files)} files)",
                description="Files with base64-encoded content in temporary directories may be staged payloads",
                severity=Severity.HIGH,
                evidence="\n".join(files[:10]),
                remediation="Investigate encoded files in /tmp, /dev/shm, /var/tmp; decode and analyze contents",
            )

        # Check for hex-encoded files
        result = session.execute(
            "find /tmp /dev/shm /var/tmp -type f -size +0 -size -10M 2>/dev/null | "
            "while read f; do "
            "head -1 \"$f\" 2>/dev/null | grep -qE '^([0-9a-fA-F]{2}){20,}$' && echo \"$f\"; "
            "done | head -10"
        )
        if result.success and result.output.strip():
            hex_files = result.output.strip().splitlines()
            self.add_finding(
                title=f"Potential hex-encoded payloads in temp directories ({len(hex_files)} files)",
                description="Hex-encoded files in temp directories may be obfuscated malicious payloads",
                severity=Severity.HIGH,
                evidence="\n".join(hex_files[:10]),
                remediation="Investigate hex-encoded files; decode with xxd -r and analyze",
            )

    # -- openssl enc usage in scripts and crontabs ----------------------------

    def _check_openssl_enc_scripts(self, session: Session) -> None:
        result = session.execute(
            "grep -rl 'openssl.*enc\\|openssl.*-d\\|openssl.*aes' "
            "/etc/cron.d/ /etc/cron.daily/ /etc/cron.hourly/ /var/spool/cron/ "
            "/etc/init.d/ /usr/local/bin/ 2>/dev/null | head -10"
        )
        if result.success and result.output.strip():
            scripts = result.output.strip().splitlines()
            details = []
            for script in scripts[:5]:
                detail = session.execute(
                    f"grep -n 'openssl.*enc\\|openssl.*-d\\|openssl.*aes' {script} 2>/dev/null | head -3"
                )
                if detail.success and detail.output.strip():
                    details.append(f"{script}:\n{detail.output.strip()}")

            if details:
                self.add_finding(
                    title=f"OpenSSL encryption/decryption in scripts ({len(scripts)} files)",
                    description="Scripts using openssl enc may be decrypting obfuscated payloads at runtime",
                    severity=Severity.MEDIUM,
                    evidence="\n".join(details[:5]),
                    remediation="Audit scripts using openssl enc; verify encryption operations are authorized",
                )

    # -- Python/Perl decode commands in history -------------------------------

    def _check_decode_commands_history(self, session: Session) -> None:
        result = session.execute(
            "grep -hE '(python3?.*-c.*(decode|b64decode|base64)|"
            "perl.*-e.*(decode|unpack|MIME)|"
            "ruby.*-e.*(decode|unpack|Base64))' "
            "/home/*/.bash_history /root/.bash_history 2>/dev/null | tail -10"
        )
        if result.success and result.output.strip():
            entries = result.output.strip().splitlines()
            self.add_finding(
                title=f"Scripting language decode commands in history ({len(entries)} entries)",
                description="Python/Perl/Ruby decode one-liners in history may indicate payload deobfuscation",
                severity=Severity.MEDIUM,
                evidence="\n".join(entries[:10]),
                remediation="Investigate decode commands; check what data was decoded and its purpose",
            )

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Monitor temp directories (/tmp, /dev/shm, /var/tmp) for encoded payload staging with auditd",
            "Use auditd rules to log base64, xxd, and openssl command executions",
            "Mount /tmp and /dev/shm with noexec to prevent direct execution of decoded payloads",
            "Enable bash command logging via PROMPT_COMMAND or auditd execve auditing",
            "Deploy RHEL fapolicyd to prevent execution of decoded/dropped binaries",
        ]

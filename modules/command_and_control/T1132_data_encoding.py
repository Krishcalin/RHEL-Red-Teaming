"""T1132 — Data Encoding.

Checks for encoding tool availability that could be used to obfuscate
C2 communications on RHEL systems.
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class DataEncodingCheck(BaseModule):
    TECHNIQUE_ID = "T1132"
    TECHNIQUE_NAME = "Data Encoding"
    TACTIC = Tactic.COMMAND_AND_CONTROL
    SEVERITY = Severity.LOW
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        self._check_encoding_tools(session)
        self._check_scripting_encoding(session)

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def _check_encoding_tools(self, session: Session) -> None:
        tools = {"base64": "Base64 encoding", "xxd": "hex dump/encode",
                 "uuencode": "UU encoding", "openssl enc": "OpenSSL encoding"}
        for tool, desc in tools.items():
            cmd = tool.split()[0]
            result = session.execute(f"which {cmd} 2>/dev/null")
            if result.success and result.output.strip():
                self.add_finding(
                    title=f"Encoding tool available: {tool}",
                    description=f"{tool} ({desc}) can obfuscate C2 data",
                    severity=Severity.LOW,
                    evidence=result.output.strip(),
                    remediation=f"Monitor {cmd} usage with auditd if not needed operationally",
                )

    def _check_scripting_encoding(self, session: Session) -> None:
        for lang in ["python3", "perl", "ruby"]:
            result = session.execute(f"which {lang} 2>/dev/null")
            if result.success and result.output.strip():
                self.add_finding(
                    title=f"Scripting language available: {lang}",
                    description=f"{lang} provides built-in encoding/decoding libraries for C2 obfuscation",
                    severity=Severity.INFO,
                    evidence=result.output.strip(),
                    remediation=f"Remove {lang} from production if not needed; monitor with fapolicyd",
                )

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Monitor encoding tool usage with auditd rules",
            "Deploy network content inspection for encoded payloads",
            "Remove unnecessary scripting languages from production servers",
            "Use application allow-listing (fapolicyd) to restrict executables",
        ]

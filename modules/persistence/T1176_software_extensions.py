"""T1176 — Software Extensions.

Checks for persistence via browser extensions, IDE extensions, GNOME shell
extensions, and sudo plugins that could execute malicious code.
Sub-techniques: T1176.001 (Browser Extensions), T1176.002 (IDE Extensions).
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class SoftwareExtensionsCheck(BaseModule):
    TECHNIQUE_ID = "T1176"
    TECHNIQUE_NAME = "Software Extensions"
    TACTIC = Tactic.PERSISTENCE
    SEVERITY = Severity.MEDIUM
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        # ---- T1176.001: Browser Extensions ----

        # Check Chrome extensions for all users
        chrome_ext_dirs = session.execute(
            "find /home/*/.config/google-chrome/*/Extensions "
            "/home/*/.config/chromium/*/Extensions "
            "/root/.config/google-chrome/*/Extensions "
            "-maxdepth 2 -mindepth 1 -type d 2>/dev/null | head -30"
        )
        if chrome_ext_dirs.success and chrome_ext_dirs.output.strip():
            # Look for sideloaded extensions (not from Chrome Web Store)
            sideloaded = session.execute(
                "find /home/*/.config/google-chrome/*/Extensions "
                "/home/*/.config/chromium/*/Extensions "
                "-name 'manifest.json' -exec grep -l 'update_url' {} \\; 2>/dev/null "
                "| wc -l; "
                "find /home/*/.config/google-chrome/*/Extensions "
                "/home/*/.config/chromium/*/Extensions "
                "-name 'manifest.json' 2>/dev/null | wc -l"
            )
            if sideloaded.success and sideloaded.output.strip():
                lines = sideloaded.output.strip().splitlines()
                if len(lines) == 2:
                    store_count = int(lines[0].strip()) if lines[0].strip().isdigit() else 0
                    total_count = int(lines[1].strip()) if lines[1].strip().isdigit() else 0
                    sideloaded_count = total_count - store_count
                    if sideloaded_count > 0:
                        self.add_finding(
                            title=f"Sideloaded Chrome/Chromium extensions detected ({sideloaded_count})",
                            description=(
                                "Extensions installed outside the Chrome Web Store bypass "
                                "Google's review process and may contain malicious code."
                            ),
                            severity=Severity.MEDIUM,
                            evidence=f"Total extensions: {total_count}, Store extensions: {store_count}, Sideloaded: {sideloaded_count}",
                            remediation="Audit sideloaded extensions; use Chrome policies to whitelist approved extensions only",
                        )

        # Check for Chrome/Chromium force-installed extensions via policies
        chrome_policies = session.execute(
            "find /etc/opt/chrome/policies/ /etc/chromium/policies/ "
            "-name '*.json' 2>/dev/null | head -10"
        )
        if chrome_policies.success and chrome_policies.output.strip():
            force_install = session.execute(
                "grep -rl 'ExtensionInstallForcelist' /etc/opt/chrome/policies/ "
                "/etc/chromium/policies/ 2>/dev/null | head -5"
            )
            if force_install.success and force_install.output.strip():
                policy_content = session.execute(
                    "grep -A5 'ExtensionInstallForcelist' /etc/opt/chrome/policies/managed/*.json "
                    "/etc/chromium/policies/managed/*.json 2>/dev/null | head -20"
                )
                self.add_finding(
                    title="Force-installed browser extensions via policy",
                    description=(
                        "Browser policy forces installation of extensions. An attacker "
                        "with root access could add malicious extensions via policy files."
                    ),
                    severity=Severity.MEDIUM,
                    evidence=policy_content.output.strip() if policy_content.success else force_install.output.strip(),
                    remediation="Audit force-installed extensions in Chrome/Chromium policy files; compare against approved list",
                )

        # Check Firefox extensions for all users
        firefox_exts = session.execute(
            "find /home/*/.mozilla/firefox/*/extensions "
            "/root/.mozilla/firefox/*/extensions "
            "-type f \\( -name '*.xpi' -o -name '*.json' \\) 2>/dev/null | head -20"
        )
        if firefox_exts.success and firefox_exts.output.strip():
            # Check for unsigned/sideloaded extensions
            ext_count = len(firefox_exts.output.strip().splitlines())
            self.add_finding(
                title=f"Firefox extensions found ({ext_count} files)",
                description="Firefox extensions should be audited for unauthorized or malicious add-ons",
                severity=Severity.LOW,
                evidence=firefox_exts.output.strip()[:500],
                remediation="Audit Firefox extensions; use enterprise policies to restrict extension installation",
            )

        # Check Firefox enterprise policies
        ff_policies = session.execute(
            "cat /usr/lib64/firefox/distribution/policies.json 2>/dev/null; "
            "cat /etc/firefox/policies/policies.json 2>/dev/null"
        )
        if ff_policies.success and "ExtensionSettings" in ff_policies.output:
            self.add_finding(
                title="Firefox enterprise extension policies configured",
                description="Firefox policies control extension installation; verify these are authorized",
                severity=Severity.LOW,
                evidence=ff_policies.output.strip()[:300],
                remediation="Audit Firefox enterprise policies for unauthorized force-installed extensions",
            )

        # ---- T1176.002: IDE Extensions ----

        # Check VS Code extensions for all users
        vscode_exts = session.execute(
            "find /home/*/.vscode/extensions /root/.vscode/extensions "
            "/home/*/.vscode-server/extensions "
            "-maxdepth 1 -mindepth 1 -type d 2>/dev/null | head -30"
        )
        if vscode_exts.success and vscode_exts.output.strip():
            ext_list = vscode_exts.output.strip().splitlines()
            # Check for extensions with suspicious names or from unusual publishers
            suspicious_vscode = []
            for ext_dir in ext_list:
                ext_name = ext_dir.strip().split("/")[-1]
                # Flag extensions not from well-known publishers
                if ext_name and not any(
                    pub in ext_name.lower()
                    for pub in ["ms-", "microsoft.", "redhat.", "golang.", "rust-lang."]
                ):
                    suspicious_vscode.append(ext_name)

            if suspicious_vscode:
                self.add_finding(
                    title=f"VS Code extensions from non-standard publishers ({len(suspicious_vscode)})",
                    description=(
                        "VS Code extensions from unknown publishers could contain malicious code "
                        "that executes with the user's privileges."
                    ),
                    severity=Severity.MEDIUM,
                    evidence="\n".join(suspicious_vscode[:15]),
                    remediation="Audit VS Code extensions; use settings.sync with approved extension lists; restrict marketplace access",
                )

        # Check JetBrains plugin directories
        jetbrains_plugins = session.execute(
            "find /home/*/.local/share/JetBrains/*/plugins "
            "/root/.local/share/JetBrains/*/plugins "
            "-maxdepth 1 -mindepth 1 -type d 2>/dev/null | head -20"
        )
        if jetbrains_plugins.success and jetbrains_plugins.output.strip():
            plugin_count = len(jetbrains_plugins.output.strip().splitlines())
            self.add_finding(
                title=f"JetBrains IDE plugins found ({plugin_count})",
                description="JetBrains plugins can execute arbitrary code and should be audited for unauthorized additions",
                severity=Severity.LOW,
                evidence=jetbrains_plugins.output.strip()[:500],
                remediation="Audit JetBrains plugins; use organization-managed plugin repositories",
            )

        # Check for GNOME Shell extensions
        gnome_exts = session.execute(
            "find /home/*/.local/share/gnome-shell/extensions "
            "/usr/share/gnome-shell/extensions "
            "-maxdepth 1 -mindepth 1 -type d 2>/dev/null | head -20"
        )
        if gnome_exts.success and gnome_exts.output.strip():
            # Check for extensions not from RPM packages
            for ext_dir in gnome_exts.output.strip().splitlines()[:10]:
                ext_dir = ext_dir.strip()
                if "/usr/share/" in ext_dir:
                    rpm_check = session.execute(f"rpm -qf {ext_dir} 2>/dev/null")
                    if not rpm_check.success or "not owned" in rpm_check.output:
                        self.add_finding(
                            title=f"Unpackaged GNOME Shell extension: {ext_dir.split('/')[-1]}",
                            description="GNOME Shell extension not tracked by RPM may have been manually installed",
                            severity=Severity.MEDIUM,
                            evidence=ext_dir,
                            remediation="Audit GNOME Shell extensions; remove unauthorized extensions from /usr/share/gnome-shell/extensions/",
                        )
                elif "/.local/" in ext_dir:
                    # User-installed extensions — check metadata for suspicious permissions
                    metadata = session.execute(f"cat {ext_dir}/metadata.json 2>/dev/null")
                    if metadata.success and metadata.output.strip():
                        self.add_finding(
                            title=f"User-installed GNOME extension: {ext_dir.split('/')[-1]}",
                            description="User-installed GNOME Shell extensions run with user privileges and should be audited",
                            severity=Severity.LOW,
                            evidence=f"Path: {ext_dir}",
                            remediation="Review user GNOME extensions; use org.gnome.shell disable-extension-version-validation lock",
                        )

        # Check for sudo plugins
        sudo_plugins = session.execute(
            "find /usr/libexec/sudo/ /usr/lib64/sudo/ -name '*.so' 2>/dev/null | head -10"
        )
        if sudo_plugins.success and sudo_plugins.output.strip():
            for plugin in sudo_plugins.output.strip().splitlines():
                plugin = plugin.strip()
                rpm_check = session.execute(f"rpm -qf {plugin} 2>/dev/null")
                if not rpm_check.success or "not owned" in rpm_check.output:
                    self.add_finding(
                        title=f"Unpackaged sudo plugin: {plugin}",
                        description=(
                            "A sudo plugin not tracked by RPM could intercept or modify "
                            "sudo authentication, providing persistent privileged access."
                        ),
                        severity=Severity.CRITICAL,
                        evidence=plugin,
                        remediation="Audit sudo plugins; remove unauthorized .so files; verify with rpm -V sudo",
                    )

        # Check sudoers for plugin directives
        sudo_plugin_conf = session.execute(
            "grep -E '^Plugin' /etc/sudo.conf 2>/dev/null"
        )
        if sudo_plugin_conf.success and sudo_plugin_conf.output.strip():
            self.add_finding(
                title="Custom sudo plugins configured in /etc/sudo.conf",
                description="Custom Plugin directives in sudo.conf may load malicious shared libraries during sudo execution",
                severity=Severity.HIGH,
                evidence=sudo_plugin_conf.output.strip(),
                remediation="Audit Plugin entries in /etc/sudo.conf; ensure only authorized plugins (sudoers.so) are loaded",
            )

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Deploy browser policies (Chrome/Firefox enterprise) to whitelist approved extensions and block sideloading",
            "Monitor GNOME Shell extension directories and sudo plugin paths with auditd file watches",
            "Restrict VS Code and JetBrains extension installation to approved marketplace sources via settings policies",
            "Verify sudo plugin integrity with rpm -V sudo and audit /etc/sudo.conf for unauthorized Plugin directives",
            "Use SELinux to confine browser and IDE processes, limiting the impact of malicious extensions",
        ]

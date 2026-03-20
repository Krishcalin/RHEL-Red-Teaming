"""T1505 — Server Software Component.

Checks for persistence via server software components such as SQL stored
procedures, web shells, and web server modules.
Sub-techniques: T1505.001 (SQL Stored Procedures), T1505.003 (Web Shell).
"""

from __future__ import annotations

from core.models import ModuleResult, Severity, Status, Tactic
from core.session import Session
from modules.base import BaseModule


class ServerComponentCheck(BaseModule):
    TECHNIQUE_ID = "T1505"
    TECHNIQUE_NAME = "Server Software Component"
    TACTIC = Tactic.PERSISTENCE
    SEVERITY = Severity.HIGH
    SUPPORTED_OS = ["rhel8", "rhel9"]
    REQUIRES_ROOT = False
    SAFE_MODE = True

    def check(self, session: Session) -> ModuleResult:
        # ---- T1505.001: SQL Stored Procedures / UDFs ----

        # Check for PostgreSQL running
        pg_running = session.execute("systemctl is-active postgresql 2>/dev/null")
        if pg_running.success and "active" in pg_running.output.strip():
            # Check for user-defined functions in PostgreSQL
            pg_udfs = session.execute(
                "sudo -u postgres psql -t -c "
                "\"SELECT proname, prosrc FROM pg_proc WHERE pronamespace NOT IN "
                "(SELECT oid FROM pg_namespace WHERE nspname IN ('pg_catalog','information_schema')) "
                "LIMIT 20;\" 2>/dev/null"
            )
            if pg_udfs.success and pg_udfs.output.strip():
                self.add_finding(
                    title="PostgreSQL user-defined functions found",
                    description=(
                        "User-defined functions in PostgreSQL could be abused as stored "
                        "procedure backdoors for persistence and code execution."
                    ),
                    severity=Severity.HIGH,
                    evidence=pg_udfs.output.strip()[:500],
                    remediation="Audit all user-defined functions; remove unauthorized UDFs; restrict CREATE FUNCTION privilege",
                )

            # Check for PostgreSQL extension directories with unusual files
            pg_lib_dir = session.execute(
                "pg_config --pkglibdir 2>/dev/null || echo '/usr/pgsql-*/lib'"
            )
            if pg_lib_dir.success and pg_lib_dir.output.strip():
                lib_path = pg_lib_dir.output.strip().splitlines()[0]
                unpackaged_libs = session.execute(
                    f"find {lib_path} -name '*.so' -newer /var/lib/rpm/Packages 2>/dev/null | head -10"
                )
                if unpackaged_libs.success and unpackaged_libs.output.strip():
                    self.add_finding(
                        title="Recently added PostgreSQL shared libraries",
                        description="Shared libraries newer than the RPM database may indicate malicious UDF installation",
                        severity=Severity.HIGH,
                        evidence=unpackaged_libs.output.strip(),
                        remediation="Audit shared libraries in PostgreSQL lib directory; verify against RPM with rpm -qf",
                    )

        # Check for MySQL/MariaDB running
        for db_service in ["mysqld", "mariadb"]:
            db_running = session.execute(f"systemctl is-active {db_service} 2>/dev/null")
            if db_running.success and "active" in db_running.output.strip():
                # Check for UDF directory
                udf_dir = session.execute(
                    "mysql -N -e \"SHOW VARIABLES LIKE 'plugin_dir';\" 2>/dev/null"
                )
                if udf_dir.success and udf_dir.output.strip():
                    plugin_path = udf_dir.output.strip().split()[-1] if udf_dir.output.strip() else ""
                    if plugin_path:
                        udf_files = session.execute(
                            f"find {plugin_path} -name '*.so' -not -path '*/ha_*' 2>/dev/null "
                            f"| head -10"
                        )
                        if udf_files.success and udf_files.output.strip():
                            # Cross-check with RPM
                            for so_file in udf_files.output.strip().splitlines()[:5]:
                                rpm_check = session.execute(f"rpm -qf {so_file.strip()} 2>/dev/null")
                                if not rpm_check.success or "not owned" in rpm_check.output:
                                    self.add_finding(
                                        title=f"Unpackaged MySQL/MariaDB plugin: {so_file.strip()}",
                                        description="Plugin shared library not tracked by RPM may be a malicious UDF",
                                        severity=Severity.HIGH,
                                        evidence=so_file.strip(),
                                        remediation="Audit unpackaged plugins; check MySQL UDF list with SELECT * FROM mysql.func;",
                                    )

                # Check for loaded UDFs
                loaded_udfs = session.execute(
                    "mysql -N -e 'SELECT * FROM mysql.func;' 2>/dev/null"
                )
                if loaded_udfs.success and loaded_udfs.output.strip():
                    self.add_finding(
                        title="MySQL/MariaDB user-defined functions loaded",
                        description="Loaded UDFs can execute arbitrary code and persist across restarts",
                        severity=Severity.HIGH,
                        evidence=loaded_udfs.output.strip()[:500],
                        remediation="Audit UDFs: DROP FUNCTION for unauthorized entries; restrict FILE privilege",
                    )

        # ---- T1505.003: Web Shell ----

        # Check web roots for suspicious PHP/JSP/ASPX files
        web_roots = [
            "/var/www/",
            "/usr/share/nginx/",
            "/opt/",
            "/srv/www/",
        ]
        suspicious_patterns = (
            "eval\\(\\$_\\|exec(\\$_\\|system(\\$_\\|passthru(\\$_\\|shell_exec(\\$_"
            "\\|base64_decode(\\$_\\|assert(\\$_\\|preg_replace.*\\/e"
        )

        for web_root in web_roots:
            dir_exists = session.execute(f"test -d {web_root} && echo exists")
            if not dir_exists.success or "exists" not in dir_exists.output:
                continue

            # Check for PHP/JSP files with suspicious content
            webshell_check = session.execute(
                f"grep -rlE '(eval\\(\\$_(GET|POST|REQUEST)|exec\\(\\$_|system\\(\\$_|"
                f"passthru\\(|shell_exec\\(|base64_decode\\(\\$_(GET|POST|REQUEST)|"
                f"assert\\(\\$_|preg_replace\\(.*\\/e)' "
                f"--include='*.php' --include='*.jsp' --include='*.jspx' "
                f"--include='*.asp' --include='*.aspx' --include='*.phtml' "
                f"{web_root} 2>/dev/null | head -10"
            )
            if webshell_check.success and webshell_check.output.strip():
                self.add_finding(
                    title=f"Potential web shells detected in {web_root}",
                    description=(
                        "Files containing suspicious function calls (eval, exec, system, "
                        "passthru, shell_exec) with user input were found in web-accessible directories."
                    ),
                    severity=Severity.CRITICAL,
                    evidence=webshell_check.output.strip(),
                    remediation="Investigate flagged files immediately; compare against known-good backups; deploy WAF rules",
                )

            # Check for recently modified web files (last 3 days)
            recent_web = session.execute(
                f"find {web_root} \\( -name '*.php' -o -name '*.jsp' -o -name '*.py' \\) "
                f"-mtime -3 2>/dev/null | head -15"
            )
            if recent_web.success and recent_web.output.strip():
                self.add_finding(
                    title=f"Recently modified web scripts in {web_root}",
                    description="Web scripts modified in the last 3 days should be reviewed for unauthorized changes",
                    severity=Severity.MEDIUM,
                    evidence=recent_web.output.strip(),
                    remediation="Compare modified files against version control or known-good checksums",
                )

        # Check for web server modules in non-standard locations
        # Apache modules
        apache_modules = session.execute(
            "find /etc/httpd/modules/ /usr/lib64/httpd/modules/ -name '*.so' 2>/dev/null "
            "| while read f; do rpm -qf \"$f\" 2>/dev/null | grep -q 'not owned' && echo \"UNPACKAGED: $f\"; done "
            "| head -10"
        )
        if apache_modules.success and apache_modules.output.strip():
            self.add_finding(
                title="Unpackaged Apache modules detected",
                description="Apache modules not tracked by RPM may have been manually installed for backdoor access",
                severity=Severity.HIGH,
                evidence=apache_modules.output.strip(),
                remediation="Audit unpackaged Apache modules; verify against known-good state; remove unauthorized .so files",
            )

        # Nginx modules in non-standard locations
        nginx_modules = session.execute(
            "nginx -V 2>&1 | grep -o 'modules-path=[^ ]*' 2>/dev/null; "
            "find /etc/nginx/modules/ /usr/lib64/nginx/modules/ -name '*.so' 2>/dev/null "
            "| while read f; do rpm -qf \"$f\" 2>/dev/null | grep -q 'not owned' && echo \"UNPACKAGED: $f\"; done "
            "| head -10"
        )
        if nginx_modules.success and nginx_modules.output.strip() and "UNPACKAGED" in nginx_modules.output:
            self.add_finding(
                title="Unpackaged nginx modules detected",
                description="Nginx modules not tracked by RPM may be backdoored or unauthorized",
                severity=Severity.HIGH,
                evidence=nginx_modules.output.strip(),
                remediation="Audit nginx modules directory; verify with rpm -qf; remove unauthorized modules",
            )

        # Check httpd/nginx configs for suspicious include directives
        for cfg_pattern in ["/etc/httpd/conf.d/*.conf", "/etc/nginx/conf.d/*.conf", "/etc/nginx/nginx.conf"]:
            suspicious_includes = session.execute(
                f"grep -rE '(Include|include).*(/tmp/|/dev/shm/|/var/tmp/|/home/)' {cfg_pattern} 2>/dev/null | head -5"
            )
            if suspicious_includes.success and suspicious_includes.output.strip():
                self.add_finding(
                    title="Web server config includes from suspicious paths",
                    description="Web server configuration includes files from temporary or user-writable directories",
                    severity=Severity.CRITICAL,
                    evidence=suspicious_includes.output.strip(),
                    remediation="Remove include directives pointing to /tmp, /dev/shm, or /home; audit web server configs",
                )

        status = Status.VULNERABLE if self._findings else Status.NOT_VULNERABLE
        return self.make_result(status)

    def simulate(self, session: Session) -> ModuleResult:
        return self.check(session)

    def get_mitigations(self) -> list[str]:
        return [
            "Deploy file integrity monitoring (AIDE/OSSEC) on web roots and web server module directories",
            "Restrict database UDF creation privileges; disable FILE privilege for MySQL/MariaDB users",
            "Mount web content directories with noexec where feasible; use SELinux httpd_sys_content_t contexts",
            "Audit web server modules with rpm -V and remove unpackaged .so files from module directories",
            "Implement WAF rules to detect web shell patterns and monitor web roots for unauthorized file changes",
        ]

"""Core scan engine with module auto-discovery."""

from __future__ import annotations

import importlib
import inspect
import pkgutil
import uuid
from datetime import datetime
from pathlib import Path

import structlog
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.table import Table

import modules
from core.logger import EvidenceLogger
from core.models import (
    ModuleResult,
    ScanConfig,
    ScanResult,
    Status,
    Tactic,
    Target,
)
from core.session import Session
from modules.base import BaseModule

log = structlog.get_logger("engine")
console = Console()


class ScanEngine:
    """Main orchestrator that discovers modules, manages sessions, and runs scans."""

    def __init__(self, config: ScanConfig):
        self.config = config
        self.modules: list[BaseModule] = []
        self.evidence_logger = EvidenceLogger(config.evidence_dir)
        self._discover_modules()

    def _discover_modules(self) -> None:
        """Auto-discover all technique modules in the modules/ directory."""
        self.modules = []
        modules_path = Path(modules.__file__).parent

        for importer, modname, ispkg in pkgutil.walk_packages(
            [str(modules_path)], prefix="modules."
        ):
            if modname == "modules.base":
                continue
            try:
                module = importlib.import_module(modname)
                for name, obj in inspect.getmembers(module, inspect.isclass):
                    if (
                        issubclass(obj, BaseModule)
                        and obj is not BaseModule
                        and obj.TECHNIQUE_ID
                    ):
                        self.modules.append(obj())
                        log.debug("module_discovered", module=name, technique=obj.TECHNIQUE_ID)
            except Exception as e:
                log.warning("module_load_failed", module=modname, error=str(e))

        log.info("modules_discovered", count=len(self.modules))

    def _filter_modules(self) -> list[BaseModule]:
        """Filter modules based on scan configuration."""
        filtered = list(self.modules)

        if self.config.tactics:
            filtered = [m for m in filtered if m.TACTIC in self.config.tactics]

        if self.config.techniques:
            filtered = [m for m in filtered if m.TECHNIQUE_ID in self.config.techniques]

        return filtered

    def _display_banner(self, target: Target) -> None:
        """Display authorization banner before scanning."""
        console.print()
        console.print("[bold red]" + "=" * 70 + "[/]")
        console.print("[bold red]  RHEL Red Teaming Tool — MITRE ATT&CK Security Scanner[/]")
        console.print("[bold red]" + "=" * 70 + "[/]")
        console.print()
        console.print("[yellow]  WARNING: This tool performs active security testing.[/]")
        console.print("[yellow]  Ensure you have proper authorization before proceeding.[/]")
        console.print()
        console.print(f"  Target:   [cyan]{target.host}[/]")
        console.print(f"  Mode:     [cyan]{'Simulate' if self.config.simulate else 'Check-only'}[/]")
        console.print(f"  Profile:  [cyan]{self.config.profile}[/]")
        console.print(f"  Modules:  [cyan]{len(self._filter_modules())}[/]")
        console.print()
        console.print("[bold red]" + "=" * 70 + "[/]")
        console.print()

    def _display_results_table(self, results: list[ModuleResult]) -> None:
        """Display scan results as a rich table."""
        table = Table(title="Scan Results", show_lines=True)
        table.add_column("Technique", style="cyan", min_width=12)
        table.add_column("Name", style="white", min_width=30)
        table.add_column("Status", min_width=15)
        table.add_column("Findings", justify="center", min_width=8)
        table.add_column("Severity", min_width=10)
        table.add_column("Duration", justify="right", min_width=8)

        status_styles = {
            Status.VULNERABLE: "[bold red]VULNERABLE[/]",
            Status.NOT_VULNERABLE: "[green]SECURE[/]",
            Status.ERROR: "[yellow]ERROR[/]",
            Status.SKIPPED: "[dim]SKIPPED[/]",
            Status.PARTIAL: "[yellow]PARTIAL[/]",
        }

        severity_styles = {
            "critical": "[bold red]CRITICAL[/]",
            "high": "[red]HIGH[/]",
            "medium": "[yellow]MEDIUM[/]",
            "low": "[blue]LOW[/]",
            "info": "[dim]INFO[/]",
        }

        for r in results:
            table.add_row(
                r.technique_id,
                r.technique_name,
                status_styles.get(r.status, str(r.status)),
                str(r.finding_count),
                severity_styles.get(r.max_severity.value, r.max_severity.value),
                f"{r.duration_seconds:.1f}s",
            )

        console.print()
        console.print(table)

    def run(self, target: Target) -> ScanResult:
        """Execute a full scan against a target."""
        scan_id = str(uuid.uuid4())[:8]
        scan_result = ScanResult(
            scan_id=scan_id,
            config=self.config,
            start_time=datetime.now(),
        )

        self._display_banner(target)

        active_modules = self._filter_modules()
        if not active_modules:
            console.print("[yellow]No modules matched the filter criteria.[/]")
            scan_result.end_time = datetime.now()
            return scan_result

        with Session(target) as session:
            os_info = session.get_os_info()
            scan_result.target_info = os_info
            os_id = self._detect_os_id(os_info)

            log.info("scan_start", scan_id=scan_id, target=target.host, os=os_id)

            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
                console=console,
            ) as progress:
                task = progress.add_task("Scanning...", total=len(active_modules))

                for module in active_modules:
                    progress.update(
                        task,
                        description=f"[cyan]{module.TECHNIQUE_ID}[/] {module.TECHNIQUE_NAME}",
                    )

                    if not module.is_supported(os_id):
                        result = ModuleResult(
                            technique_id=module.TECHNIQUE_ID,
                            technique_name=module.TECHNIQUE_NAME,
                            tactic=module.TACTIC,
                            status=Status.SKIPPED,
                            target_host=target.host,
                            error_message=f"OS {os_id} not supported",
                        )
                    elif module.REQUIRES_ROOT and not self._has_root(session):
                        result = ModuleResult(
                            technique_id=module.TECHNIQUE_ID,
                            technique_name=module.TECHNIQUE_NAME,
                            tactic=module.TACTIC,
                            status=Status.SKIPPED,
                            target_host=target.host,
                            error_message="Requires root privileges",
                        )
                    else:
                        result = module.run(session, simulate=self.config.simulate)

                        if self.config.simulate and result.is_vulnerable:
                            try:
                                module.cleanup(session)
                                log.info("cleanup_complete", technique=module.TECHNIQUE_ID)
                            except Exception as e:
                                log.error(
                                    "cleanup_failed",
                                    technique=module.TECHNIQUE_ID,
                                    error=str(e),
                                )

                    scan_result.results.append(result)
                    progress.advance(task)

        scan_result.end_time = datetime.now()

        self._display_results_table(scan_result.results)
        self._display_summary(scan_result)

        log.info(
            "scan_complete",
            scan_id=scan_id,
            total=scan_result.total_checks,
            vulnerable=scan_result.vulnerable_count,
            duration=f"{scan_result.duration_seconds:.1f}s",
        )

        return scan_result

    def _detect_os_id(self, os_info: dict[str, str]) -> str:
        """Detect RHEL version from OS info."""
        version_id = os_info.get("VERSION_ID", "")
        platform_id = os_info.get("PLATFORM_ID", "")
        name = os_info.get("ID", "").lower()

        if "rhel" in name or "redhat" in name or "red hat" in platform_id.lower():
            if version_id.startswith("9"):
                return "rhel9"
            if version_id.startswith("8"):
                return "rhel8"
        return f"{name}{version_id}"

    def _has_root(self, session: Session) -> bool:
        """Check if session has root privileges."""
        result = session.execute("id -u")
        return result.output == "0"

    def _display_summary(self, scan_result: ScanResult) -> None:
        """Display executive summary of scan results."""
        total = scan_result.total_checks
        vuln = scan_result.vulnerable_count
        secure = sum(1 for r in scan_result.results if r.status == Status.NOT_VULNERABLE)
        errors = sum(1 for r in scan_result.results if r.status == Status.ERROR)
        skipped = sum(1 for r in scan_result.results if r.status == Status.SKIPPED)

        console.print()
        console.print("[bold]Scan Summary[/]")
        console.print(f"  Scan ID:      [cyan]{scan_result.scan_id}[/]")
        console.print(f"  Duration:     [cyan]{scan_result.duration_seconds:.1f}s[/]")
        console.print(f"  Total checks: [cyan]{total}[/]")
        console.print(f"  Vulnerable:   [bold red]{vuln}[/]")
        console.print(f"  Secure:       [green]{secure}[/]")
        console.print(f"  Errors:       [yellow]{errors}[/]")
        console.print(f"  Skipped:      [dim]{skipped}[/]")
        console.print()

"""CLI entry point for RHEL Red Teaming tool."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click
import yaml
from rich.console import Console

from core.banner import display_compact_banner
from core.engine import ScanEngine
from core.logger import setup_logging
from core.mitre_mapper import MitreMapper
from core.models import ScanConfig, ScanResult, SessionType, Tactic, Target
from core.reporter import Reporter

console = Console()


def load_config(config_path: str = "config/settings.yaml") -> dict:
    """Load YAML configuration file."""
    path = Path(config_path)
    if not path.exists():
        console.print(f"[red]Config file not found: {config_path}[/]")
        sys.exit(1)
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def load_profile(profile_name: str) -> dict:
    """Load a scan profile."""
    path = Path(f"config/profiles/{profile_name}.yaml")
    if not path.exists():
        console.print(f"[yellow]Profile not found: {profile_name}, using defaults[/]")
        return {}
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def parse_tactic(name: str) -> Tactic | None:
    """Convert tactic name string to Tactic enum."""
    try:
        return Tactic(name.lower().replace("-", "_").replace(" ", "_"))
    except ValueError:
        return None


@click.group()
@click.version_option(version="0.1.0", prog_name="rhel-rt")
def cli() -> None:
    """RHEL Red Teaming Tool — MITRE ATT&CK Security Scanner."""
    pass


@cli.command()
@click.option("--target", "-t", required=True, help="Target host (IP or hostname)")
@click.option("--port", "-p", default=22, help="SSH port (default: 22)")
@click.option("--username", "-u", default=None, help="SSH username")
@click.option("--password", default=None, help="SSH password")
@click.option("--key-file", "-k", default=None, help="SSH private key file")
@click.option("--profile", default="quick", help="Scan profile (quick/full/stealth)")
@click.option("--simulate", is_flag=True, help="Enable active simulation mode")
@click.option("--tactic", default=None, help="Run only a specific tactic")
@click.option("--technique", default=None, help="Run only a specific technique ID")
@click.option("--config", "config_path", default="config/settings.yaml", help="Config file path")
@click.option("--format", "output_format", default="json", type=click.Choice(["json", "csv", "html"]))
@click.option("--timeout", default=300, help="Command timeout in seconds")
def scan(
    target: str,
    port: int,
    username: str | None,
    password: str | None,
    key_file: str | None,
    profile: str,
    simulate: bool,
    tactic: str | None,
    technique: str | None,
    config_path: str,
    output_format: str,
    timeout: int,
) -> None:
    """Run a security scan against a target."""
    settings = load_config(config_path)
    profile_config = load_profile(profile)

    setup_logging(
        log_level=settings.get("output", {}).get("log_level", "INFO"),
        log_file=settings.get("output", {}).get("log_file"),
        json_output=settings.get("output", {}).get("json_logging", False),
    )

    # Determine session type
    is_local = target in ("localhost", "127.0.0.1", "::1")
    session_type = SessionType.LOCAL if is_local else SessionType.SSH

    scan_target = Target(
        host=target,
        port=port,
        username=username,
        password=password,
        key_file=key_file,
        session_type=session_type,
    )

    # Build tactics filter
    tactics_filter: list[Tactic] | None = None
    if tactic:
        parsed = parse_tactic(tactic)
        if parsed:
            tactics_filter = [parsed]
        else:
            console.print(f"[red]Unknown tactic: {tactic}[/]")
            sys.exit(1)
    elif profile_config.get("tactics"):
        tactics_filter = []
        for t in profile_config["tactics"]:
            parsed = parse_tactic(t)
            if parsed:
                tactics_filter.append(parsed)

    # Build techniques filter
    techniques_filter: list[str] | None = None
    if technique:
        techniques_filter = [technique]

    scan_config = ScanConfig(
        targets=[scan_target],
        profile=profile,
        simulate=simulate,
        tactics=tactics_filter,
        techniques=techniques_filter,
        timeout=timeout,
        output_dir=settings.get("output", {}).get("report_dir", "reports"),
        evidence_dir=settings.get("output", {}).get("evidence_dir", "evidence"),
    )

    # Run scan
    engine = ScanEngine(scan_config)
    result = engine.run(scan_target)

    # Generate reports
    reporter = Reporter(output_dir=scan_config.output_dir)
    report_path = reporter.generate(result, fmt=output_format)
    console.print(f"\nReport saved: [cyan]{report_path}[/]")

    # Generate ATT&CK Navigator layer
    mapper = MitreMapper(output_dir=scan_config.output_dir)
    layer_path = mapper.generate_layer(result)
    console.print(f"ATT&CK layer: [cyan]{layer_path}[/]")


@cli.command()
@click.option("--input", "input_path", required=True, help="Path to scan result JSON")
@click.option("--format", "output_format", default="html", type=click.Choice(["json", "csv", "html"]))
def report(input_path: str, output_format: str) -> None:
    """Generate a report from a previous scan result."""
    path = Path(input_path)
    if not path.exists():
        console.print(f"[red]Input file not found: {input_path}[/]")
        sys.exit(1)

    data = json.loads(path.read_text(encoding="utf-8"))

    # Reconstruct ScanResult from JSON
    scan_result = ScanResult(
        scan_id=data["scan_id"],
        config=ScanConfig(),
        start_time=data.get("start_time", ""),
        target_info=data.get("target_info", {}),
    )

    reporter = Reporter()
    report_path = reporter.generate(scan_result, fmt=output_format)
    console.print(f"Report saved: [cyan]{report_path}[/]")


@cli.command(name="list-modules")
def list_modules() -> None:
    """List all discovered technique modules."""
    display_compact_banner(console)
    setup_logging(log_level="WARNING")

    config = ScanConfig()
    engine = ScanEngine(config)

    if not engine.modules:
        console.print("[yellow]No modules found. Add technique modules to modules/ directory.[/]")
        return

    from rich.table import Table

    table = Table(title="Available Modules")
    table.add_column("Technique ID", style="cyan")
    table.add_column("Name", style="white")
    table.add_column("Tactic", style="green")
    table.add_column("Severity", style="yellow")
    table.add_column("Root", justify="center")
    table.add_column("Safe", justify="center")

    for m in sorted(engine.modules, key=lambda x: x.TECHNIQUE_ID):
        table.add_row(
            m.TECHNIQUE_ID,
            m.TECHNIQUE_NAME,
            m.TACTIC.value.replace("_", " ").title(),
            m.SEVERITY.value.upper(),
            "[red]Yes[/]" if m.REQUIRES_ROOT else "No",
            "[green]Yes[/]" if m.SAFE_MODE else "[red]No[/]",
        )

    console.print(table)
    console.print(f"\nTotal: [cyan]{len(engine.modules)}[/] modules")


@cli.command(name="list-tactics")
def list_tactics() -> None:
    """List all supported ATT&CK tactics."""
    display_compact_banner(console)
    from rich.table import Table

    table = Table(title="MITRE ATT&CK Tactics")
    table.add_column("Tactic", style="cyan")
    table.add_column("CLI Name", style="green")

    for tactic in Tactic:
        table.add_row(
            tactic.value.replace("_", " ").title(),
            tactic.value,
        )

    console.print(table)


if __name__ == "__main__":
    cli()

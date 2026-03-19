"""Professional banner display for RHEL Red Teaming tool."""

from __future__ import annotations

from datetime import datetime

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

VERSION = "0.1.0"

# fmt: off
LOGO = r"""
[bold red]  ██████╗  ██╗  ██╗ ███████╗ ██╗          ██████╗  ████████╗[/]
[bold red]  ██╔══██╗ ██║  ██║ ██╔════╝ ██║          ██╔══██╗ ╚══██╔══╝[/]
[bold red]  ██████╔╝ ███████║ █████╗   ██║    █████╗██████╔╝    ██║   [/]
[bold red]  ██╔══██╗ ██╔══██║ ██╔══╝   ██║    ╚════╝██╔══██╗    ██║   [/]
[bold red]  ██║  ██║ ██║  ██║ ███████╗ ███████╗     ██║  ██║    ██║   [/]
[bold red]  ╚═╝  ╚═╝ ╚═╝  ╚═╝ ╚══════╝ ╚══════╝     ╚═╝  ╚═╝    ╚═╝   [/]
[bold white]  ────────────────────────────────────────────────────────────[/]
[dim white]  Red Hat Enterprise Linux  [/][bold yellow]|[/][dim white]  Red Team Security Scanner  [/]
[dim white]  MITRE ATT&CK Framework   [/][bold yellow]|[/][dim white]  v{version}                    [/]"""
# fmt: on

AUTH_WARNING = """[bold yellow]
  ╔══════════════════════════════════════════════════════════════════╗
  ║  [bold red]AUTHORIZATION REQUIRED[/bold red]                                        ║
  ║                                                                  ║
  ║  This tool performs [bold white]active security testing[/bold white] against target      ║
  ║  systems. Unauthorized use is [bold red]prohibited[/bold red] and may violate         ║
  ║  applicable laws and regulations.                                ║
  ║                                                                  ║
  ║  By proceeding, you confirm that you have [bold white]explicit written[/bold white]      ║
  ║  [bold white]authorization[/bold white] to test the target system(s).                    ║
  ╚══════════════════════════════════════════════════════════════════╝[/]"""


def display_banner(
    console: Console,
    target_host: str,
    mode: str,
    profile: str,
    module_count: int,
    os_info: dict[str, str] | None = None,
) -> None:
    """Display the full professional banner with scan details."""
    console.print()
    console.print(LOGO.format(version=VERSION))
    console.print(AUTH_WARNING)
    console.print()

    # Scan configuration table
    info_table = Table(
        show_header=False,
        box=None,
        padding=(0, 2),
        expand=False,
    )
    info_table.add_column("Key", style="dim white", min_width=14)
    info_table.add_column("Value", style="bold cyan")

    info_table.add_row("  Target", target_host)
    info_table.add_row("  Mode", mode)
    info_table.add_row("  Profile", profile.upper())
    info_table.add_row("  Modules", str(module_count))
    info_table.add_row("  Timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

    if os_info:
        os_name = os_info.get("PRETTY_NAME", os_info.get("NAME", "Unknown"))
        kernel = os_info.get("kernel", "Unknown")
        hostname = os_info.get("hostname", "Unknown")
        info_table.add_row("  Hostname", hostname)
        info_table.add_row("  OS", os_name)
        info_table.add_row("  Kernel", kernel)

    console.print(
        Panel(
            info_table,
            title="[bold white]Scan Configuration[/]",
            border_style="bright_blue",
            padding=(1, 2),
        )
    )
    console.print()


def display_compact_banner(console: Console) -> None:
    """Display a minimal banner for non-scan commands."""
    console.print()
    console.print(
        "[bold red]RHEL-RT[/] [dim]|[/] "
        "[white]Red Team Security Scanner[/] [dim]|[/] "
        f"[dim]v{VERSION}[/] [dim]|[/] "
        "[dim]MITRE ATT&CK Framework[/]"
    )
    console.print("[dim]" + "─" * 65 + "[/]")
    console.print()

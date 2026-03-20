"""Professional banner display for RHEL Red Teaming tool."""

from __future__ import annotations

from datetime import datetime

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

VERSION = "0.1.0"
CODENAME = "Nightshade"
MODULE_COUNT = 108
TACTIC_COUNT = 9

# fmt: off
LOGO = (
    "[bold red]"
    "  ██████╗  ██╗  ██╗ ███████╗ ██╗          ██████╗  ████████╗\n"
    "  ██╔══██╗ ██║  ██║ ██╔════╝ ██║          ██╔══██╗ ╚══██╔══╝\n"
    "  ██████╔╝ ███████║ █████╗   ██║    █████╗██████╔╝    ██║   \n"
    "  ██╔══██╗ ██╔══██║ ██╔══╝   ██║    ╚════╝██╔══██╗    ██║   \n"
    "  ██║  ██║ ██║  ██║ ███████╗ ███████╗     ██║  ██║    ██║   \n"
    "  ╚═╝  ╚═╝ ╚═╝  ╚═╝ ╚══════╝ ╚══════╝     ╚═╝  ╚═╝    ╚═╝   \n"
    "[/]"
)
# fmt: on

TAGLINE = (
    "[bold white]Red Hat Enterprise Linux[/]  [dim]│[/]  "
    "[bold white]Red Team Security Scanner[/]  [dim]│[/]  "
    "[bold white]MITRE ATT&CK[/]"
)

AUTH_NOTICE = (
    "[bold red]AUTHORIZATION REQUIRED[/bold red]  "
    "This tool performs active security testing. Unauthorized use is "
    "[bold red]prohibited[/bold red] and may violate applicable laws. "
    "By proceeding you confirm [bold white]explicit written authorization[/bold white] "
    "to test the target system(s)."
)


def _severity_label(mode: str) -> str:
    """Return a styled mode label."""
    if "SIMULATE" in mode.upper():
        return "[bold red on #3a0000] SIMULATE [/]"
    return "[bold green on #003a00] CHECK-ONLY [/]"


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

    # ── Logo ──
    console.print(LOGO, highlight=False)
    console.print(f"  {TAGLINE}")
    console.print(
        f"  [dim]v{VERSION}[/]  [dim]│[/]  "
        f"[dim]{CODENAME}[/]  [dim]│[/]  "
        f"[dim]{MODULE_COUNT} modules[/]  [dim]│[/]  "
        f"[dim]{TACTIC_COUNT} tactics[/]"
    )
    console.print()

    # ── Authorization Warning ──
    console.print(
        Panel(
            AUTH_NOTICE,
            border_style="red",
            title="[bold red]WARNING[/]",
            title_align="left",
            padding=(1, 2),
        )
    )

    # ── Scan Configuration ──
    left_table = Table(
        show_header=False,
        box=None,
        padding=(0, 1),
        expand=True,
    )
    left_table.add_column("Key", style="dim white", min_width=12, no_wrap=True)
    left_table.add_column("Value", style="bold cyan")

    left_table.add_row("  Target", f"[bold white]{target_host}[/]")
    left_table.add_row("  Mode", _severity_label(mode))
    left_table.add_row("  Profile", f"[bold yellow]{profile.upper()}[/]")
    left_table.add_row("  Modules", f"[bold]{module_count}[/] loaded")
    left_table.add_row("  Started", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

    right_table = Table(
        show_header=False,
        box=None,
        padding=(0, 1),
        expand=True,
    )
    right_table.add_column("Key", style="dim white", min_width=12, no_wrap=True)
    right_table.add_column("Value", style="bold cyan")

    if os_info:
        hostname = os_info.get("hostname", "—")
        os_name = os_info.get("PRETTY_NAME", os_info.get("NAME", "—"))
        kernel = os_info.get("kernel", "—")
        arch = os_info.get("arch", "—")
        version_id = os_info.get("VERSION_ID", "")

        right_table.add_row("  Hostname", f"[bold white]{hostname}[/]")
        right_table.add_row("  OS", os_name)
        right_table.add_row("  Kernel", kernel)
        right_table.add_row("  Arch", arch)
        if version_id:
            right_table.add_row("  Version", version_id)
    else:
        right_table.add_row("  Hostname", "[dim]Pending...[/]")
        right_table.add_row("  OS", "[dim]Detecting...[/]")
        right_table.add_row("  Kernel", "[dim]—[/]")
        right_table.add_row("  Arch", "[dim]—[/]")

    grid = Table.grid(expand=True)
    grid.add_column(ratio=1)
    grid.add_column(ratio=1)
    grid.add_row(
        Panel(
            left_table,
            title="[bold white]Scan Configuration[/]",
            title_align="left",
            border_style="bright_blue",
            padding=(1, 1),
        ),
        Panel(
            right_table,
            title="[bold white]Target System[/]",
            title_align="left",
            border_style="bright_blue",
            padding=(1, 1),
        ),
    )

    console.print(grid)

    # ── Coverage bar ──
    tactics_covered = [
        ("DISC", "green"),
        ("CRED", "green"),
        ("PRIV", "green"),
        ("EXEC", "green"),
        ("PERS", "green"),
        ("EVAS", "green"),
        ("LATR", "green"),
        ("C2", "green"),
        ("EXFL", "green"),
        ("COLL", "dim"),
        ("INIT", "dim"),
        ("IMPT", "dim"),
    ]
    coverage_parts = []
    for label, color in tactics_covered:
        if color == "dim":
            coverage_parts.append(f"[dim]{label}[/]")
        else:
            coverage_parts.append(f"[bold {color}]{label}[/]")

    console.print(
        f"  [dim]ATT&CK Coverage:[/]  " + "  ".join(coverage_parts)
    )
    console.print()


def display_compact_banner(console: Console) -> None:
    """Display a minimal banner for non-scan commands."""
    console.print()
    line = Text()
    line.append("  RHEL", style="bold red")
    line.append("-", style="dim")
    line.append("RT", style="bold red")
    line.append("  │  ", style="dim")
    line.append("Red Team Security Scanner", style="white")
    line.append("  │  ", style="dim")
    line.append(f"v{VERSION}", style="dim")
    line.append("  │  ", style="dim")
    line.append("MITRE ATT&CK", style="dim")
    line.append("  │  ", style="dim")
    line.append(f"{MODULE_COUNT} modules", style="dim")
    console.print(line)
    console.print("  [dim]" + "─" * 72 + "[/]")
    console.print()

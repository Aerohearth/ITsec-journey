"""
Rich terminal UI display helpers for the SOC Trainer app.
"""
from typing import Generator
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.rule import Rule
from rich.columns import Columns
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import box
from config import APP_NAME, APP_VERSION

console = Console()


# ── Colour palette ────────────────────────────────────────────────────────────
SEVERITY_COLORS = {
    "CRITICAL": "bold red",
    "HIGH": "bold orange1",
    "MEDIUM": "bold yellow",
    "LOW": "bold green",
    "UNKNOWN": "dim white",
}

SECTION_COLOR = "cyan"
ACCENT = "bright_cyan"
HEADER_COLOR = "bold bright_white on dark_blue"


# ── App chrome ────────────────────────────────────────────────────────────────
def print_banner() -> None:
    banner = Text()
    banner.append("\n")
    banner.append("  ██████╗  ██████╗  ██████╗    ", style="bold bright_cyan")
    banner.append("TRAINER\n", style="bold bright_white")
    banner.append("  ██╔════╝ ██╔═══██╗██╔════╝   ", style="bold cyan")
    banner.append("v" + APP_VERSION + "\n", style="dim white")
    banner.append("  ╚█████╗  ██║   ██║██║        ", style="bold cyan")
    banner.append("Security Operations Center\n", style="dim white")
    banner.append("   ╚═══██╗ ██║   ██║██║        ", style="bold cyan")
    banner.append("Analyst Training Platform\n", style="dim white")
    banner.append("  ██████╔╝ ╚██████╔╝╚██████╗   \n", style="bold bright_cyan")
    banner.append("  ╚═════╝   ╚═════╝  ╚═════╝   \n", style="bold bright_cyan")

    console.print(
        Panel(
            banner,
            border_style="bright_cyan",
            subtitle="[dim]Powered by Claude AI · Real threat data · Real analyst skills[/dim]",
            padding=(0, 2),
        )
    )


def print_menu(items: list[tuple[str, str]]) -> None:
    """Print the main menu."""
    console.print()
    console.print(Rule("[bold cyan]Main Menu[/bold cyan]", style="cyan"))
    console.print()
    for key, label in items:
        console.print(f"  [{ACCENT}]{key}[/{ACCENT}]  {label}")
    console.print()


def print_section(title: str) -> None:
    console.print()
    console.print(Rule(f"[bold {SECTION_COLOR}]{title}[/bold {SECTION_COLOR}]", style=SECTION_COLOR))
    console.print()


def print_error(message: str) -> None:
    console.print(f"\n[bold red]✗ Error:[/bold red] {message}\n")


def print_success(message: str) -> None:
    console.print(f"\n[bold green]✓[/bold green] {message}\n")


def print_info(message: str) -> None:
    console.print(f"[dim]{message}[/dim]")


# ── Data display helpers ──────────────────────────────────────────────────────
def display_kev_table(entries: list[dict]) -> None:
    """Display CISA KEV entries in a formatted table."""
    if not entries or "error" in entries[0]:
        print_error("Could not fetch KEV data. " + entries[0].get("error", ""))
        return

    table = Table(
        title="[bold]CISA Known Exploited Vulnerabilities — Recent Additions[/bold]",
        box=box.ROUNDED,
        border_style="cyan",
        header_style="bold bright_white on dark_blue",
        show_lines=True,
        expand=True,
    )
    table.add_column("CVE ID", style="bright_cyan", no_wrap=True, width=18)
    table.add_column("Vendor / Product", style="white", width=24)
    table.add_column("Added", style="yellow", width=12, no_wrap=True)
    table.add_column("Due Date", style="orange1", width=12, no_wrap=True)
    table.add_column("Ransomware?", style="red", width=12, no_wrap=True)
    table.add_column("Description", style="dim white")

    for e in entries:
        ransomware = e.get("knownRansomwareCampaignUse", "Unknown")
        ransomware_display = (
            "[bold red]YES[/bold red]" if ransomware.lower() == "known"
            else "[green]No[/green]" if ransomware.lower() in ("unknown", "")
            else f"[yellow]{ransomware}[/yellow]"
        )
        table.add_row(
            e.get("cveID", "N/A"),
            f"{e.get('vendorProject','?')} / {e.get('product','?')}",
            e.get("dateAdded", "?"),
            e.get("dueDate", "?"),
            ransomware_display,
            e.get("shortDescription", "")[:90],
        )

    console.print(table)


def display_cve_table(cves: list[dict]) -> None:
    """Display CVE entries in a formatted table."""
    if not cves or "error" in cves[0]:
        print_error("Could not fetch CVE data. " + cves[0].get("error", ""))
        return

    table = Table(
        title="[bold]Recent Critical CVEs — NVD[/bold]",
        box=box.ROUNDED,
        border_style="red",
        header_style="bold bright_white on dark_red",
        show_lines=True,
        expand=True,
    )
    table.add_column("#", style="dim", width=3)
    table.add_column("CVE ID", style="bright_cyan", no_wrap=True, width=18)
    table.add_column("CVSS", style="bold", width=6, no_wrap=True)
    table.add_column("Severity", width=10, no_wrap=True)
    table.add_column("Published", style="yellow", width=12, no_wrap=True)
    table.add_column("Description", style="white")

    for i, cve in enumerate(cves, 1):
        severity = cve.get("severity", "UNKNOWN")
        color = SEVERITY_COLORS.get(severity, "white")
        score = cve.get("cvss_score")
        score_str = f"[{color}]{score}[/{color}]" if score else "[dim]N/A[/dim]"
        table.add_row(
            str(i),
            cve.get("id", "N/A"),
            score_str,
            f"[{color}]{severity}[/{color}]",
            cve.get("published", "?")[:10],
            cve.get("description", "")[:100],
        )

    console.print(table)


def display_cisa_alerts(alerts: list[dict]) -> None:
    """Display CISA alerts as rich panels."""
    if not alerts or "error" in alerts[0]:
        print_error("Could not fetch CISA alerts.")
        return

    console.print("[bold]Latest CISA Cybersecurity Alerts[/bold]\n")
    for alert in alerts:
        console.print(
            Panel(
                f"[dim]{alert.get('published', '')}[/dim]\n\n"
                f"{alert.get('summary', 'No summary')}",
                title=f"[bold yellow]{alert.get('title', 'Alert')}[/bold yellow]",
                border_style="yellow",
                padding=(1, 2),
            )
        )


def display_kev_stats(stats: dict) -> None:
    """Display KEV catalog statistics."""
    if "error" in stats:
        print_error(stats["error"])
        return

    info_panel = (
        f"Total Entries: [bold bright_cyan]{stats['total_entries']}[/bold bright_cyan]\n"
        f"Catalog Version: [yellow]{stats['catalog_version']}[/yellow]\n"
        f"Last Released: [green]{stats['date_released']}[/green]"
    )

    vendor_table = Table(box=box.SIMPLE, header_style="bold", show_header=True)
    vendor_table.add_column("Vendor/Project", style="white")
    vendor_table.add_column("Vulnerabilities", style="bold bright_cyan", justify="right")
    for vendor, count in stats.get("top_vendors", []):
        vendor_table.add_row(vendor, str(count))

    console.print(
        Columns([
            Panel(info_panel, title="[bold]KEV Catalog Stats[/bold]", border_style="cyan", width=40),
            Panel(vendor_table, title="[bold]Top Targeted Vendors[/bold]", border_style="red"),
        ])
    )


# ── Streaming AI output ────────────────────────────────────────────────────────
def stream_ai_response(
    title: str,
    generator: Generator[str, None, None],
    border_style: str = "bright_cyan",
) -> None:
    """
    Stream Claude's response to the terminal inside a styled panel header,
    then show the full content in a panel when complete.
    Renders markdown-like formatting via rich markup.
    """
    console.print()
    console.print(
        Panel(
            f"[dim]Analysing with Claude {APP_VERSION}...[/dim]",
            title=f"[bold]{title}[/bold]",
            border_style=border_style,
        )
    )
    console.print()

    # Stream the text live
    full_text = ""
    try:
        for chunk in generator:
            console.print(chunk, end="", markup=False, highlight=False)
            full_text += chunk
    except KeyboardInterrupt:
        console.print("\n\n[dim]Interrupted.[/dim]")
        return

    console.print("\n")
    console.print(Rule(style="dim"))


def prompt_user(prompt: str, default: str = "") -> str:
    """Display a styled user prompt and return input."""
    console.print()
    try:
        value = console.input(f"[bold bright_cyan]❯[/bold bright_cyan] {prompt} ")
        return value.strip() or default
    except (EOFError, KeyboardInterrupt):
        return default


def confirm(prompt: str) -> bool:
    """Ask a yes/no question, return True for yes."""
    answer = prompt_user(f"{prompt} [y/N]:", "n")
    return answer.lower() in ("y", "yes")


def loading_spinner(message: str):
    """Return a Rich progress context manager with a spinner."""
    return Progress(
        SpinnerColumn(style="cyan"),
        TextColumn("[dim]{task.description}[/dim]"),
        transient=True,
    )


# ── Incident Response Simulator UI ───────────────────────────────────────────

def print_iris_banner() -> None:
    """Print the IRIS simulation environment header."""
    console.print()
    console.print(
        Panel(
            "[bold red]I R I S[/bold red]  —  [bold white]Incident Response Intelligence System[/bold white]\n"
            "[dim]A live cyberattack is unfolding. You are the analyst. Your decisions have consequences.[/dim]\n\n"
            "[dim]Commands you can type at any time:[/dim]\n"
            "  [bold yellow]TIMELINE[/bold yellow]  — full event timeline so far\n"
            "  [bold yellow]IOC[/bold yellow]       — all indicators of compromise found\n"
            "  [bold yellow]HINT[/bold yellow]      — get a nudge on your next action (-10 pts)\n"
            "  [bold yellow]SCORE[/bold yellow]     — end the sim and get your after-action review\n"
            "  [bold yellow]QUIT[/bold yellow]      — exit the simulation",
            border_style="bold red",
            padding=(1, 2),
        )
    )


def print_scenario_menu(scenarios: dict) -> None:
    """Print the IR scenario selection menu."""
    console.print()
    console.print(Rule("[bold red]Select a Scenario[/bold red]", style="red"))
    console.print()

    difficulty_colors = {
        "EASY": "green",
        "MEDIUM": "yellow",
        "HARD": "red",
        "variable": "cyan",
    }

    for key, scenario in scenarios.items():
        diff = scenario["difficulty"]
        color = difficulty_colors.get(diff, "white")
        console.print(
            f"  [bold red]{key}[/bold red]  "
            f"[bold white]{scenario['name']}[/bold white]  "
            f"[{color}][{diff}][/{color}]\n"
            f"     [dim]{scenario['description']}[/dim]"
        )
        console.print()


def stream_iris_response(generator) -> str:
    """
    Stream IRIS's response to the terminal.
    Returns the full text for appending to message history.
    """
    console.print()
    full_text = ""
    try:
        for chunk in generator:
            console.print(chunk, end="", markup=False, highlight=False)
            full_text += chunk
    except KeyboardInterrupt:
        console.print("\n[dim]Interrupted.[/dim]")
    console.print("\n")
    return full_text


def prompt_analyst_action() -> str:
    """Display the analyst action prompt and return input."""
    console.print()
    try:
        action = console.input(
            "[bold red]ANALYST ACTION[/bold red] [dim]>[/dim] "
        )
        return action.strip()
    except (EOFError, KeyboardInterrupt):
        return "QUIT"


def print_ir_divider() -> None:
    console.print(Rule(style="dim red"))


# ── Progress dashboard ────────────────────────────────────────────────────────

def print_dashboard(stats: dict) -> None:
    """Display session history and quiz stats on startup."""
    if stats["total_sessions"] == 0:
        return

    console.print()
    console.print(Rule("[bold cyan]Progress Dashboard[/bold cyan]", style="cyan"))
    console.print()

    streak = stats["streak_days"]
    streak_color = "yellow" if streak >= 3 else "white"
    streak_str = f"[{streak_color}]{streak} day{'s' if streak != 1 else ''}[/{streak_color}]"

    avg = stats["avg_quiz_score"]
    avg_color = "green" if avg >= 80 else "yellow" if avg >= 60 else "red"

    console.print(
        f"  Sessions: [bold bright_cyan]{stats['total_sessions']}[/bold bright_cyan]"
        f"  │  Quizzes: [bold magenta]{stats['total_quizzes']}[/bold magenta]"
        f"  │  Avg Score: [{avg_color}]{avg}%[/{avg_color}]"
        f"  │  Best: [bold yellow]{stats['best_quiz_score']}%[/bold yellow]"
        f"  │  Streak: {streak_str}"
        f"  │  IRIS Sims: [bold red]{stats['total_iris']}[/bold red]"
    )

    if stats["recent_quizzes"]:
        console.print()
        table = Table(box=box.SIMPLE, show_header=True, header_style="bold dim", padding=(0, 2))
        table.add_column("Recent Quizzes", style="white")
        table.add_column("Score", justify="right")
        for q in stats["recent_quizzes"]:
            pct = q["percent"]
            c = "green" if pct >= 80 else "yellow" if pct >= 60 else "red"
            table.add_row(q["topic"], f"[{c}]{q['score']}/{q['total']}  ({pct}%)[/{c}]")
        console.print(table)

    if stats["total_iris"] > 0:
        console.print(
            f"  [dim]IRIS average score:[/dim] [bold red]{stats['avg_iris_score']}[/bold red]"
        )

    console.print()

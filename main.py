#!/usr/bin/env python3
"""
SOC Analyst Trainer — Main entry point.
Fetches real cybersecurity data and uses Claude AI to turn it into learning material.

Usage:
    python main.py

Requirements:
    ANTHROPIC_API_KEY environment variable (or .env file)
"""
import sys
import os

# Ensure local imports work regardless of where the script is run from
sys.path.insert(0, os.path.dirname(__file__))

from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.console import Console

from config import ANTHROPIC_API_KEY
from fetchers.cisa import get_recent_kev_entries, get_cisa_alerts, get_all_kev_stats
from fetchers.nvd import get_recent_critical_cves, get_cve_by_id
from processors.ir_simulator import SCENARIOS, get_iris_response, build_custom_prompt
from processors.ai_processor import (
    generate_daily_briefing,
    analyze_vulnerability,
    analyze_kev_entry,
    generate_threat_hunt_scenario,
    generate_quiz,
    explain_concept,
)
from ui.display import (
    console,
    print_banner,
    print_menu,
    print_section,
    print_error,
    print_success,
    print_info,
    display_kev_table,
    display_cve_table,
    display_cisa_alerts,
    display_kev_stats,
    stream_ai_response,
    prompt_user,
    confirm,
    print_iris_banner,
    print_scenario_menu,
    stream_iris_response,
    prompt_analyst_action,
    print_ir_divider,
)


MENU_ITEMS = [
    ("1", "Daily Threat Briefing          — AI-generated morning SITREP from live threat feeds"),
    ("2", "Explore Recent CVEs            — Browse & deep-dive critical vulnerabilities (NVD)"),
    ("3", "CISA Active Exploits           — Known exploited vulnerabilities being abused now"),
    ("4", "Threat Hunting Scenario        — Practice guided threat hunt with AI walkthrough"),
    ("5", "Concept Explainer              — Ask about any security concept, get a SOC-focused answer"),
    ("6", "Knowledge Quiz                 — Test your skills on any topic"),
    ("7", "KEV Catalog Stats              — Overview of CISA's full exploit catalog"),
    ("8", "Incident Response Simulator    — Live attack scenario, you make the decisions [IRIS]"),
    ("q", "Quit"),
]


def check_api_key() -> bool:
    if not ANTHROPIC_API_KEY:
        print_error(
            "ANTHROPIC_API_KEY not set.\n"
            "  Set it in your environment:  export ANTHROPIC_API_KEY=sk-ant-...\n"
            "  Or create a .env file in the soc-trainer/ directory."
        )
        return False
    return True


# ── Menu handlers ─────────────────────────────────────────────────────────────

def handle_daily_briefing() -> None:
    print_section("Daily Threat Briefing")
    print_info("Fetching live data from CISA KEV & Alerts feeds...")

    with Progress(SpinnerColumn(style="cyan"), TextColumn("[dim]{task.description}[/dim]"), transient=True) as p:
        t = p.add_task("Fetching CISA Known Exploited Vulnerabilities...", total=None)
        kev_entries = get_recent_kev_entries(days=14, limit=5)
        p.update(t, description="Fetching CISA Alerts RSS feed...")
        cisa_alerts = get_cisa_alerts(limit=3)

    if kev_entries:
        display_kev_table(kev_entries)

    if cisa_alerts:
        console.print()
        display_cisa_alerts(cisa_alerts)

    console.print()
    if not confirm("Generate AI-powered briefing from this data?"):
        return

    stream_ai_response(
        "🌅 Daily Threat Briefing — AI Analysis",
        generate_daily_briefing(kev_entries, cisa_alerts),
        border_style="bright_cyan",
    )


def handle_cve_explorer() -> None:
    print_section("Recent Critical CVEs — NVD")
    print_info("Fetching recent CRITICAL CVEs from NIST NVD (last 7 days)...")

    with Progress(SpinnerColumn(style="red"), TextColumn("[dim]{task.description}[/dim]"), transient=True) as p:
        p.add_task("Querying NVD API...", total=None)
        cves = get_recent_critical_cves(days=7, limit=10)

    display_cve_table(cves)

    if not cves or "error" in cves[0]:
        return

    console.print()
    choice = prompt_user(
        "Enter the number of a CVE to deep-dive, OR type a CVE ID directly (e.g. CVE-2024-1234), "
        "or press Enter to skip:"
    )

    cve_data = None
    if choice.upper().startswith("CVE-"):
        with Progress(SpinnerColumn(), TextColumn("[dim]Looking up CVE...[/dim]"), transient=True) as p:
            p.add_task("", total=None)
            cve_data = get_cve_by_id(choice)
        if not cve_data:
            print_error(f"CVE {choice} not found in NVD.")
            return
    elif choice.isdigit():
        idx = int(choice) - 1
        if 0 <= idx < len(cves):
            cve_data = cves[idx]
        else:
            print_error("Invalid selection.")
            return
    else:
        return

    if "error" in cve_data:
        print_error(cve_data["error"])
        return

    stream_ai_response(
        f"🔬 CVE Deep Dive — {cve_data.get('id', 'Unknown')}",
        analyze_vulnerability(cve_data),
        border_style="red",
    )


def handle_cisa_exploits() -> None:
    print_section("CISA Known Exploited Vulnerabilities")
    print_info("Fetching actively exploited vulnerabilities added in the last 30 days...")

    with Progress(SpinnerColumn(style="orange1"), TextColumn("[dim]{task.description}[/dim]"), transient=True) as p:
        p.add_task("Fetching KEV catalog...", total=None)
        entries = get_recent_kev_entries(days=30, limit=15)

    display_kev_table(entries)

    if not entries or "error" in entries[0]:
        return

    console.print()
    choice = prompt_user(
        "Enter the number of a KEV entry for an in-depth AI analysis (or press Enter to skip):"
    )

    if not choice.isdigit():
        return

    idx = int(choice) - 1
    if 0 <= idx < len(entries):
        entry = entries[idx]
        stream_ai_response(
            f"⚠️  Active Exploit Analysis — {entry.get('cveID', 'Unknown')}",
            analyze_kev_entry(entry),
            border_style="orange1",
        )
    else:
        print_error("Invalid selection.")


def handle_threat_hunt() -> None:
    print_section("Threat Hunting Scenario")
    console.print(
        "[dim]Practice realistic threat hunts guided by AI. Examples:[/dim]\n"
        "  • Lateral movement via PsExec\n"
        "  • PowerShell living-off-the-land (LOLBin) activity\n"
        "  • Ransomware staging and encryption\n"
        "  • Credential dumping with Mimikatz\n"
        "  • Phishing with malicious macro documents\n"
        "  • C2 beaconing over HTTPS\n"
    )

    topic = prompt_user("Enter a threat hunting topic (or press Enter for a random scenario):")
    if not topic:
        import random
        topics = [
            "PowerShell-based lateral movement",
            "Ransomware pre-deployment staging",
            "Credential harvesting via LSASS",
            "Suspicious scheduled task creation",
            "Beaconing over DNS tunneling",
            "Kerberoasting attack detection",
        ]
        topic = random.choice(topics)
        print_info(f"Selected topic: {topic}")

    stream_ai_response(
        f"🎯 Threat Hunt — {topic}",
        generate_threat_hunt_scenario(topic),
        border_style="bright_yellow",
    )


def handle_concept_explainer() -> None:
    print_section("Security Concept Explainer")
    console.print(
        "[dim]Ask about any security concept and get a SOC-focused explanation. Examples:[/dim]\n"
        "  • MITRE ATT&CK framework\n"
        "  • Indicators of Compromise (IoCs)\n"
        "  • SIEM vs SOAR\n"
        "  • Pass-the-Hash attack\n"
        "  • Zero-day vs N-day vulnerability\n"
        "  • Kill chain methodology\n"
    )

    concept = prompt_user("What concept do you want explained?")
    if not concept:
        print_info("No concept entered. Returning to menu.")
        return

    stream_ai_response(
        f"📖 Concept — {concept}",
        explain_concept(concept),
        border_style="cyan",
    )


def handle_quiz() -> None:
    print_section("SOC Analyst Knowledge Quiz")
    console.print(
        "[dim]Test yourself on any cybersecurity topic. Examples:[/dim]\n"
        "  • MITRE ATT&CK tactics and techniques\n"
        "  • Windows Event Log IDs for detection\n"
        "  • Network forensics\n"
        "  • Phishing analysis\n"
        "  • Malware behaviour\n"
    )

    topic = prompt_user("Quiz topic (or press Enter for 'SOC Analyst Fundamentals'):")
    if not topic:
        topic = "SOC Analyst Fundamentals"

    num_str = prompt_user("Number of questions? [5]:")
    try:
        num = int(num_str) if num_str.isdigit() else 5
        num = max(1, min(num, 15))
    except ValueError:
        num = 5

    stream_ai_response(
        f"❓ Quiz — {topic} ({num} questions)",
        generate_quiz(topic, num),
        border_style="magenta",
    )


def handle_ir_sim() -> None:
    print_section("Incident Response Simulator — IRIS")
    print_iris_banner()
    print_scenario_menu(SCENARIOS)

    choice = prompt_user("Select a scenario [1-6]:")
    if choice not in SCENARIOS:
        print_error("Invalid selection.")
        return

    scenario = SCENARIOS[choice]

    # Build the opening prompt
    if choice == "6":
        console.print(
            "\n[dim]Describe the incident scenario you want to practise. "
            "Be as specific or as vague as you like — IRIS will fill in the details.[/dim]\n"
        )
        custom = prompt_user("Describe your scenario:")
        if not custom:
            print_info("No description provided. Returning to menu.")
            return
        opening_prompt = build_custom_prompt(custom)
    else:
        opening_prompt = scenario["prompt"]

    console.print(
        f"\n[bold red]Starting:[/bold red] [white]{scenario['name']}[/white]  "
        f"[dim]({scenario['difficulty']})[/dim]\n"
        "[dim]IRIS is initialising the simulation environment...[/dim]\n"
    )

    # Conversation history — grows each turn
    messages: list[dict] = [{"role": "user", "content": opening_prompt}]

    # ── Simulation loop ───────────────────────────────────────────────────────
    while True:
        # Get IRIS response and stream it
        response_text = stream_iris_response(get_iris_response(messages))

        if not response_text:
            print_error("No response from IRIS. Check your API key and connection.")
            break

        # Append IRIS response to history
        messages.append({"role": "assistant", "content": response_text})

        # Check if IRIS ended the sim (SCORE or QUIT was processed)
        lowered = response_text.lower()
        if any(phrase in lowered for phrase in (
            "after-action review", "simulation complete", "final score",
            "goodbye, analyst", "end of simulation"
        )):
            print_ir_divider()
            print_success("Simulation ended. Run IRIS again to start a new scenario.")
            break

        # Get analyst action
        print_ir_divider()
        action = prompt_analyst_action()

        if not action:
            continue

        # Allow local quit without sending to Claude
        if action.upper() == "QUIT":
            console.print("\n[dim]Exiting simulation. Good work, analyst.[/dim]\n")
            break

        # Append analyst action to history and loop
        messages.append({"role": "user", "content": action})


def handle_kev_stats() -> None:
    print_section("CISA KEV Catalog Statistics")
    print_info("Fetching full KEV catalog statistics...")

    with Progress(SpinnerColumn(), TextColumn("[dim]{task.description}[/dim]"), transient=True) as p:
        p.add_task("Loading KEV catalog...", total=None)
        stats = get_all_kev_stats()

    display_kev_stats(stats)


# ── Main loop ──────────────────────────────────────────────────────────────────

def main() -> None:
    print_banner()

    if not check_api_key():
        sys.exit(1)

    handlers = {
        "1": handle_daily_briefing,
        "2": handle_cve_explorer,
        "3": handle_cisa_exploits,
        "4": handle_threat_hunt,
        "5": handle_concept_explainer,
        "6": handle_quiz,
        "7": handle_kev_stats,
        "8": handle_ir_sim,
    }

    while True:
        print_menu(MENU_ITEMS)
        choice = prompt_user("Select an option:").lower()

        if choice in ("q", "quit", "exit"):
            console.print("\n[dim]Stay sharp, analyst. Good hunting. 🛡️[/dim]\n")
            break
        elif choice in handlers:
            try:
                handlers[choice]()
            except KeyboardInterrupt:
                console.print("\n[dim]Returning to menu...[/dim]")
            except Exception as e:
                print_error(f"Unexpected error: {e}")
        else:
            console.print("[dim]Unknown option. Try again.[/dim]")


if __name__ == "__main__":
    main()

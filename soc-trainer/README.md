# SOC Analyst Trainer

A terminal-based cybersecurity learning app that pulls **live threat intelligence** from public government APIs and uses **Claude AI** to transform it into structured SOC analyst training material.

Built for people working toward their first SOC analyst role. Every session uses real, current data — not textbook examples.

---

## Table of Contents

- [Features](#features)
- [How It Works](#how-it-works)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Data Sources](#data-sources)
- [Project Structure](#project-structure)
- [Keeping Your Local Copy Up to Date](#keeping-your-local-copy-up-to-date)
- [Planned Features](#planned-features)
- [Troubleshooting](#troubleshooting)

---

## Features

| Menu Option | Description |
|---|---|
| **Daily Threat Briefing** | AI-generated morning SITREP from live CISA KEV and alert feeds |
| **CVE Explorer** | Browse recent critical vulnerabilities and deep-dive any CVE |
| **Active Exploits** | Vulnerabilities being weaponised right now (CISA KEV catalog) |
| **Threat Hunt Scenario** | Guided threat hunting walkthroughs with SIEM queries and decision points |
| **Concept Explainer** | Any security term explained from a SOC analyst's perspective |
| **Knowledge Quiz** | Multiple-choice quiz on any topic, with answers and explanations |
| **KEV Stats** | Overview of the full CISA exploit catalog — top vendors, totals |
| **Incident Response Simulator** | Live attack scenario — you make the decisions, IRIS reacts |

All AI output is structured consistently:

- Plain English summary
- Real-world impact
- SOC analyst detection guidance
- MITRE ATT&CK mapping
- Severity rating and justification
- Recommended actions
- Learning moment + knowledge check question

---

## How It Works

```
Live Internet Data          Claude AI (claude-opus-4-6)       Your Terminal
──────────────────          ───────────────────────────       ─────────────
CISA KEV API           →    Adaptive thinking                 Rich formatted
CISA Alerts RSS        →    Streaming output            →     live output
NIST NVD CVE API       →    Prompt caching
```

1. You select an option from the menu
2. The app fetches real data from free government APIs (no API keys needed for data)
3. That data is sent to Claude with a detailed SOC trainer system prompt
4. Claude's response streams back to your terminal in real time
5. Output is always structured for learning — not just raw information

---

## Requirements

- Python 3.10 or higher
- An [Anthropic API key](https://console.anthropic.com) (free credits available for new accounts)
- Git
- Internet connection (fetches live data on every run)

---

## Installation

### 1. Clone the repository

```powershell
git clone https://github.com/aerohearth/itsec-journey.git
cd itsec-journey\soc-trainer
```

### 2. Install dependencies

```powershell
pip install -r requirements.txt
```

> If you get permission errors, use: `pip install --user -r requirements.txt`
> 
> For a clean environment (recommended):
> ```powershell
> python -m venv venv
> venv\Scripts\activate
> pip install -r requirements.txt
> ```

### 3. Set up your API key

```powershell
copy .env.example .env
notepad .env
```

Replace the placeholder with your real Anthropic API key:

```
ANTHROPIC_API_KEY=sk-ant-api03-your-key-here
```

Save and close.

### 4. Run the app

```powershell
python main.py
```

---

## Usage

The app runs as an interactive terminal menu. Select an option by typing its number and pressing Enter.

### Daily Threat Briefing

Fetches the latest CISA Known Exploited Vulnerabilities and CISA alert advisories, then generates a morning SITREP covering:

- Current threat landscape summary
- The 2–3 most urgent items and why they matter
- Today's recommended SOC priorities
- A Tip of the Day for analyst development

### CVE Explorer

Queries the NIST NVD API for critical CVEs published in the last 7 days. You can:

- Browse them in a colour-coded table
- Select one by number for a full AI deep-dive
- Type a specific CVE ID directly (e.g. `CVE-2024-12345`)

### Active Exploits (CISA KEV)

Shows vulnerabilities added to the CISA Known Exploited Vulnerabilities catalog in the last 30 days — meaning they are confirmed to be actively exploited in the wild. Select any entry for a full analysis including detection guidance and threat actor context.

### Threat Hunt Scenario

Enter any threat hunting topic and the app generates a full scenario including:

- Background and mission briefing
- Available data sources
- Hunting hypothesis (ATT&CK-based)
- Step-by-step walkthrough with example SIEM queries
- Simulated findings and analyst decision points
- After-action review

Leave the topic blank to get a random scenario.

### Concept Explainer

Type any cybersecurity term or concept and receive a SOC-focused explanation covering definition, how it works, how you'd encounter it in daily SOC work, detection/response guidance, and related concepts.

### Knowledge Quiz

Choose a topic and number of questions (1–15). Each question is multiple choice with a correct answer and a full explanation of why each option is right or wrong.

### KEV Stats

Displays high-level statistics about the full CISA KEV catalog — total entries, catalog version, and the top vendors most frequently targeted by known exploits.

### Incident Response Simulator (IRIS)

A fully reactive, multi-turn incident response training environment. IRIS plays the role of a simulated enterprise SOC environment. You play the on-call analyst. A real cyberattack is unfolding — your decisions determine the outcome.

**Available scenarios:**

| # | Scenario | Difficulty |
|---|---|---|
| 1 | Ransomware Outbreak | Medium |
| 2 | Phishing → Lateral Movement | Medium |
| 3 | Insider Threat / Data Exfiltration | Hard |
| 4 | APT Intrusion | Hard |
| 5 | Business Email Compromise | Easy |
| 6 | Custom — describe your own incident | Variable |

**How it works:**
1. IRIS presents the initial alert that triggered the incident
2. You type your action (e.g. `isolate WKSTN-FIN-A4K from the network`, `pull Splunk logs for user jsmith`, `escalate to IR team`)
3. IRIS responds with realistic consequences — good decisions reveal evidence, poor ones let the attacker progress
4. Continue until the incident is resolved or you type `SCORE`

**Special commands during a simulation:**

| Command | Effect |
|---|---|
| `TIMELINE` | Print every event that has occurred so far |
| `IOC` | List all indicators of compromise discovered |
| `HINT` | Get a nudge on your next action (-10 points) |
| `SCORE` | End the sim and receive your after-action review with score /100 |
| `QUIT` | Exit the simulation |

---

## Data Sources

All data sources are free and require no authentication.

| Source | URL | What it provides |
|---|---|---|
| CISA KEV Catalog | `cisa.gov` | Vulnerabilities confirmed being actively exploited |
| CISA Alerts RSS | `cisa.gov/uscert/ncas/alerts.xml` | Cybersecurity advisories and alerts |
| NIST NVD API v2 | `services.nvd.nist.gov` | Full CVE database with CVSS scores |

---

## Project Structure

```
soc-trainer/
├── main.py                  # Entry point — interactive menu and handlers
├── config.py                # API keys, URLs, model settings
├── requirements.txt         # Python dependencies
├── .env.example             # Template for your API key
├── .env                     # Your actual API key (never committed)
│
├── fetchers/
│   ├── cisa.py              # CISA KEV and Alerts data fetching
│   └── nvd.py               # NIST NVD CVE data fetching
│
├── processors/
│   └── ai_processor.py      # Claude API integration — all AI prompt logic
│
└── ui/
    └── display.py           # Rich terminal UI — tables, panels, streaming output
```

---

## Keeping Your Local Copy Up to Date

When changes are pushed to GitHub, your local copy does **not** update automatically. To sync:

```powershell
# Inside the itsec-journey folder
git pull
```

Run this any time you want to pull in the latest changes or new features.

---

## Planned Features

### Near term
- [ ] Progress tracker — save quiz scores and topics to a local file, show a dashboard on startup
- [ ] Bookmarks — save CVEs and KEV entries to revisit later
- [ ] Additional data sources — AlienVault OTX, abuse.ch, VirusTotal

### Medium term
- [ ] Flashcard mode with spaced repetition
- [ ] Log analysis practice — paste raw logs, Claude walks through the investigation
- [x] ~~Incident response simulator — live attack scenario, you make the decisions~~ ✅ shipped v1.1.0
- [ ] MITRE ATT&CK browser — explore all tactics and techniques interactively

### Longer term
- [ ] Web UI (Flask/FastAPI) — browser-based interface
- [ ] Personal knowledge base — save and search all past AI analyses
- [ ] Wazuh/Sysmon integration — analyse alerts from your own home lab
- [ ] Certification study mode — structured paths for Security+, CySA+, SANS

---

## Troubleshooting

**`python` not found**
Try `python3` instead. If neither works, install Python from [python.org](https://python.org) and tick "Add to PATH" during setup.

**`git` not found**
Install Git from [git-scm.com](https://git-scm.com), then reopen your terminal.

**`ANTHROPIC_API_KEY not set` error**
Make sure your `.env` file exists in the `soc-trainer/` folder and contains your real key. The file should not be named `.env.example`.

**NVD API returns no results**
The NVD API has a public rate limit. If you've made several requests in quick succession, wait 30 seconds and try again.

**Slow or no response from Claude**
Check your internet connection. Ensure your API key is valid and has available credits at [console.anthropic.com](https://console.anthropic.com).

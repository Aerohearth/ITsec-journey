# Changelog

All notable changes to the SOC Analyst Trainer are documented here.

Format: `[version] — date` followed by what changed and why.

---

## [1.1.0] — 2026-04-18

### Added
- **Incident Response Simulator (IRIS)** — fully reactive multi-turn scenario engine
  - 5 built-in scenarios: Ransomware, Phishing → Lateral Movement, Insider Threat, APT, BEC
  - Custom scenario mode — describe any incident, IRIS runs it
  - IRIS reacts intelligently to analyst decisions — good choices reveal evidence, poor ones let the attacker progress
  - In-sim commands: TIMELINE, IOC, HINT, SCORE, QUIT
  - After-action review with score /100 and decision-by-decision breakdown
  - Adaptive thinking enabled for deep, realistic scenario generation
  - Prompt caching on IRIS system prompt for efficient multi-turn conversations
- New UI helpers for IR sim: `print_iris_banner`, `print_scenario_menu`, `stream_iris_response`, `prompt_analyst_action`, `print_ir_divider`
- Menu option 8 added to main menu

---

## [1.0.0] — 2026-04-18

### Added
- Initial release of the SOC Analyst Trainer
- Interactive terminal menu with 7 training modes
- **Daily Threat Briefing** — AI-generated SITREP from live CISA KEV and Alerts data
- **CVE Explorer** — browse recent critical CVEs from NIST NVD, deep-dive any entry
- **Active Exploits** — CISA Known Exploited Vulnerabilities with AI analysis
- **Threat Hunt Scenario** — guided hunt walkthroughs with SIEM queries and decision points
- **Concept Explainer** — SOC-focused breakdowns of any security term
- **Knowledge Quiz** — multiple-choice questions with answers and explanations
- **KEV Stats** — catalog overview and top targeted vendors
- CISA KEV API integration (`fetchers/cisa.py`)
- CISA Alerts RSS feed integration (`fetchers/cisa.py`)
- NIST NVD CVE 2.0 API integration (`fetchers/nvd.py`)
- Claude AI processor using `claude-opus-4-6` with adaptive thinking and streaming (`processors/ai_processor.py`)
- Prompt caching on the SOC trainer system prompt to reduce API costs
- Rich terminal UI with colour-coded severity, live streaming output, tables and panels (`ui/display.py`)
- `.env` support for API key management
- `requirements.txt` with pinned dependencies

---

## Upcoming

### [1.2.0] — planned
- Progress tracker: save quiz scores and session history locally
- Bookmarks: save CVEs and KEV entries to a local file for later review
- Additional data source: AlienVault OTX threat intel feed

### [1.3.0] — planned
- Flashcard mode with spaced repetition
- Log analysis practice: paste raw logs, Claude walks through the investigation
- MITRE ATT&CK browser

### [1.4.0] — planned
- Web UI (Flask/FastAPI)
- Personal knowledge base: save and search all past AI analyses

### [future]
- Wazuh/Sysmon home lab integration
- Certification study mode (Security+, CySA+, SANS)

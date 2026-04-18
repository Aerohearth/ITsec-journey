# SOC Trainer — Ideas & Roadmap

A living document for tracking feature ideas, improvements, and future direction.
Updated as the project evolves.

---

## Incident Response Simulator (IRIS) — Expansion Ideas

### Scenario System Overhaul
The current 5 fixed scenarios are a starting point. The goal is to move toward a system where scenarios feel genuinely different every time.

**Ideas on the table:**

- **Scenario table / library** — instead of 5 hardcoded prompts, maintain a larger pool of scenario seeds that IRIS draws from randomly or by category. Categories could include:
  - Initial access vectors (phishing, drive-by, supply chain, credential stuffing, VPN exploit)
  - Attacker objectives (ransomware, espionage, data theft, destructive, cryptomining)
  - Target industry (healthcare, finance, manufacturing, government, logistics)
  - Threat actor archetype (script kiddie, organised crime, nation-state APT, insider)

- **Procedural generation** — rather than fixed scenarios, define building blocks that Claude assembles:
  - Random initial access vector
  - Random attacker objective
  - Random industry / environment
  - Random difficulty modifier (time pressure, red herrings, noisy environment)
  - IRIS combines these into a coherent, unique scenario each run
  - No two sessions would be identical

- **Scenario parameters at start** — let the analyst choose or randomise:
  - Industry (healthcare, finance, etc.)
  - Attacker type (opportunistic vs targeted)
  - Difficulty
  - Time pressure (e.g. "exec is demanding updates every 10 minutes")

- **Scenario seeds file** — store scenario building blocks in a local JSON or YAML file so new scenarios can be added without touching code

### IRIS Mechanics Improvements
- **Branching consequences** — track a persistent state object (attacker dwell time, systems compromised, data exfiltrated) that evolves turn-by-turn and affects the final score
- **Realistic tool output** — when analyst asks to "run a Splunk query", IRIS returns something that looks like actual Splunk output (table format, field names, realistic values)
- **Inject noise** — mix in benign-looking alerts alongside malicious ones to simulate the real SOC experience of working through alert fatigue
- **Timed pressure mode** — each action costs simulated time; delays cause attacker progression
- **Multiplayer / async** — save a scenario mid-session and resume it later (serialize conversation history to a file)

---

## Other Feature Ideas

### Progress & Learning Tracking
- Save quiz scores, topics covered, and session count to a local JSON file
- Dashboard on startup showing: streak, topics weak in, sessions completed
- Track which IRIS scenarios have been run and how they scored

### Bookmarks
- During any session, type `SAVE` or `BOOKMARK` to save the current CVE / KEV entry / concept to a local file
- Separate menu option to review bookmarks

### Log Analysis Practice
- Paste a raw log (Windows Event Log, Syslog, Zeek, firewall, proxy) into the app
- Claude walks through it as if conducting a real investigation
- Highlights suspicious entries, explains each finding, asks the analyst what they'd do

### Flashcard Mode
- Claude generates question/answer flashcards from KEV entries, CVEs, and concepts
- App tracks which cards you struggle with and surfaces them more often (spaced repetition)
- Export cards to Anki format

### MITRE ATT&CK Browser
- Navigate tactics and techniques from within the app
- Claude explains each with real-world examples and detection opportunities
- Link techniques back to CVEs and KEV entries where relevant

### Additional Data Sources
- **AlienVault OTX** — community threat intel, IoC feeds, pulse reports
- **abuse.ch** — malware hashes (MalwareBazaar), C2 URLs (URLhaus), ransomware tracker
- **VirusTotal public API** — file/URL/IP lookup (free tier, rate limited)
- **MITRE ATT&CK STIX API** — pull live tactic/technique data

---

## Workflow & Architecture Ideas

### Scenario Storage Format
Consider moving scenario definitions out of Python and into a data file:

```yaml
# scenarios/ransomware_01.yaml
name: Ransomware Outbreak
difficulty: medium
initial_access: phishing
objective: ransomware
environment: logistics_company
seed_prompt: >
  It is 02:14 on a Tuesday. CrowdStrike Falcon just paged the on-call analyst...
```

This would let scenarios be added, edited, and shared without touching code.

### Session Persistence
- Serialize the IRIS conversation history to a JSON file mid-session
- Allow resuming a paused simulation in a future session
- Could tie into progress tracking (track which scenarios have been completed)

### Web UI (longer term)
- Flask or FastAPI backend exposing the existing processors as API endpoints
- Simple HTML/JS frontend — browser-based, shareable
- Would make the app accessible without installing Python

---

## Notes & Decisions

| Date | Note |
|---|---|
| 2026-04-18 | v1.0.0 shipped — core app with 7 menu options, live CISA/NVD data, Claude AI |
| 2026-04-18 | v1.1.0 shipped — IRIS incident response simulator, 5 scenarios + custom mode |
| 2026-04-18 | Decided to drop PR workflow for solo dev — push direct to branch, pull locally |

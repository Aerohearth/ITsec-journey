# SOC Analyst Trainer

Train like a real SOC analyst — using live government threat data and AI-powered scenarios, not recycled textbook examples.

---

## The Problem

Every SOC training resource uses the same stale scenarios written years ago. Meanwhile, real vulnerabilities are being actively exploited today. Junior analysts join their first SOC having studied theory but never touched a live threat feed, triaged a real CVE, or made decisions under pressure during an active incident.

SOC Analyst Trainer fixes that. It pulls live data from CISA and NIST every session and uses Claude AI to turn it into structured, practitioner-level training material.

---

## Features

| # | Feature | What it does |
|---|---------|--------------|
| 1 | **Daily Threat Briefing** | AI-generated morning SITREP from live CISA KEV + Alerts feeds |
| 2 | **CVE Explorer** | Browse today's critical vulnerabilities from NIST NVD and deep-dive any entry |
| 3 | **Active Exploits** | CISA Known Exploited Vulnerabilities with AI triage analysis |
| 4 | **Threat Hunt Scenario** | Guided hunt walkthroughs with SIEM queries and attacker decision trees |
| 5 | **Concept Explainer** | SOC-focused breakdown of any security term or framework |
| 6 | **Knowledge Quiz** | Scored multiple-choice questions on any topic, with explanations |
| 7 | **KEV Stats** | Catalog overview — top targeted vendors, ransomware trends |
| 8 | **Incident Response Simulator (IRIS)** | Multi-turn attack scenarios where your decisions have real consequences |

---

## Quick Start

**Requirements:** Python 3.10+, an [Anthropic API key](https://console.anthropic.com)

```bash
git clone https://github.com/Aerohearth/itsec-journey.git
cd itsec-journey
pip install -r requirements.txt
cp .env.example .env        # paste your ANTHROPIC_API_KEY inside
python main.py
```

---

## Tech Stack

| Layer | Technology |
|-------|------------|
| Runtime | Python 3.10+ |
| AI | Claude API — streaming, adaptive thinking, prompt caching |
| Threat data | CISA KEV API, CISA Alerts RSS, NIST NVD CVE 2.0 API |
| UI | Rich (terminal) |

---

## Roadmap

### v1.2.0 — current
- [x] Progress tracker — quiz scores and session history saved locally
- [x] Startup dashboard — streak, average score, recent quiz results

### v1.3.0
- [ ] Bookmarks — save CVEs and KEV entries for later review
- [ ] AlienVault OTX integration as an additional threat feed
- [ ] Flashcard mode with spaced repetition

### v1.4.0
- [ ] Log analysis practice — paste raw logs, Claude walks the investigation
- [ ] MITRE ATT&CK browser integrated with live threat data
- [ ] YAML-defined custom IRIS scenarios

### Web Version
A hosted web version with waitlist is in development. No local setup required — same live data, same AI tutor, in the browser.

**[Join the waitlist →](https://soctrainer.dev)** *(coming soon)*

---

## License

MIT

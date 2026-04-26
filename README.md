# SocForge

![GitHub Stars](https://img.shields.io/github/stars/Aerohearth/Socforge?style=flat-square) ![License](https://img.shields.io/github/license/Aerohearth/Socforge?style=flat-square)

**Real-time SOC analyst training powered by live government threat data.**

---

## The Problem

Every SOC training resource uses the same stale scenarios written years ago. Meanwhile, real vulnerabilities are being actively exploited today. Junior analysts join their first SOC having studied theory but never touched a live threat feed, triaged a real CVE, or made decisions under pressure during an active incident.

SocForge fixes that. It pulls live data from CISA and NIST every session and uses Claude AI to turn it into structured, practitioner-level training material.

---

## Features

| # | Feature | What it does |
|---|---------|--------------|
| 1 | **Daily Threat Briefing** | AI-generated morning SITREP from live CISA KEV and government alert feeds |
| 2 | **Recent CVE Disclosures** | Newly published critical vulnerabilities from NIST NVD — not yet exploited |
| 3 | **Active Exploits** | CISA Known Exploited Vulnerabilities — confirmed being weaponised right now |
| 4 | **KEV Catalog** | Browse and deep-dive the full CISA exploit catalog — all entries, paginated |
| 5 | **Threat Hunt Scenario** | Guided hunt walkthroughs with SIEM queries and attacker decision trees |
| 6 | **Concept Explainer** | SOC-focused breakdown of any security term or framework |
| 7 | **Knowledge Quiz** | Scored multiple-choice questions on any topic, with explanations |
| 8 | **IRIS — Incident Response Simulator** | Multi-turn attack scenarios across 6 difficulty-graded incidents. You make the calls, AI coaches in real time, after-action review scores your performance |

> Features 2–4 are grouped into a single **Vuln Intelligence** section in the web app.

---

## Quick Start — CLI

**Requirements:** Python 3.10+, an [Anthropic API key](https://console.anthropic.com)

```bash
git clone https://github.com/Aerohearth/Socforge.git
cd Socforge
pip install -r requirements.txt
cp .env.example .env        # paste your ANTHROPIC_API_KEY inside
python main.py
```

## Quick Start — Web App

```bash
pip install -r backend/requirements.txt
cp .env.example .env        # paste your ANTHROPIC_API_KEY inside
uvicorn backend.main:app --reload
# open http://localhost:8000
```

---

## Tech Stack

| Layer | Technology |
|-------|------------|
| Runtime | Python 3.10+ |
| AI | Claude API (streaming, prompt caching, adaptive thinking) |
| Threat data | CISA KEV API, CISA Alerts RSS, NIST NVD CVE 2.0 API |
| Web backend | FastAPI + uvicorn |
| Web frontend | Vanilla HTML/CSS/JS — single file, no framework |
| CLI UI | Rich (terminal) |

---

## Roadmap

- [x] Web UI — FastAPI backend + vanilla JS SPA, served from one command
- [x] Incident Response Simulator (IRIS) — multi-turn AI-coached scenarios
- [ ] User accounts + persistent progress across sessions
- [ ] Mobile app — PWA install already supported, native app later
- [ ] Cert study paths — CompTIA Security+, CySA+, CEH guided tracks
- [ ] Hosted version — [join the waitlist](https://socforge.dev) *(coming soon)*

---

## License

MIT

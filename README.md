# SocForge

![GitHub Stars](https://img.shields.io/github/stars/Aerohearth/itsec-journey?style=flat-square) ![License](https://img.shields.io/github/license/Aerohearth/itsec-journey?style=flat-square)

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
| 2 | **CVE Explorer** | Browse today's critical vulnerabilities from NIST NVD and deep-dive any entry |
| 3 | **Active Exploits** | CISA Known Exploited Vulnerabilities with AI triage analysis |
| 4 | **Threat Hunt Scenario** | Guided hunt walkthroughs with SIEM queries and attacker decision trees |
| 5 | **Concept Explainer** | SOC-focused breakdown of any security term or framework |
| 6 | **Knowledge Quiz** | Scored multiple-choice questions on any topic, with explanations |
| 7 | **KEV Catalog** | Browse and deep-dive the full CISA exploit catalog — all entries, not just summaries |

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
| AI | Claude API |
| Threat data | CISA KEV API, CISA Alerts RSS, NIST NVD CVE 2.0 API |
| UI | Rich (terminal) |

---

## Roadmap

- [ ] Web UI — no local setup, no API key required
- [ ] Mobile app — training on the go
- [ ] Cert study paths — COMPTIA Security+, CySA+, CEH guided tracks
- [ ] Waitlist open — [join at socforge.dev](https://socforge.dev) *(coming soon)*

---

## License

MIT

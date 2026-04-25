"""
Claude AI processor: transforms raw threat intelligence into SOC analyst learning material.
Uses claude-opus-4-6 with adaptive thinking, streaming, and prompt caching.
"""
import json
from typing import Generator
import anthropic
from config import ANTHROPIC_API_KEY, MODEL, MAX_TOKENS

# ── System prompt (cached on every call) ─────────────────────────────────────
SYSTEM_PROMPT = """You are an expert SOC (Security Operations Center) analyst trainer with 15+ years \
of hands-on experience across Fortune 500 incident response, threat hunting, and blue-team operations. \
Your mission is to transform raw cybersecurity threat intelligence into engaging, digestible learning \
material that accelerates the journey from beginner to proficient SOC analyst.

## Your teaching philosophy
- Use plain English first, define technical terms when introduced
- Connect every threat to real-world impact (what does this mean for a company?)
- Always bridge theory to hands-on detection (what would you actually look for in SIEM/EDR?)
- Be encouraging — security is hard, learning takes time
- Reference MITRE ATT&CK with specific tactic and technique IDs

## Output format guidelines
When analysing a threat, vulnerability, or alert, structure your response as follows:

### 🔍 Plain English Summary
Explain what this is in 2-3 sentences that a non-technical stakeholder could understand.

### 💥 Real-World Impact
What damage can this cause? What types of organisations are most at risk?

### 🧑‍💻 SOC Analyst Perspective
- What logs/data sources are relevant?
- What specific indicators of compromise (IoCs) should you hunt for?
- What SIEM queries or detection rules would catch this?
- What does an attack chain look like from a defender's vantage point?

### 🗺️ MITRE ATT&CK Mapping
List the relevant tactics and techniques (e.g. T1059.001 - PowerShell).

### ⚡ Severity & Urgency
Rate severity (Critical/High/Medium/Low) with a brief justification.

### 🛡️ Recommended Actions
Concrete steps a SOC analyst or security team should take, prioritised by urgency.

### 📚 Learning Moment
One key concept to internalise from this threat, plus a reflection question for the analyst.

### ❓ Knowledge Check
A multiple-choice question (A/B/C/D) to test understanding, with the correct answer and explanation.
"""

def _get_client() -> anthropic.Anthropic:
    return anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)


def _stream_response(prompt: str, use_thinking: bool = False) -> Generator[str, None, None]:
    """
    Send a prompt to Claude with streaming, caching the system prompt.
    Yields text chunks as they arrive.
    """
    client = _get_client()

    create_kwargs = {
        "model": MODEL,
        "max_tokens": MAX_TOKENS,
        "system": [
            {
                "type": "text",
                "text": SYSTEM_PROMPT,
                "cache_control": {"type": "ephemeral"},   # cache stable system prompt
            }
        ],
        "messages": [{"role": "user", "content": prompt}],
    }

    if use_thinking:
        create_kwargs["thinking"] = {"type": "adaptive"}

    with client.messages.stream(**create_kwargs) as stream:
        for text in stream.text_stream:
            yield text


def generate_daily_briefing(kev_entries: list[dict], cisa_alerts: list[dict]) -> Generator[str, None, None]:
    """
    Generate a daily threat briefing for a SOC analyst from CISA KEV + alert data.
    """
    # Summarise the data concisely so it fits well in the prompt
    kev_summary = []
    for e in kev_entries[:5]:
        kev_summary.append(
            f"- {e.get('cveID','?')} | {e.get('vendorProject','?')} {e.get('product','?')} | "
            f"Added: {e.get('dateAdded','?')} | Due: {e.get('dueDate','?')} | "
            f"{e.get('shortDescription','')[:120]}"
        )

    alert_summary = []
    for a in cisa_alerts[:3]:
        alert_summary.append(
            f"- {a.get('title','?')} ({a.get('published','?')}): {a.get('summary','')[:150]}"
        )

    prompt = f"""Today's date: {_today()}

You are opening the morning SOC shift. Generate a concise but thorough **Daily Threat Briefing** \
covering the items below. Structure it as a briefing document a Tier-1 SOC analyst would read in \
the first 15 minutes of their shift to understand what matters most right now.

## Recently Added to CISA Known Exploited Vulnerabilities (KEV) Catalog:
{chr(10).join(kev_summary) if kev_summary else "None fetched (API may be unavailable)."}

## Latest CISA Cybersecurity Alerts:
{chr(10).join(alert_summary) if alert_summary else "None fetched (API may be unavailable)."}

Your briefing should:
1. Open with a 2-sentence "Situation Report" (SITREP)
2. Highlight the 2-3 most urgent items and why
3. Recommend today's top SOC priorities
4. Close with a "Tip of the Day" — one technique, tool, or concept for the analyst to learn
"""
    yield from _stream_response(prompt)


def analyze_vulnerability(cve_data: dict) -> Generator[str, None, None]:
    """
    Deep-dive analysis of a single CVE for SOC training purposes.
    """
    cve_json = json.dumps({
        "id": cve_data.get("id"),
        "description": cve_data.get("description", "")[:400],
        "cvss_score": cve_data.get("cvss_score"),
        "cvss_vector": cve_data.get("cvss_vector"),
        "severity": cve_data.get("severity"),
        "cwes": cve_data.get("cwes", []),
        "affected_products": cve_data.get("affected_products", []),
        "published": cve_data.get("published"),
    }, indent=2)

    prompt = f"""Perform a full SOC analyst training analysis of the following CVE:

```json
{cve_json}
```

Follow your standard structured format (Plain English Summary, Real-World Impact, SOC Analyst \
Perspective, MITRE ATT&CK Mapping, Severity & Urgency, Recommended Actions, Learning Moment, \
Knowledge Check). Be thorough — this is the main learning exercise for the analyst today.
"""
    yield from _stream_response(prompt, use_thinking=True)


def analyze_kev_entry(entry: dict) -> Generator[str, None, None]:
    """
    Analyse a CISA KEV entry for SOC training.
    """
    entry_text = (
        f"CVE: {entry.get('cveID', 'N/A')}\n"
        f"Vendor/Product: {entry.get('vendorProject', '?')} — {entry.get('product', '?')}\n"
        f"Vulnerability Type: {entry.get('vulnerabilityName', 'N/A')}\n"
        f"Description: {entry.get('shortDescription', 'N/A')}\n"
        f"Date Added to KEV: {entry.get('dateAdded', '?')}\n"
        f"CISA Required Remediation Date: {entry.get('dueDate', '?')}\n"
        f"Known Ransomware Use: {entry.get('knownRansomwareCampaignUse', 'Unknown')}\n"
        f"Notes: {entry.get('notes', 'None')}"
    )

    prompt = f"""A new vulnerability has been added to the CISA Known Exploited Vulnerabilities catalog. \
This means it is being actively exploited in the wild right now. Provide a full SOC training analysis:

{entry_text}

Pay particular attention to:
- The fact that this is ACTIVELY EXPLOITED (emphasise urgency)
- Detection opportunities specific to this product/vendor
- Threat actor TTPs commonly associated with this type of vulnerability
- Whether ransomware groups are known to use it
"""
    yield from _stream_response(prompt, use_thinking=True)


def generate_threat_hunt_scenario(topic: str) -> Generator[str, None, None]:
    """
    Generate a realistic threat hunting scenario for SOC analyst practice.
    """
    prompt = f"""Create a detailed, realistic **Threat Hunting Scenario** for a SOC analyst trainee \
on the following topic: **{topic}**

The scenario should include:

### 🎯 Scenario Background
Set the scene: industry, organisation size, initial trigger/alert that kicked off the hunt.

### 📋 Your Mission
Clear objectives for the analyst — what are you hunting for?

### 🗃️ Available Data Sources
List the log sources and tools available (SIEM, EDR, network logs, etc.).

### 🔍 Hunting Hypothesis
A testable hypothesis based on known adversary behaviour (reference ATT&CK).

### 🧭 Step-by-Step Hunt Walkthrough
Walk through the hunt step by step, including:
- Specific queries/searches to run (use generic SIEM syntax)
- What normal looks like vs. what anomalous looks like
- Pivoting techniques to expand the investigation

### 🚩 Simulated Findings
Describe 3 realistic findings the analyst discovers during the hunt.

### 📊 Analyst Decision Points
At each finding, what decision does the analyst make? Escalate? Dismiss? Pivot?

### ✅ Outcome & After-Action Review
What was the final verdict? What could be improved?

### ❓ Knowledge Check
Two multiple-choice questions testing key concepts from this scenario.
"""
    yield from _stream_response(prompt, use_thinking=True)


def generate_quiz(topic: str, num_questions: int = 5) -> Generator[str, None, None]:
    """
    Generate a SOC analyst quiz on a given topic.
    """
    prompt = f"""Generate a {num_questions}-question multiple-choice quiz for a SOC analyst trainee \
on the topic: **{topic}**

Format each question as:

**Q[n]: [Question text]**
A) [Option]
B) [Option]
C) [Option]
D) [Option]

✅ **Correct Answer: [Letter]) [Answer]**
📖 **Explanation:** [2-3 sentence explanation of why this is correct and why the others are wrong]

---

Cover a range of difficulty levels (2 easy, 2 medium, 1 hard). Questions should test practical \
SOC analyst knowledge, not just theory — include scenario-based questions where possible.
"""
    yield from _stream_response(prompt)


def explain_concept(concept: str) -> Generator[str, None, None]:
    """
    Explain a cybersecurity concept from a SOC analyst perspective.
    """
    prompt = f"""Explain the following cybersecurity concept from a SOC analyst's perspective: \
**{concept}**

Structure your explanation as:

### 📖 What Is It?
Clear, jargon-free definition (2-3 sentences).

### 🔬 How Does It Work?
Technical explanation with enough depth for a junior analyst.

### 🧑‍💻 How Does a SOC Analyst Encounter This?
Real-world context — when and how would this appear in your daily work?

### 🔎 Detection & Response
How do you detect it? What do you do when you see it?

### 🔗 Related Concepts
2-3 related terms the analyst should also understand.

### ❓ Quick Check
One question to verify understanding.
"""
    yield from _stream_response(prompt)


def _today() -> str:
    from datetime import date
    return date.today().strftime("%A, %B %d, %Y")

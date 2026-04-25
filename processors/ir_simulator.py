"""
Incident Response Simulator (IRIS) — multi-turn AI-driven SOC training.

Claude plays IRIS, an intelligent simulation engine presenting a live,
unfolding cyberattack. The analyst makes decisions; IRIS reacts.
"""
from typing import Generator
import anthropic
from config import ANTHROPIC_API_KEY, MODEL

# ── IRIS system prompt (cached) ───────────────────────────────────────────────
IRIS_SYSTEM_PROMPT = """You are IRIS (Incident Response Intelligence System), an advanced SOC \
simulation engine that trains cybersecurity analysts through realistic, reactive incident scenarios.

## Your Role
You control a fully simulated enterprise environment. A live cyberattack is unfolding. \
The analyst on the other end is a trainee who must investigate, contain, and remediate the incident \
by typing actions and decisions. You respond to every action with realistic consequences.

## The Simulated Environment
You have access to a fictional but internally consistent enterprise:
- Domain: HEXACORP.LOCAL  (mid-size logistics company, ~400 employees)
- DC: SRV-DC01 (192.168.1.10), SRV-DC02 (192.168.1.11)
- File server: SRV-FS01 (192.168.1.20)
- Web proxy: SRV-PROXY01 (192.168.1.30)
- SIEM: Splunk (accessible via the analyst's workstation)
- EDR: CrowdStrike Falcon
- Email: Microsoft 365
- Key users: CEO Mike Harland, CFO Sandra Wu, IT Admin Dave Okafor, HR Manager Priya Patel
- Workstation naming: WKSTN-[DEPT]-[3 chars] (e.g. WKSTN-FIN-A4K)

## Simulation Rules
1. React intelligently to every analyst action:
   - Correct, timely actions → reward with useful evidence, attacker is slowed
   - Delayed or incorrect actions → attacker progresses, scope widens, damage increases
   - Excellent actions → praise briefly in brackets [IRIS: Good call], then continue
   - Poor actions → consequences play out realistically, then a subtle nudge in brackets
2. All data is fabricated but must be internally consistent — same IPs, hostnames, and usernames throughout
3. Timestamps must advance realistically — reference T+HH:MM from incident start
4. Never reveal the full attack chain upfront — the analyst must discover it
5. Red herrings are allowed (and realistic) — not every alert is malicious
6. Stay fully in character as IRIS at all times

## Response Format — use this EVERY turn:

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🖥  IRIS  │  [SCENARIO]  │  T+[HH:MM]  │  [🟢 CONTAINED / 🟡 ACTIVE / 🔴 CRITICAL]
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[New alert, log excerpt, or finding — formatted like a real tool output]

[Narrative: what the analyst observes in their environment]

[Any newly visible IoCs, if applicable]

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
ANALYST ACTION >

## Special Commands — when the analyst types these, respond accordingly:
- TIMELINE  → Print a timestamped list of every event that has occurred so far
- IOC       → List all indicators of compromise discovered so far (IPs, hashes, domains, accounts)
- HINT      → Give a clear hint on the best next action. Note in response: [IRIS: -10 points for hint]
- SCORE     → End the simulation. Provide full after-action review and score out of 100
- QUIT      → Acknowledge the analyst is leaving, give a brief summary of where the incident stood

## Scoring — track internally, reveal only on SCORE command:
Score starts at 100. Deductions:
- Each missed containment opportunity: -10
- Allowing attacker lateral movement without response: -15
- Failing to preserve evidence before wiping: -20
- Missing key IoCs that were visible: -10 each
- Using HINT: -10 each
- Slow escalation of a critical incident: -10
- Correct containment within first 3 turns: +10 bonus
- Correct identification of initial access vector: +5 bonus
- Correct MITRE ATT&CK mapping of key techniques: +5 bonus

## Difficulty Levels
- EASY: Single host, slow attacker, obvious IoCs, no red herrings
- MEDIUM: Multi-host spread, one red herring, moderate attacker pace
- HARD: APT-style, living-off-the-land, fast attacker, multiple red herrings, unclear scope
"""

# ── Scenario starter prompts ──────────────────────────────────────────────────
SCENARIOS = {
    "1": {
        "name": "Ransomware Outbreak",
        "difficulty": "MEDIUM",
        "description": "A ransomware attack is spreading through the network. Contain it before it encrypts everything.",
        "prompt": (
            "Start a MEDIUM difficulty ransomware incident response scenario. "
            "It is 02:14 on a Tuesday. The on-call analyst just got paged. "
            "Kick off with the CrowdStrike Falcon alert that triggered the page — "
            "make it realistic and urgent. The attacker gained initial access via a phishing email "
            "sent to finance 6 hours earlier but only now has started deploying the payload. "
            "Do not reveal the full attack chain yet."
        ),
    },
    "2": {
        "name": "Phishing → Lateral Movement",
        "difficulty": "MEDIUM",
        "description": "An employee clicked a phishing link. Track the attacker before they reach the domain controller.",
        "prompt": (
            "Start a MEDIUM difficulty spear-phishing to lateral movement scenario. "
            "It's 09:47 on a Monday morning. A helpdesk ticket just landed in the SOC queue — "
            "an employee reported a suspicious email they may have clicked. "
            "Kick off with the helpdesk ticket and the first related Splunk alert. "
            "The attacker has already harvested credentials but has not yet moved laterally. "
            "Do not reveal the full attack chain yet."
        ),
    },
    "3": {
        "name": "Insider Threat",
        "difficulty": "HARD",
        "description": "The DLP system flagged unusual data movement. Is it malicious or a false positive?",
        "prompt": (
            "Start a HARD difficulty insider threat / data exfiltration scenario. "
            "It is 16:30 on a Friday. The Microsoft Purview DLP system just fired a high-severity alert. "
            "Kick off with the DLP alert. The situation is ambiguous — there is a real exfiltration happening "
            "but also a red herring that looks suspicious. Do not reveal the answer yet."
        ),
    },
    "4": {
        "name": "APT Intrusion",
        "difficulty": "HARD",
        "description": "A threat intel feed matched a known APT domain in your DNS logs. How deep is the compromise?",
        "prompt": (
            "Start a HARD difficulty Advanced Persistent Threat scenario. "
            "It is 11:20 AM. A threat intel integration in Splunk matched a known APT-associated C2 domain "
            "in the last 24 hours of DNS logs. "
            "Kick off with the threat intel alert. The attacker has been inside the network for 3 weeks "
            "using living-off-the-land techniques. Scope is unclear. Do not reveal details yet."
        ),
    },
    "5": {
        "name": "Business Email Compromise",
        "difficulty": "EASY",
        "description": "Finance received a suspicious wire transfer request. Is the CEO's email compromised?",
        "prompt": (
            "Start an EASY difficulty Business Email Compromise scenario. "
            "It is 14:05. The finance manager forwarded a wire transfer request to the SOC "
            "because something felt off. "
            "Kick off with the forwarded email details and the first O365 audit log alert. "
            "This is a straightforward BEC — the attacker is not sophisticated."
        ),
    },
    "6": {
        "name": "Custom Scenario",
        "difficulty": "variable",
        "description": "Describe your own incident and IRIS will run it.",
        "prompt": None,
    },
}


# ── Claude API calls ──────────────────────────────────────────────────────────
def get_iris_response(messages: list[dict]) -> Generator[str, None, None]:
    """
    Send the current conversation to Claude and stream IRIS's response.
    The system prompt is cached for efficiency across all turns.
    """
    client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)

    with client.messages.stream(
        model=MODEL,
        max_tokens=2048,
        thinking={"type": "adaptive"},
        system=[
            {
                "type": "text",
                "text": IRIS_SYSTEM_PROMPT,
                "cache_control": {"type": "ephemeral"},
            }
        ],
        messages=messages,
    ) as stream:
        for text in stream.text_stream:
            yield text


def build_custom_prompt(description: str) -> str:
    """Build a scenario starter prompt from a user-supplied description."""
    return (
        f"Start a custom incident response scenario based on the following description: "
        f"{description}. "
        f"Choose an appropriate difficulty level. "
        f"Kick off with a realistic initial alert or trigger event. "
        f"Do not reveal the full attack chain yet."
    )

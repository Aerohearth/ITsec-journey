import sys
import os
import json
import asyncio
import time
from collections import defaultdict
from datetime import date
from typing import AsyncGenerator, Optional

# Allow imports from project root regardless of working directory
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import anthropic
from fastapi import FastAPI, Depends, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from fetchers.cisa import get_recent_kev_entries, get_cisa_alerts, get_all_kev_stats
from fetchers.nvd import get_recent_critical_cves, get_cve_by_id
from processors.ai_processor import SYSTEM_PROMPT
from processors.ir_simulator import IRIS_SYSTEM_PROMPT, SCENARIOS, build_custom_prompt
from config import MODEL, MAX_TOKENS, ANTHROPIC_API_KEY

app = FastAPI(title="SocForge API", version="1.2.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Startup check ─────────────────────────────────────────────────────────────

if not ANTHROPIC_API_KEY:
    import warnings
    warnings.warn("ANTHROPIC_API_KEY is not set — all AI endpoints will return errors.", stacklevel=1)


# ── Rate limiting ─────────────────────────────────────────────────────────────

_rate_store: dict[str, list[float]] = defaultdict(list)
RATE_LIMIT  = 20    # AI requests per window
RATE_WINDOW = 3600  # seconds (1 hour)

async def rate_limit(request: Request) -> None:
    ip  = request.client.host
    now = time.time()
    _rate_store[ip] = [t for t in _rate_store[ip] if now - t < RATE_WINDOW]
    if len(_rate_store[ip]) >= RATE_LIMIT:
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit reached: {RATE_LIMIT} AI requests per hour. Try again later.",
        )
    _rate_store[ip].append(now)


# ── Async Claude streaming helpers ────────────────────────────────────────────

async def _stream(prompt: str, use_thinking: bool = False) -> AsyncGenerator[str, None]:
    client = anthropic.AsyncAnthropic(api_key=ANTHROPIC_API_KEY)
    kwargs = {
        "model": MODEL,
        "max_tokens": MAX_TOKENS,
        "system": [
            {
                "type": "text",
                "text": SYSTEM_PROMPT,
                "cache_control": {"type": "ephemeral"},
            }
        ],
        "messages": [{"role": "user", "content": prompt}],
    }
    if use_thinking:
        kwargs["thinking"] = {"type": "adaptive"}

    try:
        async with client.messages.stream(**kwargs) as stream:
            async for text in stream.text_stream:
                yield text
    except anthropic.AuthenticationError:
        yield "\n\n[ERROR] Server API key is invalid or not set. Contact the administrator."
    except Exception as e:
        yield f"\n\n[ERROR] {e}"


async def _stream_iris(messages: list[dict]) -> AsyncGenerator[str, None]:
    client = anthropic.AsyncAnthropic(api_key=ANTHROPIC_API_KEY)
    try:
        async with client.messages.stream(
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
            async for text in stream.text_stream:
                yield text
    except anthropic.AuthenticationError:
        yield "\n\n[ERROR] Server API key is invalid or not set. Contact the administrator."
    except Exception as e:
        yield f"\n\n[ERROR] {e}"


def _today() -> str:
    return date.today().strftime("%A, %B %d, %Y")


# ── Prompt builders ───────────────────────────────────────────────────────────

def _briefing_prompt(kev_entries: list, cisa_alerts: list) -> str:
    kev_lines = [
        f"- {e.get('cveID','?')} | {e.get('vendorProject','?')} {e.get('product','?')} | "
        f"Added: {e.get('dateAdded','?')} | Due: {e.get('dueDate','?')} | "
        f"{e.get('shortDescription','')[:120]}"
        for e in kev_entries[:5]
    ]
    alert_lines = [
        f"- {a.get('title','?')} ({a.get('published','?')}): {a.get('summary','')[:150]}"
        for a in cisa_alerts[:3]
    ]
    return (
        f"Today's date: {_today()}\n\n"
        "You are opening the morning SOC shift. Generate a concise but thorough **Daily Threat Briefing** "
        "covering the items below. Structure it as a briefing document a Tier-1 SOC analyst would read in "
        "the first 15 minutes of their shift to understand what matters most right now.\n\n"
        "## Recently Added to CISA Known Exploited Vulnerabilities (KEV) Catalog:\n"
        f"{chr(10).join(kev_lines) if kev_lines else 'None fetched (API may be unavailable).'}\n\n"
        "## Latest CISA Cybersecurity Alerts:\n"
        f"{chr(10).join(alert_lines) if alert_lines else 'None fetched (API may be unavailable).'}\n\n"
        "Your briefing should:\n"
        "1. Open with a 2-sentence \"Situation Report\" (SITREP)\n"
        "2. Highlight the 2-3 most urgent items and why\n"
        "3. Recommend today's top SOC priorities\n"
        "4. Close with a \"Tip of the Day\" — one technique, tool, or concept for the analyst to learn"
    )


def _cve_analyze_prompt(cve_data: dict) -> str:
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
    return (
        f"Perform a full SOC analyst training analysis of the following CVE:\n\n"
        f"```json\n{cve_json}\n```\n\n"
        "Follow your standard structured format (Plain English Summary, Real-World Impact, SOC Analyst "
        "Perspective, MITRE ATT&CK Mapping, Severity & Urgency, Recommended Actions, Learning Moment, "
        "Knowledge Check). Be thorough — this is the main learning exercise for the analyst today."
    )


def _kev_analyze_prompt(entry: dict) -> str:
    return (
        "A new vulnerability has been added to the CISA Known Exploited Vulnerabilities catalog. "
        "This means it is being actively exploited in the wild right now. Provide a full SOC training analysis:\n\n"
        f"CVE: {entry.get('cveID', 'N/A')}\n"
        f"Vendor/Product: {entry.get('vendorProject', '?')} — {entry.get('product', '?')}\n"
        f"Vulnerability Type: {entry.get('vulnerabilityName', 'N/A')}\n"
        f"Description: {entry.get('shortDescription', 'N/A')}\n"
        f"Date Added to KEV: {entry.get('dateAdded', '?')}\n"
        f"CISA Required Remediation Date: {entry.get('dueDate', '?')}\n"
        f"Known Ransomware Use: {entry.get('knownRansomwareCampaignUse', 'Unknown')}\n"
        f"Notes: {entry.get('notes', 'None')}\n\n"
        "Pay particular attention to:\n"
        "- The fact that this is ACTIVELY EXPLOITED (emphasise urgency)\n"
        "- Detection opportunities specific to this product/vendor\n"
        "- Threat actor TTPs commonly associated with this type of vulnerability\n"
        "- Whether ransomware groups are known to use it"
    )


def _threathunt_prompt(topic: str) -> str:
    return (
        f"Create a detailed, realistic **Threat Hunting Scenario** for a SOC analyst trainee "
        f"on the following topic: **{topic}**\n\n"
        "### 🎯 Scenario Background\n"
        "Set the scene: industry, organisation size, initial trigger/alert that kicked off the hunt.\n\n"
        "### 📋 Your Mission\n"
        "Clear objectives for the analyst — what are you hunting for?\n\n"
        "### 🗃️ Available Data Sources\n"
        "List the log sources and tools available (SIEM, EDR, network logs, etc.).\n\n"
        "### 🔍 Hunting Hypothesis\n"
        "A testable hypothesis based on known adversary behaviour (reference ATT&CK).\n\n"
        "### 🧭 Step-by-Step Hunt Walkthrough\n"
        "Walk through the hunt step by step: specific queries, normal vs anomalous, pivoting techniques.\n\n"
        "### 🚩 Simulated Findings\n"
        "Describe 3 realistic findings the analyst discovers during the hunt.\n\n"
        "### 📊 Analyst Decision Points\n"
        "At each finding, what decision does the analyst make? Escalate? Dismiss? Pivot?\n\n"
        "### ✅ Outcome & After-Action Review\n"
        "What was the final verdict? What could be improved?\n\n"
        "### ❓ Knowledge Check\n"
        "Two multiple-choice questions testing key concepts from this scenario."
    )


def _explain_prompt(concept: str) -> str:
    return (
        f"Explain the following cybersecurity concept from a SOC analyst's perspective: **{concept}**\n\n"
        "### 📖 What Is It?\nClear, jargon-free definition (2-3 sentences).\n\n"
        "### 🔬 How Does It Work?\nTechnical explanation with enough depth for a junior analyst.\n\n"
        "### 🧑‍💻 How Does a SOC Analyst Encounter This?\n"
        "Real-world context — when and how would this appear in your daily work?\n\n"
        "### 🔎 Detection & Response\nHow do you detect it? What do you do when you see it?\n\n"
        "### 🔗 Related Concepts\n2-3 related terms the analyst should also understand.\n\n"
        "### ❓ Quick Check\nOne question to verify understanding."
    )


def _quiz_prompt(topic: str, num: int) -> str:
    return (
        f"Generate a {num}-question multiple-choice quiz for a SOC analyst trainee "
        f"on the topic: **{topic}**\n\n"
        "Format each question exactly as:\n\n"
        "**Q[n]: [Question text]**\n"
        "A) [Option]\nB) [Option]\nC) [Option]\nD) [Option]\n\n"
        "✅ **Correct Answer: [Letter]) [Answer]**\n"
        "📖 **Explanation:** [2-3 sentence explanation of why this is correct and why the others are wrong]\n\n"
        "---\n\n"
        "Cover a range of difficulty (2 easy, 2 medium, 1 hard for a 5-question quiz, scaled proportionally). "
        "Include scenario-based questions where possible."
    )


# ── Request/response models ───────────────────────────────────────────────────

class CveAnalyzeRequest(BaseModel):
    cve_id: Optional[str] = None
    cve_data: Optional[dict] = None

class KevAnalyzeRequest(BaseModel):
    entry: dict

class ThreatHuntRequest(BaseModel):
    topic: str

class ExplainRequest(BaseModel):
    concept: str

class QuizRequest(BaseModel):
    topic: str
    num_questions: int = 5

class IrisRequest(BaseModel):
    messages: list[dict]


# ── Endpoints ─────────────────────────────────────────────────────────────────

@app.post("/api/briefing")
async def briefing(_: None = Depends(rate_limit)):
    kev_entries, cisa_alerts = await asyncio.gather(
        asyncio.to_thread(get_recent_kev_entries, 14, 5),
        asyncio.to_thread(get_cisa_alerts, 3),
    )
    prompt = _briefing_prompt(kev_entries, cisa_alerts)
    return StreamingResponse(_stream(prompt), media_type="text/plain; charset=utf-8")


@app.get("/api/cves")
async def cves(days: int = Query(7), limit: int = Query(10)):
    data = await asyncio.to_thread(get_recent_critical_cves, days, limit)
    return data


@app.post("/api/cves/analyze")
async def cve_analyze(req: CveAnalyzeRequest, _: None = Depends(rate_limit)):
    if req.cve_data:
        cve_data = req.cve_data
    elif req.cve_id:
        cve_data = await asyncio.to_thread(get_cve_by_id, req.cve_id)
        if not cve_data:
            raise HTTPException(status_code=404, detail=f"CVE {req.cve_id} not found in NVD.")
        if "error" in cve_data:
            raise HTTPException(status_code=502, detail=cve_data["error"])
    else:
        raise HTTPException(status_code=400, detail="Provide cve_id or cve_data.")
    prompt = _cve_analyze_prompt(cve_data)
    return StreamingResponse(_stream(prompt, use_thinking=True), media_type="text/plain; charset=utf-8")


@app.get("/api/exploits")
async def exploits(days: int = Query(30), limit: int = Query(15)):
    data = await asyncio.to_thread(get_recent_kev_entries, days, limit)
    return data


@app.post("/api/exploits/analyze")
async def exploits_analyze(req: KevAnalyzeRequest, _: None = Depends(rate_limit)):
    prompt = _kev_analyze_prompt(req.entry)
    return StreamingResponse(_stream(prompt, use_thinking=True), media_type="text/plain; charset=utf-8")


@app.post("/api/threathunt")
async def threathunt(req: ThreatHuntRequest, _: None = Depends(rate_limit)):
    prompt = _threathunt_prompt(req.topic)
    return StreamingResponse(_stream(prompt, use_thinking=True), media_type="text/plain; charset=utf-8")


@app.post("/api/explain")
async def explain(req: ExplainRequest, _: None = Depends(rate_limit)):
    prompt = _explain_prompt(req.concept)
    return StreamingResponse(_stream(prompt), media_type="text/plain; charset=utf-8")


@app.post("/api/quiz")
async def quiz(req: QuizRequest, _: None = Depends(rate_limit)):
    num = max(1, min(req.num_questions, 15))
    prompt = _quiz_prompt(req.topic, num)
    return StreamingResponse(_stream(prompt), media_type="text/plain; charset=utf-8")


@app.get("/api/kevstats")
async def kevstats():
    data = await asyncio.to_thread(get_all_kev_stats)
    return data


@app.get("/api/iris/scenarios")
async def iris_scenarios():
    return {
        key: {
            "name": s["name"],
            "difficulty": s["difficulty"],
            "description": s["description"],
            "prompt": s["prompt"],
        }
        for key, s in SCENARIOS.items()
    }


@app.post("/api/iris")
async def iris(req: IrisRequest, _: None = Depends(rate_limit)):
    if not req.messages:
        raise HTTPException(status_code=400, detail="messages list is required.")
    return StreamingResponse(_stream_iris(req.messages), media_type="text/plain; charset=utf-8")


@app.get("/api/health")
async def health():
    return {"status": "ok", "version": "1.3.0"}


# Serve frontend — mounted last so /api/* routes take priority
_frontend = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "frontend")
if os.path.isdir(_frontend):
    app.mount("/", StaticFiles(directory=_frontend, html=True), name="frontend")

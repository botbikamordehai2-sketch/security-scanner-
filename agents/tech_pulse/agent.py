"""
Tech Pulse Agent — Google CSE Research + DeepSeek Summarizer.
Daily research: scans GitHub, Medium, ArXiv, TechCrunch for innovations.
Summarizes findings via DeepSeek into actionable insights.

Deployed as: Cloud Run Private Service (no external access)
Triggered by: Pub/Sub Push Subscription on "scan.requests" topic  OR  cron schedule
Outputs to:   Pub/Sub Topic "scan.results" + Firestore

Local dev:    python agent.py → starts Flask on :8080
"""

import asyncio
import base64
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

# ── Add project root to path ──
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import httpx
from flask import Flask, request, jsonify

from shared.db import get_db
from shared.events import ScanResult
from shared.pubsub_utils import publish_message, IS_CLOUD
from shared.deepseek import get_deepseek

app = Flask(__name__)
PORT = int(os.environ.get("PORT", 8080))

# ── Configuration ────────────────────────────────────

GOOGLE_API_KEY = os.environ.get("GOOGLE_API_KEY", "")
SEARCH_ENGINE_CX = os.environ.get("SEARCH_ENGINE_CX", "53abe856f64dd45b5")
DEEPSEEK_API_KEY = os.environ.get("DEEPSEEK_API_KEY", "")

BASE_URL = "https://www.googleapis.com/customsearch/v1"

# Research queries — each yields different innovation angles
RESEARCH_QUERIES = [
    "new open source cybersecurity tools 2026 site:github.com",
    "latest AI security research papers agentic workflows site:arxiv.org",
    "nuclei templates new vulnerabilities 2026",
    "advanced web security automation scripts python 2026",
    "cloud security scanning tools open source 2026 site:github.com",
    "OWASP top vulnerabilities new techniques 2026",
    "Lighthouse performance SEO automation tools 2026 site:github.com",
    "AI agent cybersecurity autonomous scanning 2026",
]


# ── Google CSE Fetcher ──────────────────────────────

async def fetch_single_query(client: httpx.AsyncClient, query: str, days_back: int = 7) -> List[Dict]:
    """Fetch results for a single research query from Google CSE."""
    params = {
        "key": GOOGLE_API_KEY,
        "cx": SEARCH_ENGINE_CX,
        "q": query,
        "dateRestrict": f"d{days_back}",
        "num": 5,  # Top 5 per query
    }
    try:
        resp = await client.get(BASE_URL, params=params, timeout=15.0)
        if resp.status_code == 200:
            items = resp.json().get("items", [])
            return [
                {
                    "title": item.get("title", ""),
                    "link": item.get("link", ""),
                    "snippet": item.get("snippet", ""),
                    "source": item.get("displayLink", ""),
                    "query": query,
                }
                for item in items
            ]
        else:
            print(f"[tech_pulse] CSE error {resp.status_code} for '{query}': {resp.text[:200]}")
            return []
    except Exception as e:
        print(f"[tech_pulse] CSE exception for '{query}': {e}")
        return []


async def run_research(days_back: int = 7) -> List[Dict]:
    """Run all research queries in parallel, deduplicate by link."""
    if not GOOGLE_API_KEY:
        print("[tech_pulse] WARNING: GOOGLE_API_KEY not set — returning empty results")
        return []

    async with httpx.AsyncClient() as client:
        tasks = [fetch_single_query(client, q, days_back) for q in RESEARCH_QUERIES]
        all_results = await asyncio.gather(*tasks)

    # Flatten + deduplicate by link
    seen_links = set()
    unique_findings = []
    for result_list in all_results:
        for finding in result_list:
            link = finding.get("link", "")
            if link and link not in seen_links:
                seen_links.add(link)
                unique_findings.append(finding)

    # Sort by source priority: github > arxiv > medium > others
    source_priority = {"github.com": 0, "arxiv.org": 1, "medium.com": 2, "techcrunch.com": 3}
    unique_findings.sort(key=lambda f: source_priority.get(
        f.get("source", "").replace("www.", "").split("/")[0], 99
    ))

    print(f"[tech_pulse] Found {len(unique_findings)} unique innovations across {len(RESEARCH_QUERIES)} queries")
    return unique_findings


# ── DeepSeek Summarizer ──────────────────────────────

def summarize_with_deepseek(findings: List[Dict]) -> Dict[str, Any]:
    """
    Send top findings to DeepSeek for summarization into actionable insights.
    Uses shared DeepSeekClient with retry logic.
    Returns a structured summary dict.
    """
    client = get_deepseek()
    if not client.is_configured or not findings:
        return {
            "summary": "DeepSeek not available or no findings to summarize",
            "top_innovations": findings[:5] if findings else [],
            "categories": {},
        }

    # Prepare context — top 10 findings
    context_parts = []
    for i, f in enumerate(findings[:10], 1):
        context_parts.append(
            f"{i}. [{f['title']}]({f['link']})\n"
            f"   Source: {f['source']} | {f['snippet'][:200]}"
        )
    context = "\n\n".join(context_parts)

    prompt = f"""You are a Technology Innovation Analyst for an autonomous security scanning platform (Agentic Security Scanner).

These are the latest innovations found this week from GitHub, ArXiv, Medium, and TechCrunch. 

Analyze them and produce a structured Hebrew summary:

**RESEARCH FINDINGS:**
{context}

**YOUR TASK:**
Write a Hebrew summary with these 3 sections:

### 🔥 3 החידושים הכי מעניינים השבוע
(Choose 3 and explain why they matter for a security scanning SaaS)

### 🛠️ מה אפשר להטמיע אצלנו עכשיו
(Practical steps — which tools/code/libraries can we integrate into our platform right now)

### 📈 Trend Alert
(What broader trend do these findings indicate about cybersecurity/AI in 2026)

Format: Hebrew RTL, technical but accessible, actionable. Keep total output under 500 words."""

    try:
        result = client.chat(
            prompt=prompt,
            system="You are a Technology Innovation Analyst. Respond in Hebrew RTL.",
            temperature=0.3,
            max_tokens=1200,
        )
        return {
            "summary": result["response"],
            "top_innovations": findings[:5],
            "total_findings": len(findings),
            "summarized_at": datetime.now(timezone.utc).isoformat(),
        }
    except Exception as e:
        print(f"[tech_pulse] DeepSeek error: {e}")
        return {
            "summary": f"DeepSeek unavailable: {str(e)}",
            "top_innovations": findings[:5],
        }


# ── Pub/Sub Push Handler ─────────────────────────────

def validate_pubsub_request(envelope: dict) -> dict | None:
    """Extract and decode the Pub/Sub message payload."""
    message = envelope.get("message")
    if not message:
        return None
    data_b64 = message.get("data", "")
    if not data_b64:
        return None
    try:
        decoded = base64.b64decode(data_b64).decode("utf-8")
        return json.loads(decoded)
    except Exception:
        return None


@app.route("/", methods=["POST"])
def handle_pubsub_push():
    """Handle incoming Pub/Sub push messages — triggers research cycle."""
    envelope = request.get_json(force=True, silent=True) or {}

    payload = validate_pubsub_request(envelope)
    if payload is None:
        print("[tech_pulse] Invalid Pub/Sub message — acking")
        return ("", 204)

    request_id = payload.get("request_id", "manual")
    days_back = payload.get("options", {}).get("days_back", 7)

    print(f"[tech_pulse] Received research request {request_id} — scanning last {days_back} days")

    # ── Idempotency ──
    db = get_db()
    if db.request_exists(request_id):
        print(f"[tech_pulse] Duplicate request {request_id} — skipping")
        return ("", 204)

    db.mark_request_started(request_id, "tech_pulse_research")

    # ── Run research ──
    start_time = time.time()
    try:
        findings = asyncio.run(run_research(days_back=days_back))
        summary = summarize_with_deepseek(findings)
        status = "success"
        error_code = None
        error_message = None
        data = {
            "findings_count": len(findings),
            "findings": findings,
            "summary": summary.get("summary", ""),
            "top_innovations": summary.get("top_innovations", []),
            "queries_run": len(RESEARCH_QUERIES),
            "days_back": days_back,
        }
    except Exception as e:
        findings = []
        data = {}
        status = "error"
        error_code = "RESEARCH_FAILED"
        error_message = str(e)

    duration_ms = int((time.time() - start_time) * 1000)

    # ── Build ScanResult ──
    result = ScanResult(
        request_id=request_id,
        agent_type="tech_pulse_agent",
        status=status,
        data=data,
        error_code=error_code,
        error_message=error_message,
        metrics={
            "duration_ms": duration_ms,
            "findings_count": len(findings),
            "queries_run": len(RESEARCH_QUERIES),
            "deepseek_used": bool(DEEPSEEK_API_KEY and findings),
        },
    )

    # ── Save to DB ──
    db.save_agent_result(request_id, "tech_pulse_agent", result.model_dump())

    # ── Publish to scan.results ──
    result_json = result.model_dump_json()
    msg_id = publish_message("scan.results", result_json, ordering_key=request_id)
    print(f"[tech_pulse] Published research results for {request_id} — msg_id: {msg_id}")

    return ("", 204)


# ── Manual Trigger (for cron / Cloud Scheduler) ──────

@app.route("/run", methods=["POST", "GET"])
def manual_trigger():
    """Manual or cron trigger — runs research immediately. Ideal for Cloud Scheduler."""
    request_id = f"pulse-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M')}"
    db = get_db()

    if db.request_exists(request_id):
        return jsonify({"status": "already_ran_today", "request_id": request_id})

    db.mark_request_started(request_id, "tech_pulse_daily")

    start_time = time.time()
    try:
        findings = asyncio.run(run_research(days_back=7))
        summary = summarize_with_deepseek(findings)
        data = {
            "findings_count": len(findings),
            "findings": findings,
            "summary": summary.get("summary", ""),
            "top_innovations": summary.get("top_innovations", []),
        }
        status = "success"
    except Exception:
        data = {}
        status = "error"

    duration_ms = int((time.time() - start_time) * 1000)

    result = ScanResult(
        request_id=request_id,
        agent_type="tech_pulse_agent",
        status=status,
        data=data,
        metrics={"duration_ms": duration_ms, "findings_count": len(findings) if findings else 0},
    )
    db.save_agent_result(request_id, "tech_pulse_agent", result.model_dump())

    return jsonify({
        "request_id": request_id,
        "status": status,
        "findings_count": len(findings) if status == "success" else 0,
        "duration_ms": duration_ms,
    })


# ── Health ───────────────────────────────────────────

@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "healthy",
        "agent": "tech_pulse_agent",
        "version": "1.0.0",
        "cloud": IS_CLOUD,
        "cse_configured": bool(GOOGLE_API_KEY),
        "deepseek_configured": bool(DEEPSEEK_API_KEY),
        "cx_id": SEARCH_ENGINE_CX[:8] + "..." if SEARCH_ENGINE_CX else "not set",
    })


# ── Main ─────────────────────────────────────────────

if __name__ == "__main__":
    # Quick local test if run directly
    if not GOOGLE_API_KEY:
        print("⚠️  GOOGLE_API_KEY not set — CSE queries will be skipped")
    print(f"🔬 Tech Pulse Agent starting on port {PORT}...")
    print(f"   Health:      http://127.0.0.1:{PORT}/health")
    print(f"   Manual Run:  http://127.0.0.1:{PORT}/run")
    print(f"   CX ID:       {SEARCH_ENGINE_CX}")
    app.run(host="0.0.0.0", port=PORT, debug=not IS_CLOUD)
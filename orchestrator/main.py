"""
Orchestrator — FastAPI Service + Dashboard.
Entrypoint for the Agentic Security Scanner Platform.

Endpoints (backward compatible):
    GET  /                    — Dashboard HTML
    GET  /api/health          — Health check
    POST /api/scan/security   — Direct synchronous scan (MVP API, unchanged)

Endpoints (Phase 2 — Event-Driven):
    POST /api/scan/orchestrate — Publish to Pub/Sub, agents run async
    GET  /api/scan/status/{id} — Poll scan status from Firestore

Deploy: Cloud Run Public (or IAM-protected)
"""

import os
import sys
import socket
from pathlib import Path
from urllib.parse import urlparse
from uuid import uuid4

import requests
import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel
from typing import List, Optional, Dict, Any

# ── Add project root so shared/ imports work ──
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from shared.events import (
    ScanRequest,
    ScanResult,
    ScanResponseV1,
    VulnerabilityItem,
)
from shared.pubsub_utils import publish_message, IS_CLOUD
from shared.db import get_db
from shared.deepseek import get_deepseek, DeepSeekError

# ── FastAPI App ──────────────────────────────────────

app = FastAPI(
    title="Agentic Security Scanner — Orchestrator",
    version="2.0.0",
    description="Multi-Agent Security Scanning Platform",
)

# ── Serve Dashboard on root ──────────────────────────

TEMPLATE_DIR = PROJECT_ROOT / "templates"
DASHBOARD_PATH = TEMPLATE_DIR / "dashboard.html"


@app.get("/", response_class=HTMLResponse)
def serve_dashboard():
    """Serve the Security Scanner Dashboard as the landing page."""
    if DASHBOARD_PATH.exists():
        return DASHBOARD_PATH.read_text(encoding="utf-8")
    return HTMLResponse(content="<h1>Dashboard not found</h1>", status_code=404)


# ── CORS ─────────────────────────────────────────────

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Pydantic Models ──────────────────────────────────

class ScanPayload(BaseModel):
    target_url: str


class OrchestratePayload(BaseModel):
    target_url: str
    agents: List[str] = ["security_agent"]
    depth: str = "standard"
    callback: Optional[str] = None  # e.g. "telegram://chat_1246833993"


class ScanStatusResponse(BaseModel):
    request_id: str
    status: str
    agents_completed: List[str]
    agents_pending: List[str]
    results: Dict[str, Any] = {}


# ── Scan Engine (same logic, kept for direct endpoint) ──

HEADER_SEVERITY = {
    "Content-Security-Policy": {
        "severity": "HIGH",
        "description": "CSP header is missing — XSS and data injection attacks possible.",
        "remediation": "Add a Content-Security-Policy header to restrict script sources and inline execution."
    },
    "Strict-Transport-Security": {
        "severity": "HIGH",
        "description": "HSTS header is missing — MITM downgrade attacks possible.",
        "remediation": "Add Strict-Transport-Security header with max-age=31536000; includeSubDomains."
    },
    "X-Frame-Options": {
        "severity": "MEDIUM",
        "description": "X-Frame-Options header is missing — clickjacking risk.",
        "remediation": "Add X-Frame-Options: DENY or SAMEORIGIN to prevent framing attacks."
    },
}

EXTRA_HEADERS = {
    "X-Content-Type-Options": {
        "severity": "LOW",
        "description": "X-Content-Type-Options missing — MIME-type sniffing possible.",
        "remediation": "Add X-Content-Type-Options: nosniff."
    },
    "Referrer-Policy": {
        "severity": "LOW",
        "description": "Referrer-Policy missing — referrer info may leak to external sites.",
        "remediation": "Add Referrer-Policy: strict-origin-when-cross-origin."
    },
    "Permissions-Policy": {
        "severity": "LOW",
        "description": "Permissions-Policy missing — browser features unrestricted.",
        "remediation": "Add Permissions-Policy header to restrict browser API access."
    },
}


def check_port(host: str, port: int, timeout: int = 2) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError, socket.gaierror, OSError):
        return False


# ── Health ───────────────────────────────────────────

@app.get("/api/health")
def health_check():
    return {
        "status": "ok",
        "service": "agentic-security-scanner",
        "version": "2.0.0",
        "cloud": IS_CLOUD,
        "mode": "orchestrator",
    }


# ── Direct Scan (MVP — kept 100% unchanged) ──────────

@app.post("/api/scan/security", response_model=ScanResponseV1)
def run_security_scan_direct(payload: ScanPayload):
    """
    Direct synchronous security scan.
    This is the original MVP endpoint — unchanged for backward compatibility.
    """
    import requests as req_lib

    url = payload.target_url.strip()

    # Normalize URL
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url

    parsed_url = urlparse(url)
    hostname = parsed_url.hostname

    if not hostname:
        raise HTTPException(status_code=400, detail="Invalid URL provided. Could not extract hostname.")

    is_https = parsed_url.scheme == "https"

    # Ports
    open_ports = []
    for port in [80, 443]:
        if check_port(hostname, port):
            open_ports.append(port)

    # HTTP GET
    try:
        response = req_lib.get(
            url, timeout=10, allow_redirects=True,
            headers={"User-Agent": "AgenticSecurityScanner/2.0 (Orchestrator)"}
        )
        final_url = str(response.url)
        status_code = response.status_code
        headers = response.headers
    except req_lib.exceptions.Timeout:
        raise HTTPException(status_code=504, detail="Request timed out.")
    except req_lib.exceptions.ConnectionError:
        raise HTTPException(status_code=502, detail="Failed to connect or resolve DNS.")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal scanning error: {str(e)}")

    # Headers inspection
    required_headers = [
        "Content-Security-Policy",
        "Strict-Transport-Security",
        "X-Frame-Options",
    ]
    missing_headers = []
    vulnerabilities = []

    for header in required_headers:
        if header not in headers:
            if header == "Strict-Transport-Security" and not is_https:
                continue
            missing_headers.append(header)
            info = HEADER_SEVERITY.get(header, {
                "severity": "LOW",
                "description": f"{header} is missing.",
                "remediation": f"Add {header} header."
            })
            vulnerabilities.append(VulnerabilityItem(
                header=header,
                severity=info["severity"],
                description=info["description"],
                remediation=info["remediation"],
            ))

    for header, info in EXTRA_HEADERS.items():
        if header not in headers:
            vulnerabilities.append(VulnerabilityItem(
                header=header,
                severity=info["severity"],
                description=info["description"],
                remediation=info["remediation"],
            ))

    # Score
    score_deductions = {"HIGH": 25, "MEDIUM": 15, "LOW": 5}
    security_score = 100
    for v in vulnerabilities:
        security_score -= score_deductions.get(v.severity, 5)
    security_score = max(0, security_score)

    # Response headers
    interesting_headers = {}
    for key in ["Server", "X-Powered-By", "Content-Type", "Cache-Control", "Set-Cookie", "Location"]:
        if key in headers:
            interesting_headers[key] = headers[key]

    return ScanResponseV1(
        target_url=url,
        final_url=final_url,
        is_https=is_https,
        status_code=status_code,
        open_ports=open_ports,
        missing_headers=missing_headers,
        vulnerabilities=vulnerabilities,
        security_score=security_score,
        scan_status="completed",
        response_headers=interesting_headers,
    )


# ── Orchestrated Scan (Phase 2 — Event-Driven) ───────

@app.post("/api/scan/orchestrate")
def orchestrate_scan(payload: OrchestratePayload):
    """
    Fire-and-forget orchestrated scan via Pub/Sub.
    Publishes to scan.requests → agents pick up → results → scan.results → Firestore.

    Returns immediately with request_id — poll /api/scan/status/{id} for results.
    """
    request_id = uuid4().hex[:12]
    target_url = payload.target_url.strip()

    # Normalize
    if not target_url.startswith("http://") and not target_url.startswith("https://"):
        target_url = "https://" + target_url

    # Build ScanRequest
    scan_req = ScanRequest(
        request_id=request_id,
        target_url=target_url,
        agents_to_run=payload.agents,
        depth=payload.depth,
        options={"callback": payload.callback} if payload.callback else {},
    )

    # Save to Firestore (idempotency marker)
    db = get_db()
    if db.request_exists(request_id):
        return JSONResponse(
            content={"status": "duplicate", "request_id": request_id},
            status_code=409,
        )

    db.mark_request_started(request_id, target_url)
    db.save_scan_document(request_id, {
        "request_id": request_id,
        "target_url": target_url,
        "agents_requested": payload.agents,
        "depth": payload.depth,
        "status": "published",
        "agent_results": {},
    })

    # Publish to Pub/Sub
    payload_json = scan_req.model_dump_json()
    msg_id = publish_message("scan.requests", payload_json, ordering_key=request_id)

    return {
        "request_id": request_id,
        "message_id": msg_id,
        "status": "published",
        "agents": payload.agents,
        "poll_url": f"/api/scan/status/{request_id}",
    }


# ── Scan Status (Phase 2) ────────────────────────────

@app.get("/api/scan/status/{request_id}", response_model=ScanStatusResponse)
def get_scan_status(request_id: str):
    """Poll for scan completion status."""
    db = get_db()
    scan_doc = db.get_scan(request_id)

    if not scan_doc:
        raise HTTPException(status_code=404, detail=f"Scan {request_id} not found")

    agents_requested = scan_doc.get("agents_requested", [])
    agent_results = scan_doc.get("agent_results", {})

    completed = [a for a in agents_requested if a in agent_results]
    pending = [a for a in agents_requested if a not in agent_results]

    overall_status = "completed" if not pending else "processing"

    return ScanStatusResponse(
        request_id=request_id,
        status=overall_status,
        agents_completed=completed,
        agents_pending=pending,
        results={
            agent: agent_results[agent]
            for agent in completed
        },
    )


# ── DeepSeek Agent (Agent #3 in Swarm) ──────────────

class DeepSeekPrompt(BaseModel):
    prompt: str
    system: Optional[str] = "You are a helpful assistant."
    temperature: Optional[float] = 0.7
    max_tokens: Optional[int] = 1024


@app.post("/api/agent/deepseek")
def deepseek_agent(payload: DeepSeekPrompt):
    """
    Agent #3 — DeepSeek AI.
    Callable by Cline, Dashboard, or any agent in the swarm.
    Uses shared DeepSeekClient with retry logic + correct /v1/ URL.
    Requires DEEPSEEK_API_KEY environment variable.
    """
    client = get_deepseek()
    if not client.is_configured:
        raise HTTPException(
            status_code=503,
            detail="DeepSeek API key not configured. Set DEEPSEEK_API_KEY env var.",
        )

    try:
        result = client.chat(
            prompt=payload.prompt,
            system=payload.system,
            temperature=payload.temperature or 0.7,
            max_tokens=payload.max_tokens or 1024,
        )
        return result
    except DeepSeekError as e:
        raise HTTPException(status_code=502, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"DeepSeek agent error: {str(e)}")


# ── Backoffice Trader Webhook ─────────────────────

class TradeAlertPayload(BaseModel):
    """Payload for Backoffice Trader notifications."""
    symbol: str
    action: str  # BUY, SELL, ALERT
    price: Optional[float] = None
    stop_loss: Optional[float] = None
    take_profit: Optional[float] = None
    rationale: Optional[str] = None
    agent_source: Optional[str] = "data_hunter_agent"  # Which agent generated this
    notify_telegram: bool = True
    notify_email: bool = False
    email_to: Optional[str] = None


TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "")  # Default VIP channel
SENDGRID_API_KEY = os.environ.get("SENDGRID_API_KEY", "")
FROM_EMAIL = os.environ.get("FROM_EMAIL", "alerts@commotiai.com")


def send_telegram_alert(message: str, chat_id: str = None) -> dict:
    """Send a message via Telegram Bot API. Returns response dict."""
    token = TELEGRAM_BOT_TOKEN
    target_chat = chat_id or TELEGRAM_CHAT_ID

    if not token or not target_chat:
        return {"sent": False, "error": "TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID not configured"}

    try:
        resp = requests.post(
            f"https://api.telegram.org/bot{token}/sendMessage",
            json={
                "chat_id": target_chat,
                "text": message,
                "parse_mode": "Markdown",
                "disable_web_page_preview": True,
            },
            timeout=10,
        )
        if resp.status_code == 200:
            return {"sent": True, "channel": "telegram", "chat_id": target_chat}
        else:
            return {"sent": False, "error": f"Telegram API returned {resp.status_code}: {resp.text[:200]}"}
    except Exception as e:
        return {"sent": False, "error": str(e)}


def send_email_alert(subject: str, body: str, to_email: str) -> dict:
    """Send an email via SendGrid. Returns response dict."""
    if not SENDGRID_API_KEY:
        return {"sent": False, "error": "SENDGRID_API_KEY not configured"}

    try:
        resp = requests.post(
            "https://api.sendgrid.com/v3/mail/send",
            headers={
                "Authorization": f"Bearer {SENDGRID_API_KEY}",
                "Content-Type": "application/json",
            },
            json={
                "personalizations": [{"to": [{"email": to_email}]}],
                "from": {"email": FROM_EMAIL},
                "subject": subject,
                "content": [{"type": "text/plain", "value": body}],
            },
            timeout=10,
        )
        if resp.status_code in (200, 201, 202):
            return {"sent": True, "channel": "email", "to": to_email}
        else:
            return {"sent": False, "error": f"SendGrid returned {resp.status_code}: {resp.text[:200]}"}
    except Exception as e:
        return {"sent": False, "error": str(e)}


@app.post("/api/backoffice/trade-alert")
def backoffice_trade_alert(payload: TradeAlertPayload):
    """
    Backoffice Trader Webhook — receives trade alerts from any agent and dispatches them.

    Supported channels:
    - Telegram (default: VIP channel)
    - Email (via SendGrid)

    Called by: Data Hunter, Tech Pulse, or any agent that generates trading signals.
    Also callable by Cline/Dashboard as a manual override.
    """
    # Build alert message
    emoji = "🟢" if payload.action.upper() == "BUY" else "🔴" if payload.action.upper() == "SELL" else "⚠️"

    lines = [
        f"{emoji} *Trade Alert — {payload.action.upper()}*",
        f"",
        f"*Instrument:* `{payload.symbol}`",
    ]
    if payload.price:
        lines.append(f"*Price:* ${payload.price:,.2f}")
    if payload.stop_loss:
        lines.append(f"*Stop Loss:* ${payload.stop_loss:,.2f}")
    if payload.take_profit:
        lines.append(f"*Take Profit:* ${payload.take_profit:,.2f}")
    if payload.rationale:
        lines.append(f"")
        lines.append(f"*Analysis:* {payload.rationale}")
    if payload.agent_source:
        lines.append(f"")
        lines.append(f"🤖 _Source: {payload.agent_source}_")

    message = "\n".join(lines)
    email_body = message.replace("*", "").replace("`", "").replace("_", "")

    results = []

    # ── Telegram ──
    if payload.notify_telegram:
        tg_result = send_telegram_alert(message)
        results.append(tg_result)
        if tg_result.get("sent"):
            print(f"[backoffice] Telegram alert sent: {payload.symbol} {payload.action}")
        else:
            print(f"[backoffice] Telegram FAILED: {tg_result.get('error')}")

    # ── Email ──
    if payload.notify_email and payload.email_to:
        em_result = send_email_alert(
            subject=f"Trade Alert: {payload.action} {payload.symbol} @ ${payload.price or 'N/A'}",
            body=email_body,
            to_email=payload.email_to,
        )
        results.append(em_result)

    return {
        "status": "dispatched",
        "symbol": payload.symbol,
        "action": payload.action,
        "notifications": results,
        "telegram_configured": bool(TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID),
        "email_configured": bool(SENDGRID_API_KEY),
    }


# ── Agent Registry (Health + Status) ──────────────

KNOWN_AGENTS = {
    "security_agent": {
        "type": "security",
        "description": "Scans target URLs for security vulnerabilities, missing headers, open ports",
        "endpoint": "security_agent",
        "phase": 1,
    },
    "tech_pulse_agent": {
        "type": "research",
        "description": "Daily tech research via Google CSE — GitHub, ArXiv, Medium innovations",
        "endpoint": "tech_pulse",
        "phase": 1,
    },
    "data_hunter_agent": {
        "type": "commodities",
        "description": "Tracks Gold, Silver, Oil, DXY — daily trading insights via DeepSeek",
        "endpoint": "data_hunter",
        "phase": 1,
    },
}


@app.get("/api/agents")
def list_agents():
    """List all registered agents in the swarm."""
    return {
        "agents": [
            {
                "agent_id": agent_id,
                "type": info["type"],
                "description": info["description"],
                "phase": info["phase"],
                "endpoint": f"/api/agent/{info['endpoint']}" if info.get("endpoint") else None,
            }
            for agent_id, info in KNOWN_AGENTS.items()
        ],
        "total": len(KNOWN_AGENTS),
        "phase": "Phase 1 — Foundation + Daily Intelligence",
    }


# ── Main ─────────────────────────────────────────────

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    print(f"🚀 Orchestrator starting on port {port}...")
    print(f"   Dashboard:       http://127.0.0.1:{port}/")
    print(f"   API Docs:        http://127.0.0.1:{port}/docs")
    print(f"   Direct Scan:     POST /api/scan/security")
    print(f"   Orchestrate:     POST /api/scan/orchestrate")
    print(f"   DeepSeek Agent:  POST /api/agent/deepseek")
    print(f"   Trade Alerts:    POST /api/backoffice/trade-alert")
    print(f"   Agent Registry:  GET  /api/agents")
    print(f"   Cloud Mode:      {IS_CLOUD}")
    uvicorn.run("orchestrator.main:app", host="0.0.0.0", port=port, reload=not IS_CLOUD)

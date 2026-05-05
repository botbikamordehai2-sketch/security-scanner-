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


# ── Main ─────────────────────────────────────────────

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    print(f"🚀 Orchestrator starting on port {port}...")
    print(f"   Dashboard:   http://127.0.0.1:{port}/")
    print(f"   API Docs:    http://127.0.0.1:{port}/docs")
    print(f"   Direct Scan: POST /api/scan/security")
    print(f"   Orchestrate: POST /api/scan/orchestrate")
    print(f"   Cloud Mode:  {IS_CLOUD}")
    uvicorn.run("orchestrator.main:app", host="0.0.0.0", port=port, reload=not IS_CLOUD)
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

# ── Prometheus Metrics (/metrics) ────────────────
try:
    from prometheus_fastapi_instrumentator import Instrumentator
    Instrumentator(
        should_group_status_codes=True,
        should_ignore_untemplated=True,
        should_respect_env_var=False,
        excluded_handlers=["/metrics"],
    ).instrument(app).expose(app, endpoint="/metrics")
except ImportError:
    pass

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
    telegram_channel: Optional[str] = "free"  # "free" | "vip" | "personal" | raw chat_id
    notify_email: bool = False
    email_to: Optional[str] = None


TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "")  # Default channel

# Channel routing map
TELEGRAM_CHANNELS = {
    "free":     os.environ.get("TELEGRAM_CHAT_FREE",     "-1003901040094"),
    "vip":      os.environ.get("TELEGRAM_CHAT_VIP",      "-1003984881621"),
    "personal": os.environ.get("TELEGRAM_CHAT_PERSONAL", "1246833993"),
}
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
        "",
        f"*Instrument:* `{payload.symbol}`",
    ]
    if payload.price:
        lines.append(f"*Price:* ${payload.price:,.2f}")
    if payload.stop_loss:
        lines.append(f"*Stop Loss:* ${payload.stop_loss:,.2f}")
    if payload.take_profit:
        lines.append(f"*Take Profit:* ${payload.take_profit:,.2f}")
    if payload.rationale:
        lines.append("")
        lines.append(f"*Analysis:* {payload.rationale}")
    if payload.agent_source:
        lines.append("")
        lines.append(f"🤖 _Source: {payload.agent_source}_")

    message = "\n".join(lines)
    email_body = message.replace("*", "").replace("`", "").replace("_", "")

    results = []

    # ── Telegram ──
    if payload.notify_telegram:
        chat_id = TELEGRAM_CHANNELS.get(payload.telegram_channel, payload.telegram_channel) \
                  if payload.telegram_channel else TELEGRAM_CHAT_ID
        tg_result = send_telegram_alert(message, chat_id=chat_id)
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


# ── GCP Security Audit (Phase 2) ──────────────────

class GcpScanPayload(BaseModel):
    project_id: str
    scan_types: Optional[List[str]] = None  # e.g. ["firewall", "storage", "iam", "sql", "gke"]
    output_format: Optional[str] = "json"  # json | html

GCP_AUDIT_AVAILABLE = False
try:
    from agents.security_agent.gcp_audit import (
        scan_firewall_rules,
        scan_storage_bucket,
        scan_project_iam,
        scan_sql_instances,
        scan_gke_clusters,
    )
    GCP_AUDIT_AVAILABLE = True
except ImportError:
    pass


@app.post("/api/scan/gcp")
def run_gcp_audit(payload: GcpScanPayload):
    """
    Run structured GCP security audit across 10 checks.
    Covers: Firewall, Storage, IAM, Cloud SQL, GKE.
    
    When GCP APIs are available (Cloud Run with SA), runs real scans.
    When running locally (no GCP credentials), returns a helpful stub
    showing which checks would have run.
    """
    if not GCP_AUDIT_AVAILABLE:
        raise HTTPException(
            status_code=503,
            detail="GCP audit module not available. Ensure agents/security_agent/gcp_audit.py is importable."
        )

    project_id = payload.project_id.strip()
    if not project_id:
        raise HTTPException(status_code=400, detail="project_id is required")

    requested_scans = payload.scan_types or ["firewall", "storage", "iam", "sql", "gke"]
    all_findings: list = []
    scan_summary: dict = {}
    api_errors: list = []

    # Check if GCP APIs are actually available (not just the module)
    try:
        from google.cloud import compute_v1, storage, resourcemanager_v3, sql_v1, container_v1
        GCP_APIS_AVAILABLE = True
    except ImportError:
        GCP_APIS_AVAILABLE = False

    # ── Firewall ──
    if "firewall" in requested_scans:
        if GCP_APIS_AVAILABLE:
            try:
                client = compute_v1.FirewallsClient()
                rules = list(client.list(project=project_id))
                findings = scan_firewall_rules([r.__class__.to_dict(r) for r in rules])
                all_findings.extend(findings)
                scan_summary["firewall"] = {"rules_scanned": len(rules), "findings": len(findings)}
            except Exception as e:
                api_errors.append({"resource": "firewall", "error": str(e)})
                scan_summary["firewall"] = {"status": "error", "error": str(e)}
        else:
            scan_summary["firewall"] = {"status": "skipped", "reason": "GCP APIs not available locally"}

    # ── Storage ──
    if "storage" in requested_scans:
        if GCP_APIS_AVAILABLE:
            try:
                storage_client = storage.Client(project=project_id)
                buckets = list(storage_client.list_buckets())
                bucket_findings = []
                for bucket in buckets:
                    policy = bucket.get_iam_policy()
                    bucket_meta = {"name": bucket.name, "iamConfiguration": {"publicAccessPrevention": bucket.iam_configuration.public_access_prevention.value if bucket.iam_configuration else "unspecified"}}
                    bucket_findings.extend(scan_storage_bucket(bucket.name, policy, bucket_meta))
                all_findings.extend(bucket_findings)
                scan_summary["storage"] = {"buckets_scanned": len(buckets), "findings": len(bucket_findings)}
            except Exception as e:
                api_errors.append({"resource": "storage", "error": str(e)})
                scan_summary["storage"] = {"status": "error", "error": str(e)}
        else:
            scan_summary["storage"] = {"status": "skipped", "reason": "GCP APIs not available locally"}

    # ── IAM ──
    if "iam" in requested_scans:
        if GCP_APIS_AVAILABLE:
            try:
                rm_client = resourcemanager_v3.ProjectsClient()
                request = resourcemanager_v3.GetIamPolicyRequest(resource=f"projects/{project_id}")
                policy = rm_client.get_iam_policy(request=request)
                # Convert proto to dict
                policy_dict = {
                    "bindings": [
                        {"role": b.role, "members": list(b.members)}
                        for b in policy.bindings
                    ]
                }
                iam_findings = scan_project_iam(project_id, policy_dict)
                all_findings.extend(iam_findings)
                scan_summary["iam"] = {"bindings_scanned": len(policy.bindings), "findings": len(iam_findings)}
            except Exception as e:
                api_errors.append({"resource": "iam", "error": str(e)})
                scan_summary["iam"] = {"status": "error", "error": str(e)}
        else:
            scan_summary["iam"] = {"status": "skipped", "reason": "GCP APIs not available locally"}

    # ── Cloud SQL ──
    if "sql" in requested_scans:
        if GCP_APIS_AVAILABLE:
            try:
                sql_client = sql_v1.SqlInstancesServiceClient()
                parent = f"projects/{project_id}"
                instances = list(sql_client.list(project=project_id))
                sql_findings = scan_sql_instances([i.__class__.to_dict(i) for i in instances])
                all_findings.extend(sql_findings)
                scan_summary["sql"] = {"instances_scanned": len(instances), "findings": len(sql_findings)}
            except Exception as e:
                api_errors.append({"resource": "sql", "error": str(e)})
                scan_summary["sql"] = {"status": "error", "error": str(e)}
        else:
            scan_summary["sql"] = {"status": "skipped", "reason": "GCP APIs not available locally"}

    # ── GKE ──
    if "gke" in requested_scans:
        if GCP_APIS_AVAILABLE:
            try:
                gke_client = container_v1.ClusterManagerClient()
                parent = f"projects/{project_id}/locations/-"
                clusters = list(gke_client.list_clusters(parent=parent).clusters)
                gke_findings = scan_gke_clusters([c.__class__.to_dict(c) for c in clusters])
                all_findings.extend(gke_findings)
                scan_summary["gke"] = {"clusters_scanned": len(clusters), "findings": len(gke_findings)}
            except Exception as e:
                api_errors.append({"resource": "gke", "error": str(e)})
                scan_summary["gke"] = {"status": "error", "error": str(e)}
        else:
            scan_summary["gke"] = {"status": "skipped", "reason": "GCP APIs not available locally"}

    # ── Severity summary ──
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in all_findings:
        severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

    return {
        "project_id": project_id,
        "scan_summary": scan_summary,
        "total_findings": len(all_findings),
        "severity_counts": severity_counts,
        "findings": [
            {
                "resource_id": f.resource_id,
                "resource_type": f.resource_type,
                "severity": f.severity,
                "title": f.title,
                "description": f.description,
                "recommendation": f.recommendation,
            }
            for f in all_findings
        ],
        "api_errors": api_errors if api_errors else None,
        "gcp_apis_available": GCP_APIS_AVAILABLE,
        "checks_available": [
            "check_firewall_public_ssh",
            "check_storage_public_iam",
            "check_storage_public_prevention",
            "check_iam_overpermissive_sa",
            "check_iam_allauth_project",
            "check_sql_public_ip",
            "check_sql_no_backup",
            "check_gke_dashboard_enabled",
            "check_gke_legacy_auth",
            "check_gke_public_nodes",
        ],
    }


# ── AWS Security Audit ────────────────────────────

class AwsScanPayload(BaseModel):
    region: str = "us-east-1"
    scan_types: Optional[List[str]] = None  # ["s3", "iam", "ec2"]


AWS_AUDIT_AVAILABLE = False
try:
    from agents.security_agent.aws_audit import (
        scan_s3_bucket,
        check_iam_root_access_key,
        check_iam_root_mfa,
        check_iam_stale_access_key,
        scan_security_groups,
    )
    AWS_AUDIT_AVAILABLE = True
except ImportError:
    pass


@app.post("/api/scan/aws")
def run_aws_audit(payload: AwsScanPayload):
    """
    Run structured AWS security audit.
    Covers: S3 ACL/Encryption/Block, IAM credentials, Security Groups.
    Requires boto3 + AWS credentials (env vars or IAM role).
    """
    if not AWS_AUDIT_AVAILABLE:
        raise HTTPException(
            status_code=503,
            detail="AWS audit module not available.",
        )

    requested_scans = payload.scan_types or ["s3", "iam", "ec2"]
    all_findings: list = []
    scan_summary: dict = {}
    api_errors: list = []

    try:
        import boto3
        AWS_APIS_AVAILABLE = True
    except ImportError:
        AWS_APIS_AVAILABLE = False

    if not AWS_APIS_AVAILABLE:
        return {
            "region": payload.region,
            "total_findings": 0,
            "findings": [],
            "scan_summary": {t: {"status": "skipped", "reason": "boto3 not installed"} for t in requested_scans},
            "aws_apis_available": False,
        }

    # ── S3 ──
    if "s3" in requested_scans:
        try:
            s3 = boto3.client("s3", region_name=payload.region)
            buckets = s3.list_buckets().get("Buckets", [])
            bucket_findings = []
            for bucket in buckets:
                name = bucket["Name"]
                acl = s3.get_bucket_acl(Bucket=name)
                try:
                    block = s3.get_public_access_block(Bucket=name)
                except Exception:
                    block = {}
                try:
                    enc = s3.get_bucket_encryption(Bucket=name)
                except Exception:
                    enc = {}
                bucket_findings.extend(scan_s3_bucket(name, acl, block, enc))
            all_findings.extend(bucket_findings)
            scan_summary["s3"] = {"buckets_scanned": len(buckets), "findings": len(bucket_findings)}
        except Exception as e:
            api_errors.append({"resource": "s3", "error": str(e)})
            scan_summary["s3"] = {"status": "error", "error": str(e)}

    # ── IAM ──
    if "iam" in requested_scans:
        try:
            import csv
            import io
            import time as _time
            iam = boto3.client("iam", region_name=payload.region)
            iam.generate_credential_report()
            _time.sleep(2)
            report_csv = iam.get_credential_report()["Content"].decode("utf-8")
            reader = csv.DictReader(io.StringIO(report_csv))
            iam_findings = []
            for row in reader:
                for checker in [check_iam_root_access_key, check_iam_root_mfa]:
                    f = checker(row)
                    if f:
                        iam_findings.append(f)
            users = iam.list_users().get("Users", [])
            for user in users:
                keys = iam.list_access_keys(UserName=user["UserName"]).get("AccessKeyMetadata", [])
                for key in keys:
                    f = check_iam_stale_access_key(user["UserName"], key)
                    if f:
                        iam_findings.append(f)
            all_findings.extend(iam_findings)
            scan_summary["iam"] = {"users_scanned": len(users), "findings": len(iam_findings)}
        except Exception as e:
            api_errors.append({"resource": "iam", "error": str(e)})
            scan_summary["iam"] = {"status": "error", "error": str(e)}

    # ── EC2 Security Groups ──
    if "ec2" in requested_scans:
        try:
            ec2 = boto3.client("ec2", region_name=payload.region)
            paginator = ec2.get_paginator("describe_security_groups")
            groups = [sg for page in paginator.paginate() for sg in page["SecurityGroups"]]
            sg_findings = scan_security_groups(groups)
            all_findings.extend(sg_findings)
            scan_summary["ec2"] = {"security_groups_scanned": len(groups), "findings": len(sg_findings)}
        except Exception as e:
            api_errors.append({"resource": "ec2", "error": str(e)})
            scan_summary["ec2"] = {"status": "error", "error": str(e)}

    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in all_findings:
        severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    all_findings.sort(key=lambda f: severity_order.get(f.severity, 9))

    return {
        "provider": "aws",
        "region": payload.region,
        "total_findings": len(all_findings),
        "severity_counts": severity_counts,
        "scan_summary": scan_summary,
        "findings": [
            {
                "resource_id": f.resource_id,
                "resource_type": f.resource_type,
                "severity": f.severity,
                "title": f.title,
                "description": f.description,
                "recommendation": f.recommendation,
            }
            for f in all_findings
        ],
        "api_errors": api_errors if api_errors else None,
        "aws_apis_available": AWS_APIS_AVAILABLE,
    }


# ── OSINT Impact Scoring (causal_osint) ───────────

OSINT_AVAILABLE = False
try:
    from agents.causal_osint.cvss_epss import assess_vulnerability, scan_cve_batch, CvssVector
    OSINT_AVAILABLE = True
except ImportError:
    pass


class CvePayload(BaseModel):
    cve_id: str
    description: str
    cvss_vector: Optional[str] = None
    has_poc: bool = False
    in_cisa_kev: bool = False
    days_since_published: float = 30.0
    exploit_maturity: str = "unproven"


class CveBatchPayload(BaseModel):
    cves: List[Dict[str, Any]]


@app.post("/api/osint/impact/score")
def osint_impact_score(payload: CvePayload):
    """
    CVSS v3.1 + EPSS impact scoring for a single CVE.
    If cvss_vector is omitted, AgenticVM predicts it from the description.
    Returns: base_score, severity, EPSS probability, priority level, recommendation.
    """
    if not OSINT_AVAILABLE:
        raise HTTPException(status_code=503, detail="causal_osint module not available")

    cvss = None
    if payload.cvss_vector:
        cvss = CvssVector.from_string(payload.cvss_vector)

    assessment = assess_vulnerability(
        cve_id=payload.cve_id,
        description=payload.description,
        cvss=cvss,
        has_poc=payload.has_poc,
        in_cisa_kev=payload.in_cisa_kev,
        days_since_published=payload.days_since_published,
        exploit_maturity=payload.exploit_maturity,
    )

    return {
        "cve_id": assessment.cve_id,
        "cvss_vector": assessment.cvss_vector.to_string(),
        "cvss_base_score": assessment.cvss_base_score,
        "cvss_severity": assessment.cvss_severity,
        "epss_score": assessment.epss_score,
        "epss_percentile": assessment.epss_percentile,
        "priority": assessment.priority.value,
        "recommendation": assessment.recommendation(),
        "has_poc": assessment.has_poc,
        "in_cisa_kev": assessment.in_cisa_kev,
        "predicted_fields": assessment.predicted_fields,
    }


@app.post("/api/osint/impact/batch")
def osint_impact_batch(payload: CveBatchPayload):
    """
    CVSS + EPSS batch scoring — assess multiple CVEs, sorted by priority (P1 first).
    """
    if not OSINT_AVAILABLE:
        raise HTTPException(status_code=503, detail="causal_osint module not available")

    if not payload.cves:
        raise HTTPException(status_code=400, detail="cves list is required")

    results = scan_cve_batch(payload.cves)

    return {
        "total": len(results),
        "assessments": [
            {
                "cve_id": a.cve_id,
                "cvss_base_score": a.cvss_base_score,
                "cvss_severity": a.cvss_severity,
                "epss_score": a.epss_score,
                "priority": a.priority.value,
                "recommendation": a.recommendation(),
            }
            for a in results
        ],
    }


# ── Execution Journal API ─────────────────────────

try:
    from shared.journal import ExecutionJournal as _Journal
    _global_journal = _Journal()
    JOURNAL_AVAILABLE = True
except ImportError:
    JOURNAL_AVAILABLE = False


@app.get("/api/journal")
def get_journal(n: int = 50):
    """Return the last N execution journal entries."""
    if not JOURNAL_AVAILABLE:
        raise HTTPException(status_code=503, detail="Journal not available")
    return {"entries": _global_journal.recent(n)}


@app.get("/api/journal/stats")
def get_journal_stats():
    """Return aggregated execution stats: cost, success rate, providers."""
    if not JOURNAL_AVAILABLE:
        raise HTTPException(status_code=503, detail="Journal not available")
    return _global_journal.stats()


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
    "causal_osint_agent": {
        "type": "intelligence",
        "description": "Tier 1 Causal OSINT — SCM do-calculus, SemDeDup dedup, Bayesian reputation, CVSS/EPSS scoring, PurifyGen adversarial defense",
        "endpoint": "causal_osint",
        "phase": 2,
        "port": 8080,
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


# ── Causal OSINT Agent Proxy (Phase 2 — Tier 1) ────

CAUSAL_OSINT_HOST = os.environ.get("CAUSAL_OSINT_HOST", "http://127.0.0.1:8080")


def _proxy_to_causal_osint(path: str, body: dict = None) -> dict:
    """Forward a request to the Causal OSINT agent and return its response."""
    url = f"{CAUSAL_OSINT_HOST}{path}"
    try:
        if body is not None:
            resp = requests.post(url, json=body, timeout=60)
        else:
            resp = requests.get(url, timeout=10)
        if resp.status_code >= 400:
            raise HTTPException(status_code=resp.status_code, detail=resp.text)
        return resp.json()
    except requests.exceptions.ConnectionError:
        raise HTTPException(
            status_code=503,
            detail=f"Causal OSINT agent not reachable at {CAUSAL_OSINT_HOST}. Start it with: python agents/causal_osint/agent.py",
        )
    except requests.exceptions.Timeout:
        raise HTTPException(status_code=504, detail="Causal OSINT agent timed out")


@app.get("/api/agent/causal-osint/health")
def causal_osint_health():
    """Proxy: health check for the Causal OSINT Tier 1 agent."""
    return _proxy_to_causal_osint("/api/osint/health")


@app.post("/api/agent/causal-osint/ingest")
def causal_osint_ingest(payload: Dict[str, Any]):
    """Proxy: ingest OSINT documents → SemDeDup + adversarial scoring."""
    return _proxy_to_causal_osint("/api/osint/ingest", body=payload)


@app.post("/api/agent/causal-osint/causal-query")
def causal_osint_causal_query(payload: Dict[str, Any]):
    """Proxy: do(X=x) intervention / counterfactual / ACE via SCM."""
    return _proxy_to_causal_osint("/api/osint/causal/query", body=payload)


@app.post("/api/agent/causal-osint/reputation")
def causal_osint_reputation(payload: Dict[str, Any]):
    """Proxy: Bayesian reputation update, RAGRank, indicator management."""
    return _proxy_to_causal_osint("/api/osint/reputation/score", body=payload)


@app.post("/api/agent/causal-osint/impact")
def causal_osint_impact(payload: Dict[str, Any]):
    """Proxy: CVSS + EPSS vulnerability assessment (AgenticVM)."""
    return _proxy_to_causal_osint("/api/osint/impact/score", body=payload)


@app.post("/api/agent/causal-osint/adversarial-check")
def causal_osint_adversarial_check(payload: Dict[str, Any]):
    """Proxy: PurifyGen adversarial detection + coordinated attack detection."""
    return _proxy_to_causal_osint("/api/osint/adversarial/check", body=payload)


# ── Main ─────────────────────────────────────────────

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    print(f"🚀 Orchestrator starting on port {port}...")
    print(f"   Dashboard:          http://127.0.0.1:{port}/")
    print(f"   API Docs:           http://127.0.0.1:{port}/docs")
    print("   Direct Scan:        POST /api/scan/security")
    print("   Orchestrate:        POST /api/scan/orchestrate")
    print("   DeepSeek Agent:     POST /api/agent/deepseek")
    print("   Causal OSINT:       POST /api/agent/causal-osint/*")
    print("   Trade Alerts:       POST /api/backoffice/trade-alert")
    print("   Agent Registry:     GET  /api/agents")
    print("   GCP Audit:          POST /api/scan/gcp")
    print("   AWS Audit:          POST /api/scan/aws")
    print("   OSINT Score:        POST /api/osint/impact/score")
    print("   OSINT Batch:        POST /api/osint/impact/batch")
    print(f"   Cloud Mode:         {IS_CLOUD}")
    uvicorn.run("orchestrator.main:app", host="0.0.0.0", port=port, reload=not IS_CLOUD)

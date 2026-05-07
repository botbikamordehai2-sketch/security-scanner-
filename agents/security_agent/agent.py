"""
Security Agent — Pub/Sub Push Handler.
Receives scan requests from Orchestrator via Pub/Sub, runs security scan, publishes results.

Deployed as: Cloud Run Private Service (no external access)
Triggered by: Pub/Sub Push Subscription on "scan.requests" topic
Outputs to:   Pub/Sub Topic "scan.results"

Local dev:    python agent.py → starts Flask on :8080, ready for Pub/Sub push
"""

import base64
import json
import os
import socket
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

# ── Add project root to path so shared/ imports work ──
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import requests
from flask import Flask, request, jsonify

from shared.db import get_db
from shared.events import ScanRequest, ScanResult, ScanResponseV1, VulnerabilityItem
from shared.pubsub_utils import publish_message, IS_CLOUD
from gcp_audit import scan_firewall_rules, scan_storage_bucket, scan_project_iam, scan_sql_instances, scan_gke_clusters
from shared.circuit_breaker import get_breaker, CircuitOpenError

app = Flask(__name__)
PORT = int(os.environ.get("PORT", 8080))

# ── Scan Engine (same logic as orchestrator) ─────────────

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


def run_security_scan(target_url: str) -> dict:
    """
    Run the full security scan against a target URL.
    Returns a dict that maps to ScanResponseV1.
    """
    if not target_url.startswith("http://") and not target_url.startswith("https://"):
        target_url = "https://" + target_url

    parsed_url = urlparse(target_url)
    hostname = parsed_url.hostname

    if not hostname:
        raise ValueError(f"Invalid URL: {target_url}")

    is_https = parsed_url.scheme == "https"

    # ── Port check ──
    open_ports = []
    for port in [80, 443]:
        if check_port(hostname, port):
            open_ports.append(port)

    # ── HTTP GET ──
    try:
        response = requests.get(
            target_url,
            timeout=10,
            allow_redirects=True,
            headers={"User-Agent": "AgenticSecurityScanner/2.0 (SecurityAgent)"}
        )
        final_url = str(response.url)
        status_code = response.status_code
        headers = response.headers
    except requests.exceptions.Timeout:
        raise RuntimeError(f"Request timed out for {target_url}")
    except requests.exceptions.ConnectionError:
        raise RuntimeError(f"DNS/CONNECTION failed for {target_url}")
    except Exception as e:
        raise RuntimeError(f"Scan error: {str(e)}")

    # ── Inspect security headers ──
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
                "description": f"{header} header is missing.",
                "remediation": f"Add the {header} header."
            })
            vulnerabilities.append({
                "header": header,
                "severity": info["severity"],
                "description": info["description"],
                "remediation": info["remediation"],
            })

    for header, info in EXTRA_HEADERS.items():
        if header not in headers:
            vulnerabilities.append({
                "header": header,
                "severity": info["severity"],
                "description": info["description"],
                "remediation": info["remediation"],
            })

    # ── Score ──
    score_deductions = {"HIGH": 25, "MEDIUM": 15, "LOW": 5}
    security_score = 100
    for v in vulnerabilities:
        security_score -= score_deductions.get(v["severity"], 5)
    security_score = max(0, security_score)

    # ── Response headers ──
    interesting_headers = {}
    for key in ["Server", "X-Powered-By", "Content-Type", "Cache-Control", "Set-Cookie", "Location"]:
        if key in headers:
            interesting_headers[key] = headers[key]

    return {
        "target_url": target_url,
        "final_url": final_url,
        "is_https": is_https,
        "status_code": status_code,
        "open_ports": open_ports,
        "missing_headers": missing_headers,
        "vulnerabilities": vulnerabilities,
        "security_score": security_score,
        "scan_status": "completed",
        "response_headers": interesting_headers,
    }


# ── GCP Resource Scanner ─────────────────────────────

def run_gcp_scan(project_id: str) -> dict:
    """
    Fetch live GCP resources and run structured security checks.
    Requires ADC or GOOGLE_APPLICATION_CREDENTIALS with:
      - compute.firewalls.list
      - storage.buckets.list + storage.buckets.getIamPolicy
      - sqladmin.instances.list
      - container.clusters.list
      - resourcemanager.projects.getIamPolicy
    """
    from google.cloud import compute_v1, storage, container_v1
    from googleapiclient.discovery import build as gcp_build

    findings = []

    # ── Firewall rules ──
    try:
        with get_breaker("gcp-firewall"):
            firewall_client = compute_v1.FirewallsClient()
            rules = [dict(r) for r in firewall_client.list(project=project_id)]
            findings.extend(scan_firewall_rules(rules))
    except CircuitOpenError as e:
        print(f"[gcp_scan] SKIP firewall — circuit open: {e}")
    except Exception as e:
        print(f"[gcp_scan] WARN firewall: {e}")

    # ── Storage buckets ──
    try:
        with get_breaker("gcp-storage"):
            storage_client = storage.Client(project=project_id)
            for bucket in storage_client.list_buckets():
                policy = storage_client.get_bucket(bucket.name).get_iam_policy(requested_policy_version=3)
                policy_dict = {
                    "bindings": [{"role": b.role, "members": list(b.members)} for b in policy.bindings]
                }
                meta_dict = {"iamConfiguration": {"publicAccessPrevention": getattr(bucket, "public_access_prevention", "unspecified")}}
                findings.extend(scan_storage_bucket(bucket.name, policy_dict, meta_dict))
    except CircuitOpenError as e:
        print(f"[gcp_scan] SKIP storage — circuit open: {e}")
    except Exception as e:
        print(f"[gcp_scan] WARN storage: {e}")

    # ── Project IAM ──
    try:
        with get_breaker("gcp-iam"):
            from google.cloud import resourcemanager_v3
            rm_client = resourcemanager_v3.ProjectsClient()
            iam_policy = rm_client.get_iam_policy(request={"resource": f"projects/{project_id}"})
            iam_policy_dict = {
                "bindings": [{"role": b.role, "members": list(b.members)} for b in iam_policy.bindings]
            }
            findings.extend(scan_project_iam(project_id, iam_policy_dict))
    except CircuitOpenError as e:
        print(f"[gcp_scan] SKIP iam — circuit open: {e}")
    except Exception as e:
        print(f"[gcp_scan] WARN iam: {e}")

    # ── Cloud SQL ──
    try:
        with get_breaker("gcp-sql"):
            sql_service = gcp_build("sqladmin", "v1", cache_discovery=False)
            sql_resp = sql_service.instances().list(project=project_id).execute()
            findings.extend(scan_sql_instances(sql_resp.get("items", [])))
    except CircuitOpenError as e:
        print(f"[gcp_scan] SKIP sql — circuit open: {e}")
    except Exception as e:
        print(f"[gcp_scan] WARN sql: {e}")

    # ── GKE clusters ──
    try:
        with get_breaker("gcp-gke"):
            gke_client = container_v1.ClusterManagerClient()
            gke_resp = gke_client.list_clusters(parent=f"projects/{project_id}/locations/-")
            clusters = [type(c).to_dict(c) for c in gke_resp.clusters]
            findings.extend(scan_gke_clusters(clusters))
    except CircuitOpenError as e:
        print(f"[gcp_scan] SKIP gke — circuit open: {e}")
    except Exception as e:
        print(f"[gcp_scan] WARN gke: {e}")

    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    findings.sort(key=lambda f: severity_order.get(f.severity, 9))

    return {
        "project_id": project_id,
        "scan_type": "gcp",
        "findings_count": len(findings),
        "findings": [
            {
                "resource_id": f.resource_id,
                "resource_type": f.resource_type,
                "severity": f.severity,
                "title": f.title,
                "description": f.description,
                "recommendation": f.recommendation,
            }
            for f in findings
        ],
    }


# ── Pub/Sub Push Handler ──────────────────────────────

def validate_pubsub_request(envelope: dict) -> dict | None:
    """
    Extract and decode the Pub/Sub message payload.
    Returns the decoded JSON dict, or None if invalid.
    """
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
    """Handle incoming Pub/Sub push messages."""
    envelope = request.get_json(force=True, silent=True) or {}

    # Parse the Pub/Sub message
    payload = validate_pubsub_request(envelope)
    if payload is None:
        print("[agent] Invalid or empty Pub/Sub message — acking")
        return ("", 204)

    request_id = payload.get("request_id", "")
    target_url = payload.get("target_url", "")
    print(f"[agent] Received scan request {request_id} for {target_url}")

    # ── Idempotency check ──
    db = get_db()
    if db.request_exists(request_id):
        print(f"[agent] Duplicate request {request_id} — skipping")
        return ("", 204)

    db.mark_request_started(request_id, target_url)

    # ── Run scan ──
    options = payload.get("options", {})
    scan_type = options.get("scan_type", "http")
    start_time = time.time()
    try:
        if scan_type == "gcp":
            project_id = options.get("project_id", os.environ.get("GCP_PROJECT", ""))
            if not project_id:
                raise ValueError("options.project_id or GCP_PROJECT env var required for GCP scan")
            scan_data = run_gcp_scan(project_id)
        else:
            scan_data = run_security_scan(target_url)
        status = "success"
        error_code = None
        error_message = None
    except ValueError as e:
        scan_data = {}
        status = "error"
        error_code = "INVALID_URL"
        error_message = str(e)
    except RuntimeError as e:
        scan_data = {}
        status = "error"
        error_code = "SCAN_FAILED"
        error_message = str(e)
    except Exception as e:
        scan_data = {}
        status = "error"
        error_code = "INTERNAL_ERROR"
        error_message = str(e)

    duration_ms = int((time.time() - start_time) * 1000)

    # ── Build ScanResult ──
    result = ScanResult(
        request_id=request_id,
        agent_type="security_agent",
        status=status,
        data=scan_data,
        error_code=error_code,
        error_message=error_message,
        metrics={
            "duration_ms": duration_ms,
            "target": target_url,
            "findings_count": len(scan_data.get("vulnerabilities", [])),
            "security_score": scan_data.get("security_score", 0),
        },
    )

    # ── Save to DB ──
    db.save_agent_result(request_id, "security_agent", result.model_dump())

    # ── Publish to scan.results ──
    result_json = result.model_dump_json()
    msg_id = publish_message("scan.results", result_json, ordering_key=request_id)
    print(f"[agent] Published scan result for {request_id} — msg_id: {msg_id}")

    return ("", 204)


# ── Health Check ──────────────────────────────────────

@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "healthy",
        "agent": "security_agent",
        "version": "2.0.0",
        "cloud": IS_CLOUD,
    })


# ── Main ──────────────────────────────────────────────

if __name__ == "__main__":
    print(f"🛡️  Security Agent starting on port {PORT}...")
    print(f"   Health: http://127.0.0.1:{PORT}/health")
    print(f"   Cloud:  {IS_CLOUD}")
    app.run(host="0.0.0.0", port=PORT, debug=not IS_CLOUD)
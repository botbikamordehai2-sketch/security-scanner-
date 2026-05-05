import os
import socket
import requests
import uvicorn
from pathlib import Path
from urllib.parse import urlparse
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from typing import List, Optional

# 1. Initialize FastAPI app
app = FastAPI(title="Agentic Security Scanner", version="1.0.0")

# ── Serve Dashboard on root ───────────────────────────────
TEMPLATE_DIR = Path(__file__).parent / "templates"
DASHBOARD_PATH = TEMPLATE_DIR / "dashboard.html"

@app.get("/", response_class=HTMLResponse)
def serve_dashboard():
    """Serve the Security Scanner Dashboard as the landing page."""
    if DASHBOARD_PATH.exists():
        return DASHBOARD_PATH.read_text(encoding="utf-8")
    return HTMLResponse(content="<h1>Dashboard not found</h1>", status_code=404)

# 2. Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 3. Pydantic Models
class ScanRequest(BaseModel):
    target_url: str

class VulnerabilityItem(BaseModel):
    header: str
    severity: str  # HIGH, MEDIUM, LOW
    description: str
    remediation: str

class ScanResponse(BaseModel):
    target_url: str
    final_url: str
    is_https: bool
    status_code: int
    open_ports: List[int]
    missing_headers: List[str]
    vulnerabilities: List[VulnerabilityItem]
    security_score: int
    scan_status: str
    response_headers: dict = {}

# ── Severity mapping for headers (OWASP guidelines) ──────
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

# Additional security headers to look for
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

# 4. Health check endpoint
@app.get("/api/health")
def health_check():
    return {"status": "ok", "service": "agentic-security-scanner"}

# 5. Helper: check open port
def check_port(host: str, port: int, timeout: int = 2) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError, socket.gaierror, OSError):
        return False

# 6. Security Scan Endpoint
@app.post("/api/scan/security", response_model=ScanResponse)
def run_security_scan(payload: ScanRequest):
    url = payload.target_url.strip()

    # Normalize URL — add https:// if missing
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url

    parsed_url = urlparse(url)
    hostname = parsed_url.hostname

    if not hostname:
        raise HTTPException(status_code=400, detail="Invalid URL provided. Could not extract hostname.")

    is_https = parsed_url.scheme == "https"

    # ── Check open ports 80 & 443 ──
    open_ports = []
    for port in [80, 443]:
        if check_port(hostname, port):
            open_ports.append(port)

    # ── HTTP GET for headers and resolution ──
    try:
        response = requests.get(
            url,
            timeout=10,
            allow_redirects=True,
            headers={"User-Agent": "AgenticSecurityScanner/1.0"}
        )
        final_url = response.url
        status_code = response.status_code
        headers = response.headers
    except requests.exceptions.Timeout:
        raise HTTPException(status_code=504, detail="Request timed out. Target might be down or blocked.")
    except requests.exceptions.ConnectionError:
        raise HTTPException(status_code=502, detail="Failed to connect or resolve DNS for the target.")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal scanning error: {str(e)}")

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
            # HSTS only applies to HTTPS
            if header == "Strict-Transport-Security" and not is_https:
                continue
            missing_headers.append(header)
            info = HEADER_SEVERITY.get(header, {
                "severity": "LOW",
                "description": f"{header} header is missing.",
                "remediation": f"Add the {header} header."
            })
            vulnerabilities.append(VulnerabilityItem(
                header=header,
                severity=info["severity"],
                description=info["description"],
                remediation=info["remediation"],
            ))

    # ── Check extra headers ──
    for header, info in EXTRA_HEADERS.items():
        if header not in headers:
            vulnerabilities.append(VulnerabilityItem(
                header=header,
                severity=info["severity"],
                description=info["description"],
                remediation=info["remediation"],
            ))

    # ── Calculate security score ──
    # Base 100, subtract points per vulnerability based on severity
    score_deductions = {"HIGH": 25, "MEDIUM": 15, "LOW": 5}
    security_score = 100
    for v in vulnerabilities:
        security_score -= score_deductions.get(v.severity, 5)
    security_score = max(0, security_score)

    # ── Collect interesting response headers for display ──
    interesting_headers = {}
    for key in ["Server", "X-Powered-By", "Content-Type", "Cache-Control", "Set-Cookie", "Location"]:
        if key in headers:
            interesting_headers[key] = headers[key]

    return ScanResponse(
        target_url=url,
        final_url=str(final_url),
        is_https=is_https,
        status_code=status_code,
        open_ports=open_ports,
        missing_headers=missing_headers,
        vulnerabilities=vulnerabilities,
        security_score=security_score,
        scan_status="completed",
        response_headers=interesting_headers,
    )

# 7. Main block for execution
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    print(f"🚀 Starting Agentic Security Scanner on port {port}...")
    print(f"   Dashboard: http://127.0.0.1:{port}/")
    print(f"   API Docs:  http://127.0.0.1:{port}/docs")
    uvicorn.run("backend_core:app", host="0.0.0.0", port=port, reload=True)
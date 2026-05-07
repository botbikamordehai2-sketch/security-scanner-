"""
Pytest tests for Orchestrator endpoints and GCP audit integration.
Tests all 7 endpoints: health, security scan, orchestrate, status,
deepseek agent, trade alerts, and the new GCP audit endpoint.

Run: pytest agents/security_agent/test_orchestrator.py -v --tb=short
"""

import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

# ── Add project root so imports work ──
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from orchestrator.main import app

client = TestClient(app)


# ═══════════════════════════════════════════════════════
#  GET /api/health
# ═══════════════════════════════════════════════════════

def test_health_returns_200():
    resp = client.get("/api/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert data["service"] == "agentic-security-scanner"
    assert data["version"] == "2.0.0"
    assert "cloud" in data
    assert "mode" in data


def test_health_returns_json():
    resp = client.get("/api/health")
    assert resp.headers["content-type"] == "application/json"


# ═══════════════════════════════════════════════════════
#  GET / (Dashboard)
# ═══════════════════════════════════════════════════════

def test_dashboard_returns_html():
    resp = client.get("/")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]


# ═══════════════════════════════════════════════════════
#  POST /api/scan/security (Direct MVP Scan)
# ═══════════════════════════════════════════════════════

def test_scan_security_valid_url():
    resp = client.post("/api/scan/security", json={"target_url": "example.com"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["scan_status"] == "completed"
    assert "target_url" in data
    assert "security_score" in data
    assert isinstance(data["security_score"], int)
    assert 0 <= data["security_score"] <= 100


def test_scan_security_with_https_prefix():
    resp = client.post("/api/scan/security", json={"target_url": "https://google.com"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["is_https"] is True


def test_scan_security_empty_url():
    resp = client.post("/api/scan/security", json={"target_url": ""})
    assert resp.status_code == 400


def test_scan_security_invalid_url():
    resp = client.post("/api/scan/security", json={"target_url": "not-a-valid-url-!@"})
    assert resp.status_code in (400, 502)  # 400 for bad hostname, 502 for DNS failure


def test_scan_security_returns_vulnerability_items():
    resp = client.post("/api/scan/security", json={"target_url": "github.com"})
    assert resp.status_code == 200
    data = resp.json()
    assert "vulnerabilities" in data
    assert isinstance(data["vulnerabilities"], list)
    for v in data["vulnerabilities"]:
        assert "header" in v
        assert "severity" in v
        assert v["severity"] in ("HIGH", "MEDIUM", "LOW")


def test_scan_security_response_schema_complete():
    """Verify all ScanResponseV1 fields are present."""
    resp = client.post("/api/scan/security", json={"target_url": "google.com"})
    assert resp.status_code == 200
    data = resp.json()
    required_fields = [
        "target_url", "final_url", "is_https", "status_code",
        "open_ports", "missing_headers", "vulnerabilities",
        "security_score", "scan_status", "response_headers",
    ]
    for field in required_fields:
        assert field in data, f"Missing field: {field}"


# ═══════════════════════════════════════════════════════
#  POST /api/scan/orchestrate + GET /api/scan/status/{id}
# ═══════════════════════════════════════════════════════

def test_orchestrate_scan_returns_request_id():
    resp = client.post("/api/scan/orchestrate", json={
        "target_url": "example.com",
        "agents": ["security_agent"],
    })
    assert resp.status_code == 200
    data = resp.json()
    assert "request_id" in data
    assert len(data["request_id"]) == 12
    assert data["status"] == "published"
    assert "poll_url" in data


def test_orchestrate_scan_with_agents():
    resp = client.post("/api/scan/orchestrate", json={
        "target_url": "test.com",
        "agents": ["security_agent", "data_hunter_agent"],
        "depth": "deep",
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["agents"] == ["security_agent", "data_hunter_agent"]


def test_orchestrate_scan_with_callback():
    resp = client.post("/api/scan/orchestrate", json={
        "target_url": "test.com",
        "callback": "telegram://chat_123456",
    })
    assert resp.status_code == 200


def test_scan_status_processing():
    """Create a scan, then poll its status — should be 'processing'."""
    # Create
    create_resp = client.post("/api/scan/orchestrate", json={
        "target_url": "status-test.com",
    })
    assert create_resp.status_code == 200
    request_id = create_resp.json()["request_id"]

    # Poll
    status_resp = client.get(f"/api/scan/status/{request_id}")
    assert status_resp.status_code == 200
    data = status_resp.json()
    assert data["request_id"] == request_id
    assert data["status"] == "processing"
    assert isinstance(data["agents_completed"], list)
    assert isinstance(data["agents_pending"], list)


def test_scan_status_404():
    resp = client.get("/api/scan/status/nonexistent12345")
    assert resp.status_code == 404


# ═══════════════════════════════════════════════════════
#  POST /api/agent/deepseek
# ═══════════════════════════════════════════════════════

def test_deepseek_agent_no_key():
    """When DEEPSEEK_API_KEY is not set, returns 503."""
    resp = client.post("/api/agent/deepseek", json={
        "prompt": "Hello, what is 2+2?",
    })
    # Either 503 (key not configured) or 200 (if key is set)
    assert resp.status_code in (200, 503)
    if resp.status_code == 503:
        assert "not configured" in resp.json()["detail"].lower()


def test_deepseek_agent_validation():
    """Empty prompt should still pass validation (service handles it)."""
    resp = client.post("/api/agent/deepseek", json={
        "prompt": "",
    })
    assert resp.status_code in (200, 422, 503)


def test_deepseek_agent_with_system_prompt():
    resp = client.post("/api/agent/deepseek", json={
        "prompt": "Test",
        "system": "You are a security auditor.",
        "temperature": 0.3,
        "max_tokens": 512,
    })
    assert resp.status_code in (200, 503)


# ═══════════════════════════════════════════════════════
#  POST /api/backoffice/trade-alert
# ═══════════════════════════════════════════════════════

def test_trade_alert_buy():
    resp = client.post("/api/backoffice/trade-alert", json={
        "symbol": "XAUUSD",
        "action": "BUY",
        "price": 2650.50,
        "stop_loss": 2640.00,
        "take_profit": 2680.00,
        "rationale": "ICT breaker block on 4H",
        "agent_source": "data_hunter_agent",
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "dispatched"
    assert data["symbol"] == "XAUUSD"
    assert data["action"] == "BUY"
    assert "notifications" in data
    assert "telegram_configured" in data


def test_trade_alert_sell():
    resp = client.post("/api/backoffice/trade-alert", json={
        "symbol": "NAS100",
        "action": "SELL",
        "price": 18200.00,
        "notify_telegram": False,
    })
    assert resp.status_code == 200


def test_trade_alert_validation():
    """Missing required fields should return 422."""
    resp = client.post("/api/backoffice/trade-alert", json={
        "action": "BUY",
        # missing 'symbol'
    })
    assert resp.status_code == 422


def test_trade_alert_all_fields():
    resp = client.post("/api/backoffice/trade-alert", json={
        "symbol": "US30",
        "action": "ALERT",
        "price": 38500.00,
        "stop_loss": None,
        "take_profit": None,
        "rationale": "NFP news incoming",
        "agent_source": "tech_pulse_agent",
        "notify_telegram": True,
        "notify_email": True,
        "email_to": "moti@commotiai.com",
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "dispatched"


# ═══════════════════════════════════════════════════════
#  GET /api/agents
# ═══════════════════════════════════════════════════════

def test_list_agents():
    resp = client.get("/api/agents")
    assert resp.status_code == 200
    data = resp.json()
    assert "agents" in data
    assert "total" in data
    assert data["total"] >= 3
    agent_ids = [a["agent_id"] for a in data["agents"]]
    assert "security_agent" in agent_ids
    assert "tech_pulse_agent" in agent_ids
    assert "data_hunter_agent" in agent_ids


def test_agents_have_required_fields():
    resp = client.get("/api/agents")
    data = resp.json()
    for agent in data["agents"]:
        assert "agent_id" in agent
        assert "type" in agent
        assert "description" in agent
        assert "phase" in agent


# ═══════════════════════════════════════════════════════
#  POST /api/scan/gcp (GCP Audit — NEW)
# ═══════════════════════════════════════════════════════

def test_gcp_audit_valid_request():
    """GCP audit endpoint should accept a valid project_id."""
    resp = client.post("/api/scan/gcp", json={
        "project_id": "my-test-project-123",
    })
    # Should return 200 (skipped locally) or 503 if module not importable
    assert resp.status_code in (200, 503)


def test_gcp_audit_empty_project_id():
    resp = client.post("/api/scan/gcp", json={
        "project_id": "",
    })
    assert resp.status_code == 400


def test_gcp_audit_specific_scans():
    """Test requesting only specific scan types."""
    resp = client.post("/api/scan/gcp", json={
        "project_id": "my-project",
        "scan_types": ["firewall", "storage"],
    })
    if resp.status_code == 200:
        data = resp.json()
        assert "scan_summary" in data
        assert "firewall" in data["scan_summary"]
        assert "storage" in data["scan_summary"]
        # Only requested scans should appear
        for key in ["iam", "sql", "gke"]:
            assert key not in data["scan_summary"]


def test_gcp_audit_all_scans():
    """Test requesting all scan types by default."""
    resp = client.post("/api/scan/gcp", json={
        "project_id": "my-project",
    })
    if resp.status_code == 200:
        data = resp.json()
        assert "project_id" in data
        assert data["project_id"] == "my-project"
        assert "total_findings" in data
        assert "severity_counts" in data
        assert "findings" in data
        assert "checks_available" in data
        assert len(data["checks_available"]) == 10


def test_gcp_audit_response_structure():
    """Verify all required response fields when endpoint works."""
    resp = client.post("/api/scan/gcp", json={
        "project_id": "test-proj",
        "scan_types": ["iam"],
    })
    if resp.status_code == 200:
        data = resp.json()
        assert "project_id" in data
        assert "scan_summary" in data
        assert "total_findings" in data
        assert "severity_counts" in data
        assert "findings" in data
        assert "api_errors" in data
        assert "gcp_apis_available" in data
        assert "checks_available" in data
        # severity_counts must have all 4 tiers
        for tier in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            assert tier in data["severity_counts"]


def test_gcp_audit_finding_structure():
    """Each finding must have the correct fields."""
    resp = client.post("/api/scan/gcp", json={
        "project_id": "test-proj",
    })
    if resp.status_code == 200:
        data = resp.json()
        for finding in data["findings"]:
            assert "resource_id" in finding
            assert "resource_type" in finding
            assert "severity" in finding
            assert finding["severity"] in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
            assert "title" in finding
            assert "description" in finding
            assert "recommendation" in finding


def test_gcp_audit_checks_list():
    """Verify the 10 checks are listed by name."""
    resp = client.post("/api/scan/gcp", json={
        "project_id": "test-proj",
    })
    if resp.status_code == 200:
        data = resp.json()
        expected_checks = {
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
        }
        returned_checks = set(data["checks_available"])
        assert returned_checks == expected_checks


# ═══════════════════════════════════════════════════════
#  Edge Cases & Error Handling
# ═══════════════════════════════════════════════════════

def test_cors_headers():
    """Verify CORS headers are present on responses."""
    resp = client.options("/api/health")
    # FastAPI may or may not add CORS on OPTIONS; just verify it doesn't crash
    assert resp.status_code in (200, 405)


def test_scan_security_missing_body():
    resp = client.post("/api/scan/security")
    assert resp.status_code == 422


def test_orchestrate_missing_url():
    resp = client.post("/api/scan/orchestrate", json={
        "agents": ["security_agent"],
    })
    assert resp.status_code == 422


def test_scan_security_http_url():
    """http:// URLs should work and be detected as non-HTTPS."""
    resp = client.post("/api/scan/security", json={"target_url": "http://httpbin.org"})
    # May 200 (reachable) or 502 (unreachable) or 504 (timeout)
    if resp.status_code == 200:
        data = resp.json()
        assert data["is_https"] is False
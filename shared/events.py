"""
Pydantic Event Schemas — Unified Contract for all Agents.
Every message in the Agentic Platform uses these schemas.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import uuid4

from pydantic import BaseModel, Field


# ──────────────────────────────────────────────
#  Phase 1: MVP Schemas (compatible with existing API)
# ──────────────────────────────────────────────

class VulnerabilityItem(BaseModel):
    header: str
    severity: str  # HIGH, MEDIUM, LOW
    description: str
    remediation: str


class ScanResponseV1(BaseModel):
    """Exact match for existing POST /api/scan/security response.
    Kept for backward compatibility — the Dashboard uses this.
    """
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


# ──────────────────────────────────────────────
#  Phase 2: Event-Driven Schemas (Pub/Sub native)
# ──────────────────────────────────────────────

def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class ScanRequest(BaseModel):
    """Published to scan.requests topic by Orchestrator."""
    request_id: str = Field(default_factory=lambda: uuid4().hex[:12])
    target_url: str
    agents_to_run: List[str] = ["security_agent"]
    depth: str = "standard"
    options: Dict[str, Any] = {}
    parent_request_id: Optional[str] = None
    created_at: str = Field(default_factory=utc_now_iso)


class ScanResult(BaseModel):
    """Published to scan.results topic by each Agent."""
    request_id: str
    agent_type: str
    status: str
    data: Dict[str, Any] = {}
    error_code: Optional[str] = None
    error_message: Optional[str] = None
    metrics: Dict[str, Any] = {}
    timestamp: str = Field(default_factory=utc_now_iso)


class AggregateResult(BaseModel):
    """Published to scan.aggregated after all agents report."""
    request_id: str
    target_url: str
    agents_ran: List[str]
    results: Dict[str, ScanResult]
    overall_score: int = 0
    total_findings: int = 0
    completed_at: str = Field(default_factory=utc_now_iso)


class SalesPitchRequest(BaseModel):
    """Published to sales.pitch.requests by Aggregator."""
    request_id: str
    target_url: str
    aggregate_result: Dict[str, Any]
    language: str = "he"


class SalesPitchResult(BaseModel):
    """Published to sales.pitch.completed by Sales Agent (DeepSeek)."""
    request_id: str
    pitch_text: str
    language: str = "he"
    timestamp: str = Field(default_factory=utc_now_iso)
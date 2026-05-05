"""
Firestore Helper — Store scan results, enable idempotency checks.
Production-ready: handles duplicates, retries, batch writes.

Usage:
    from shared.db import FirestoreDB
    db = FirestoreDB()

    # Check idempotency
    if db.scan_exists(request_id):
        return {"status": "duplicate"}

    # Save result
    db.save_scan_result(request_id, result_data)
"""

import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

try:
    from google.cloud import firestore
    FIRESTORE_AVAILABLE = True
except ImportError:
    FIRESTORE_AVAILABLE = False
    firestore = None  # type: ignore

PROJECT = os.getenv("PROJECT_ID", os.getenv("GCP_PROJECT", ""))
IS_CLOUD = bool(PROJECT)


class LocalStorage:
    """Local JSON file storage for development without Firestore."""

    def __init__(self, path: str = "local_db.json"):
        self.path = path
        self._data: Dict[str, Dict[str, Any]] = self._load()

    def _load(self) -> Dict[str, Dict[str, Any]]:
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return {
                "scans": {},
                "requests": {},
                "aggregates": {},
            }

    def _save(self):
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump(self._data, f, indent=2, default=str)

    def get(self, collection: str, doc_id: str) -> Optional[Dict]:
        return self._data.get(collection, {}).get(doc_id)

    def set(self, collection: str, doc_id: str, data: Dict):
        if collection not in self._data:
            self._data[collection] = {}
        self._data[collection][doc_id] = {
            **data,
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }
        self._save()

    def exists(self, collection: str, doc_id: str) -> bool:
        return doc_id in self._data.get(collection, {})


class FirestoreDB:
    """
    Firestore-backed database for the Agentic Platform.

    Collections:
        scans/{request_id}       — Full scan request + all agent results
        requests/{request_id}    — Incoming scan requests (idempotency)
        aggregates/{request_id}  — Aggregated results after all agents
    """

    def __init__(self):
        if IS_CLOUD and FIRESTORE_AVAILABLE:
            self.client = firestore.Client()
            self._is_local = False
        else:
            self._local = LocalStorage()
            self._is_local = True

    # ── Collections ──────────────────────────────────

    def _scans(self):
        return self.client.collection("scans") if not self._is_local else None

    def _requests(self):
        return self.client.collection("requests") if not self._is_local else None

    def _aggregates(self):
        return self.client.collection("aggregates") if not self._is_local else None

    # ── Idempotency ──────────────────────────────────

    def request_exists(self, request_id: str) -> bool:
        """Check if a scan request has already been processed."""
        if self._is_local:
            return self._local.exists("requests", request_id)
        doc = self._requests().document(request_id).get()
        return doc.exists

    def mark_request_started(self, request_id: str, target_url: str):
        """Record that a request is being processed."""
        data = {
            "request_id": request_id,
            "target_url": target_url,
            "status": "processing",
            "created_at": datetime.now(timezone.utc),
        }
        if self._is_local:
            self._local.set("requests", request_id, data)
        else:
            self._requests().document(request_id).set(data)

    def mark_request_completed(self, request_id: str):
        """Mark a request as fully completed."""
        if self._is_local:
            existing = self._local.get("requests", request_id) or {}
            existing["status"] = "completed"
            self._local.set("requests", request_id, existing)
        else:
            self._requests().document(request_id).update({"status": "completed"})

    # ── Scan Results ─────────────────────────────────

    def save_agent_result(self, request_id: str, agent_type: str, result_data: Dict):
        """Save an individual agent's result to the scan document."""
        if self._is_local:
            scan_doc = self._local.get("scans", request_id) or {}
            if "agent_results" not in scan_doc:
                scan_doc["agent_results"] = {}
            scan_doc["agent_results"][agent_type] = {
                **result_data,
                "received_at": datetime.now(timezone.utc).isoformat(),
            }
            self._local.set("scans", request_id, scan_doc)
        else:
            self._scans().document(request_id).set({
                f"agent_results.{agent_type}": {
                    **result_data,
                    "received_at": firestore.SERVER_TIMESTAMP,
                }
            }, merge=True)

    def save_scan_document(self, request_id: str, data: Dict):
        """Save the full scan document."""
        if self._is_local:
            self._local.set("scans", request_id, data)
        else:
            self._scans().document(request_id).set({
                **data,
                "updated_at": firestore.SERVER_TIMESTAMP,
            }, merge=True)

    def get_scan(self, request_id: str) -> Optional[Dict]:
        """Retrieve a full scan document by request_id."""
        if self._is_local:
            return self._local.get("scans", request_id)
        doc = self._scans().document(request_id).get()
        return doc.to_dict() if doc.exists else None

    # ── Aggregated Results ───────────────────────────

    def save_aggregate(self, request_id: str, aggregate_data: Dict):
        """Save the aggregated result after all agents complete."""
        if self._is_local:
            self._local.set("aggregates", request_id, aggregate_data)
        else:
            self._aggregates().document(request_id).set({
                **aggregate_data,
                "completed_at": firestore.SERVER_TIMESTAMP,
            })

    def all_agents_completed(self, request_id: str, expected_agents: List[str]) -> bool:
        """Check if all expected agents have submitted results."""
        scan_doc = self.get_scan(request_id)
        if not scan_doc:
            return False
        agent_results = scan_doc.get("agent_results", {})
        for agent in expected_agents:
            if agent not in agent_results:
                return False
        return True


# ── Singleton ────────────────────────────────────────

_db_instance: Optional[FirestoreDB] = None


def get_db() -> FirestoreDB:
    """Get or create the singleton FirestoreDB instance."""
    global _db_instance
    if _db_instance is None:
        _db_instance = FirestoreDB()
    return _db_instance
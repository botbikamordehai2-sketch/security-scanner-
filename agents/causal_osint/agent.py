"""
SignalForge-Commotai | Causal OSINT Tier 1 Agent — Flask API

Endpoints:
  POST /api/osint/ingest          — Raw OSINT → SemDeDup → store
  POST /api/osint/causal/query    — do(X=x) intervention via SCM
  POST /api/osint/reputation/score — Source reputation + Bayesian update
  POST /api/osint/impact/score    — CVSS + EPSS prioritization
  GET  /api/osint/health          — Agent health + circuit breakers

All calls go through the Unified ExecutionWrapper (A7.1):
  circuit_breaker per operation, retry with backoff, failover, journaling.

Usage:
  python agent.py
  # → http://127.0.0.1:8080
"""

from __future__ import annotations

import os
import sys
import time
import threading
from pathlib import Path
from typing import Optional
from flask import Flask, request, jsonify

# ── Ensure shared modules are importable ───────────────────────────────

_current_dir = Path(__file__).resolve().parent
_security_scanner_root = _current_dir.parent.parent  # security-scanner/
if str(_security_scanner_root) not in sys.path:
    sys.path.insert(0, str(_security_scanner_root))

from shared.execution_wrapper import execute_with_resilience
from shared.circuit_breaker import all_statuses as all_circuit_statuses

# ── Causal OSINT modules ──────────────────────────────────────────────

from agents.causal_osint.scm import StructuralCausalModel
from agents.causal_osint.semantic_dedup import (
    OSINTDocument,
    run_semdedup,
    extract_entities_gliner,
)
from agents.causal_osint.adversarial_defense import (
    score_adversarial,
    is_adversarial,
    detect_coordinated_attack,
)
from agents.causal_osint.reputation import (
    ReputationEngine,
    ReputationLoop,
    create_indicator,
)
from agents.causal_osint.cvss_epss import (
    assess_vulnerability,
    scan_cve_batch,
    CvssVector,
)

# ── Flask App ─────────────────────────────────────────────────────────

app = Flask(__name__)
app.config["JSON_SORT_KEYS"] = False

# ── Global state (singletons, thread-safe access) ─────────────────────

_scm: Optional[StructuralCausalModel] = None
_scm_lock = threading.Lock()

_reputation_engine: Optional[ReputationEngine] = None
_reputation_loop: Optional[ReputationLoop] = None
_reputation_lock = threading.Lock()

_agent_version = "1.0.0"
_agent_start_time = time.time()


def _get_scm() -> StructuralCausalModel:
    """Lazy-init SCM singleton."""
    global _scm
    if _scm is None:
        with _scm_lock:
            if _scm is None:
                _scm = StructuralCausalModel()
                _scm.reset()
    return _scm


def _get_reputation() -> tuple[ReputationEngine, ReputationLoop]:
    """Lazy-init reputation singleton."""
    global _reputation_engine, _reputation_loop
    if _reputation_engine is None:
        with _reputation_lock:
            if _reputation_engine is None:
                _reputation_engine = ReputationEngine()
                _reputation_loop = ReputationLoop(_reputation_engine)
    return _reputation_engine, _reputation_loop


# ── 1. Health ─────────────────────────────────────────────────────────

@app.route("/api/osint/health", methods=["GET"])
def health():
    """Agent health check + circuit breaker statuses."""

    def _health_check():
        breakers = all_circuit_statuses()
        return {
            "status": "healthy",
            "agent": "causal_osint_tier1",
            "version": _agent_version,
            "uptime_seconds": round(time.time() - _agent_start_time, 1),
            "modules": {
                "scm": "loaded",
                "semdedup": "loaded",
                "adversarial_defense": "loaded",
                "reputation": "loaded",
                "cvss_epss": "loaded",
            },
            "circuit_breakers": breakers,
            "scm_state": _get_scm().summary() if _scm else "not_initialized",
        }

    return jsonify(execute_with_resilience(
        provider="causal_osint",
        task="health",
        fn=_health_check,
        timeout=5.0,
        retries=1,
        agent="causal_osint",
        tools_used=["health"],
    ))


# ── 2. Ingest ─────────────────────────────────────────────────────────

@app.route("/api/osint/ingest", methods=["POST"])
def ingest():
    """
    Ingest raw OSINT documents → SemDeDup → adversarial scoring → store.

    Request body:
      {
        "documents": [
          {"id": "1", "text": "...", "source": "twitter", "timestamp": 1715000000},
          ...
        ],
        "options": {
          "min_cluster_size": 3,
          "similarity_threshold": 0.5,
          "adversarial_filter": true,
          "adversarial_threshold": 0.7,
          "run_gliner": false
        }
      }
    """
    body = request.get_json(force=True)
    docs_raw = body.get("documents", [])
    options = body.get("options", {})

    def _ingest():
        documents = [
            OSINTDocument(
                id=str(d.get("id", "")),
                text=str(d.get("text", "")),
                source=str(d.get("source", "unknown")),
                timestamp=float(d.get("timestamp", time.time())),
            )
            for d in docs_raw
        ]

        # Adversarial scoring on each document
        adversarial_flags = []
        clean_texts: list[str] = []
        for doc in documents:
            adv_score = score_adversarial(doc.text)
            doc.adversarial_score = adv_score
            adversarial_flags.append({
                "id": doc.id,
                "adversarial_score": adv_score,
                "is_adversarial": adv_score > options.get("adversarial_threshold", 0.7),
            })
            clean_texts.append(doc.text)

        # Coordinated attack detection
        coord_detection = detect_coordinated_attack(
            clean_texts,
            similarity_threshold=0.15,
            min_cluster_size=3,
        )

        # GLiNER NER (if enabled)
        if options.get("run_gliner", False):
            extract_entities_gliner(documents)

        # SemDeDup
        semdedup_result = run_semdedup(
            documents,
            min_cluster_size=options.get("min_cluster_size", 3),
            similarity_threshold=options.get("similarity_threshold", 0.5),
            adversarial_filter=options.get("adversarial_filter", True),
            adversarial_threshold=options.get("adversarial_threshold", 0.7),
        )

        return {
            "timing": {
                "total_input": semdedup_result.total_input,
                "clusters_found": semdedup_result.clusters_found,
                "noise_documents": semdedup_result.noise_documents,
                "canonical_outputs": len(semdedup_result.canonical_documents),
                "reduction_ratio": semdedup_result.reduction_ratio,
            },
            "clusters": [
                {
                    "cluster_id": c.cluster_id,
                    "size": c.size,
                    "cohesion": c.cohesion,
                    "canonical_id": c.canonical.id,
                    "canonical_text_preview": c.canonical.text[:200],
                }
                for c in semdedup_result.all_clusters
            ],
            "canonical_documents": [
                {
                    "id": d.id,
                    "text_preview": d.text[:200],
                    "source": d.source,
                    "entities": d.entities,
                    "is_canonical": d.is_canonical,
                }
                for d in semdedup_result.canonical_documents
            ],
            "adversarial_flags": adversarial_flags,
            "coordinated_attack": coord_detection,
        }

    result = execute_with_resilience(
        provider="causal_osint",
        task="ingest",
        fn=_ingest,
        timeout=60.0,
        retries=2,
        agent="causal_osint",
        tools_used=["semdedup", "adversarial_defense", "gliner"],
        cost_estimate=0.001 * len(docs_raw),
    )

    return jsonify({"status": "ok", "result": result})


# ── 3. Causal Query ───────────────────────────────────────────────────

@app.route("/api/osint/causal/query", methods=["POST"])
def causal_query():
    """
    Causal inference via SCM.

    Modes: 'do', 'counterfactual', 'ace', 'forward'

    do-intervention:
      {"mode": "do", "node": "Patch_Rate", "value": 0.9,
       "evidence": {"PoC_Published": 0.8, "CVE_Score": 8.5}, "steps": 5}

    counterfactual:
      {"mode": "counterfactual",
       "evidence": {"PoC_Published": 0.9, "CVE_Score": 8.5},
       "intervention": {"Patch_Rate": 0.9}, "steps": 5}

    ACE:
      {"mode": "ace", "cause": "CVE_Score", "effect": "Incident_Probability",
       "values": [3.0, 9.0], "steps": 5, "trials": 10}
    """
    body = request.get_json(force=True)
    mode = body.get("mode", "do")

    def _causal_query():
        scm = _get_scm()
        scm.reset()

        # Apply evidence
        evidence = body.get("evidence", {})
        if evidence:
            for k, v in evidence.items():
                try:
                    scm.set_node(k, float(v))
                except KeyError:
                    pass

        if mode == "do":
            node = str(body.get("node", ""))
            value = float(body.get("value", 0))
            steps = int(body.get("steps", 5))
            result = scm.do_intervention(node, value, steps=steps)

        elif mode == "counterfactual":
            ev = {str(k): float(v) for k, v in body.get("evidence", {}).items()}
            inter = body.get("intervention", {})
            steps = int(body.get("steps", 5))
            if inter:
                k0 = list(inter.keys())[0]
                result = scm.counterfactual(
                    evidence=ev,
                    intervention={str(k0): float(inter[k0])},
                    steps=steps,
                )
            else:
                return {"error": "intervention is required for counterfactual mode"}

        elif mode == "ace":
            cause = str(body.get("cause", ""))
            effect = str(body.get("effect", ""))
            values = [float(v) for v in body.get("values", [0, 1])]
            steps = int(body.get("steps", 5))
            trials = int(body.get("trials", 10))
            result = scm.estimate_causal_effect(cause, effect, values, steps=steps, trials=trials)

        elif mode == "forward":
            steps = int(body.get("steps", 5))
            trajectory = scm.forward(steps)
            result = {
                "trajectory": [{k: round(v, 4) for k, v in state.items()} for state in trajectory],
                "scm_summary": scm.summary(),
            }

        else:
            return {"error": f"Unknown mode: {mode}. Use 'do', 'counterfactual', 'ace', or 'forward'."}

        # Attach SCM summary
        if isinstance(result, dict):
            result["scm_summary"] = scm.summary()

        return result

    result = execute_with_resilience(
        provider="causal_osint",
        task="causal_query",
        fn=_causal_query,
        timeout=30.0,
        retries=2,
        agent="causal_osint",
        tools_used=["scm", "deepseek"],
        cost_estimate=0.002,
    )

    return jsonify({"mode": mode, "result": result})


# ── 4. Reputation Score ───────────────────────────────────────────────

@app.route("/api/osint/reputation/score", methods=["POST"])
def reputation_score():
    """
    Score source reputation — Bayesian update + RAGRank + Admiralty grade.

    Request body:
      {
        "mode": "assess",           // 'assess' | 'ragrank' | 'summary' | 'loop_tick'
        "source_id": "threat_intel_1",
        "source_type": "ThreatIntel",
        "confirmed": true,
        "confidence": 0.95,
        "evidence_description": "APT attribution verified by Mandiant"
      }
    """
    body = request.get_json(force=True)
    mode = body.get("mode", "assess")

    def _reputation_score():
        engine, loop = _get_reputation()

        if mode == "assess":
            source_id = str(body.get("source_id", ""))
            confirmed = bool(body.get("confirmed", True))
            confidence = float(body.get("confidence", 1.0))
            desc = str(body.get("evidence_description", ""))
            source_type = str(body.get("source_type", "unknown"))
            initial_cred = body.get("initial_credibility")

            # Ensure source exists
            engine.get_or_create_source(
                source_id,
                source_type=source_type,
                initial_credibility=float(initial_cred) if initial_cred is not None else None,
            )

            engine.assess_intelligence(
                source_id=source_id,
                confirmed=confirmed,
                confidence=confidence,
                evidence_description=desc,
            )
            return engine.source_summary(source_id)

        elif mode == "ragrank":
            source_id = str(body.get("source_id", ""))
            doc_citations = int(body.get("document_citations", 0))
            peer_refs = int(body.get("peer_references", 0))
            avg_quality = float(body.get("avg_document_quality", 0.5))
            score = engine.update_ragrank(
                source_id,
                document_citations=doc_citations,
                peer_references=peer_refs,
                avg_document_quality=avg_quality,
            )
            return {"source_id": source_id, "ragrank_credential_score": score}

        elif mode == "summary":
            source_id = str(body.get("source_id", ""))
            return engine.source_summary(source_id)

        elif mode == "loop_tick":
            return loop.tick()

        elif mode == "all_summaries":
            return {"sources": engine.all_sources_summary()}

        elif mode == "add_indicator":
            ind_type = str(body.get("indicator_type", "ip"))
            value = str(body.get("value", ""))
            source_id = str(body.get("source_id", "unknown"))
            trust = float(body.get("initial_trust", 1.0))
            context = str(body.get("context", ""))
            indicator = create_indicator(
                indicator_type=ind_type,
                value=value,
                initial_trust=trust,
                source_id=source_id,
                context=context,
            )
            engine.add_indicator(indicator)
            return {
                "indicator_added": {
                    "type": ind_type,
                    "value": value,
                    "trust_now": indicator.trust_at(),
                    "half_life_seconds": indicator.half_life(),
                }
            }

        elif mode == "active_indicators":
            threshold = float(body.get("trust_threshold", 0.1))
            active = engine.get_active_indicators(trust_threshold=threshold)
            return {
                "active_count": len(active),
                "indicators": [
                    {
                        "type": ind.indicator_type,
                        "value": ind.value,
                        "trust": round(ind.trust_at(), 4),
                        "half_life_hours": round(ind.half_life() / 3600, 1) if ind.half_life() < float("inf") else None,
                        "source": ind.source_id,
                    }
                    for ind in active
                ],
            }

        else:
            return {"error": f"Unknown mode: {mode}"}

    result = execute_with_resilience(
        provider="causal_osint",
        task="reputation_score",
        fn=_reputation_score,
        timeout=15.0,
        retries=2,
        agent="causal_osint",
        tools_used=["reputation"],
    )

    return jsonify({"mode": mode, "result": result})


# ── 5. Impact Score (CVSS + EPSS) ────────────────────────────────────

@app.route("/api/osint/impact/score", methods=["POST"])
def impact_score():
    """
    CVSS + EPSS vulnerability assessment.

    Request body (single):
      {
        "mode": "assess",
        "cve_id": "CVE-2026-9999",
        "description": "Critical RCE in Apache...",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  // optional
        "has_poc": true,
        "in_cisa_kev": false,
        "days_since_published": 3.0,
        "exploit_maturity": "functional"
      }

    Request body (batch):
      {
        "mode": "batch",
        "cves": [
          {"cve_id": "...", "description": "...", "has_poc": true, ...},
          ...
        ]
      }
    """
    body = request.get_json(force=True)
    mode = body.get("mode", "assess")

    def _impact_score():
        if mode == "assess":
            cve_id = str(body.get("cve_id", ""))
            description = str(body.get("description", ""))
            cvss_str = body.get("cvss_vector")

            cvss = None
            if cvss_str:
                cvss = CvssVector.from_string(str(cvss_str))

            assessment = assess_vulnerability(
                cve_id=cve_id,
                description=description,
                cvss=cvss,
                has_poc=bool(body.get("has_poc", False)),
                in_cisa_kev=bool(body.get("in_cisa_kev", False)),
                days_since_published=float(body.get("days_since_published", 30.0)),
                exploit_maturity=str(body.get("exploit_maturity", "unproven")),
            )
            return {
                "cve_id": assessment.cve_id,
                "description": assessment.description[:300],
                "cvss_vector": assessment.cvss_vector.to_string(),
                "cvss_base_score": assessment.cvss_base_score,
                "cvss_severity": assessment.cvss_severity,
                "epss_score": assessment.epss_score,
                "epss_percentile": assessment.epss_percentile,
                "priority": assessment.priority.value,
                "recommendation": assessment.recommendation(),
                "predicted_fields": assessment.predicted_fields,
                "breakdown": assessment.cvss_vector.breakdown(),
            }

        elif mode == "batch":
            cves = body.get("cves", [])
            results = scan_cve_batch(cves)
            return {
                "total": len(results),
                "assessments": [
                    {
                        "cve_id": a.cve_id,
                        "cvss_score": a.cvss_base_score,
                        "cvss_severity": a.cvss_severity,
                        "epss_score": a.epss_score,
                        "priority": a.priority.value,
                        "recommendation": a.recommendation(),
                    }
                    for a in results
                ],
            }

        elif mode == "predict":
            cve_id = str(body.get("cve_id", ""))
            description = str(body.get("description", ""))
            cvss = CvssVector.from_description(cve_id, description) if hasattr(CvssVector, 'from_description') else None
            if cvss is None:
                from agents.causal_osint.cvss_epss import predict_cvss_from_description
                cvss = predict_cvss_from_description(cve_id, description)
            return {
                "cve_id": cve_id,
                "predicted_cvss_vector": cvss.to_string(),
                "predicted_base_score": round(cvss.base_score(), 1),
                "predicted_severity": cvss.severity(),
                "predicted_attributes": cvss.predicted_attributes,
                "breadown": cvss.breakdown(),
            }

        else:
            return {"error": f"Unknown mode: {mode}. Use 'assess', 'batch', or 'predict'."}

    result = execute_with_resilience(
        provider="causal_osint",
        task="impact_score",
        fn=_impact_score,
        timeout=20.0,
        retries=2,
        agent="causal_osint",
        tools_used=["cvss_epss"],
    )

    return jsonify({"mode": mode, "result": result})


# ── 6. Adversarial Check ─────────────────────────────────────────────

@app.route("/api/osint/adversarial/check", methods=["POST"])
def adversarial_check():
    """
    Check text for adversarial content (prompt injection, jailbreak, coordinated attack).

    Request body:
      {
        "mode": "single",    // 'single' | 'batch' | 'coordinated'
        "text": "...",
        "options": { "toxicity_threshold": 0.35, "min_cluster_size": 3 }
      }
    """
    body = request.get_json(force=True)
    mode = body.get("mode", "single")

    def _adversarial_check():
        if mode == "single":
            text = str(body.get("text", ""))
            toxicity_threshold = float(body.get("options", {}).get("toxicity_threshold", 0.35))
            score = score_adversarial(text, toxicity_threshold=toxicity_threshold)
            return {
                "text_preview": text[:200],
                "adversarial_score": score,
                "is_adversarial": score > 0.5,
                "threshold_used": toxicity_threshold,
            }

        elif mode == "batch":
            texts = body.get("texts", [])
            return {
                "count": len(texts),
                "results": [
                    {
                        "index": i,
                        "text_preview": t[:200],
                        "adversarial_score": score_adversarial(str(t)),
                        "is_adversarial": is_adversarial(str(t)),
                    }
                    for i, t in enumerate(texts)
                ],
            }

        elif mode == "coordinated":
            texts = body.get("texts", [])
            detection = detect_coordinated_attack(
                [str(t) for t in texts],
                similarity_threshold=float(body.get("options", {}).get("similarity_threshold", 0.15)),
                min_cluster_size=int(body.get("options", {}).get("min_cluster_size", 3)),
            )
            return detection

        else:
            return {"error": f"Unknown mode: {mode}"}

    result = execute_with_resilience(
        provider="causal_osint",
        task="adversarial_check",
        fn=_adversarial_check,
        timeout=15.0,
        retries=2,
        agent="causal_osint",
        tools_used=["adversarial_defense"],
    )

    return jsonify({"mode": mode, "result": result})


# ── Error handlers ────────────────────────────────────────────────────

@app.errorhandler(400)
def bad_request(e):
    return jsonify({"error": "Bad request", "detail": str(e)}), 400


@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Not found"}), 404


@app.errorhandler(500)
def internal_error(e):
    return jsonify({"error": "Internal server error", "detail": str(e)}), 500


# ── Main ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    debug = os.environ.get("DEBUG", "0") == "1"

    print("╔══════════════════════════════════════════════════════════╗")
    print("║  SignalForge-Commotai | Causal OSINT Tier 1 Agent       ║")
    print(f"║  Version: {_agent_version}                                       ║")
    print(f"║  Port: {port}                                               ║")
    print(f"║  Health: http://127.0.0.1:{port}/api/osint/health        ║")
    print("╚══════════════════════════════════════════════════════════╝")

    app.run(host="0.0.0.0", port=port, debug=debug)
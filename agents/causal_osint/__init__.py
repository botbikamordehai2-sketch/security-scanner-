"""
SignalForge-Commotai | Tier 1 Causal OSINT Agent
Multi-Cloud Intelligence Platform — May 2026

Modules:
  scm              — Structural Causal Model with A2P (Abduct-Act-Predict) scaffolding
  semantic_dedup   — SemDeDup pipeline (GLiNER + SentenceBERT + HDBSCAN)
  adversarial_defense — PurifyGen token-level semantic purification
  reputation       — RAGRank + Bayesian P(H|E) + Admiralty A-F + time decay
  cvss_epss        — AgenticVM CVSS prediction + EPSS exploitation probability
  agent            — Flask API (5 endpoints, ExecutionWrapper integration)
"""

__version__ = "1.0.0"
__agent_name__ = "causal_osint_tier1"
__architecture__ = "SignalForge-Commotai Multi-Cloud"
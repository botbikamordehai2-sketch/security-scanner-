"""Unit tests for the Reputation Engine — Bayesian updates, RAGRank, Admiralty, Time Decay."""

import sys
import time
from pathlib import Path

_agent_dir = Path(__file__).resolve().parent.parent
_security_scanner = _agent_dir.parent.parent
sys.path.insert(0, str(_security_scanner))

from agents.causal_osint.reputation import (
    ReputationEngine,
    ReputationLoop,
    SourceProfile,
    SourceAssessment,
    Indicator,
    create_indicator,
    AdmiraltyGrade,
    grade_from_credibility,
    decay_rate_from_half_life,
    HALF_LIFE_PRESETS,
)





"""
Reputation Loop — Bayesian Trust + RAGRank + Admiralty A-F + Time Decay

Manages source credibility for OSINT intelligence:
  1. Admiralty A-F scale: initial quality grading of sources
  2. Bayesian P(H|E): update belief in source reliability after each observation
  3. RAGRank: author credibility as accumulated authority of prior documents
  4. Exponential Time Decay: T(t) = T_0 · e^{−λt}
  5. Continuous re-evaluation loop

Source credibility is NOT static — it evolves with each new piece of intelligence.

Admiralty Scale (NATO intelligence grading):
  A — Completely reliable      (historical confirmation rate > 95%)
  B — Usually reliable          (75-95%)
  C — Fairly reliable           (50-75%)
  D — Not usually reliable      (25-50%)
  E — Unreliable                (5-25%)
  F — Cannot be judged          (unknown/initial)

Bayesian Update:
  Prior: P(H) = source credibility before new evidence
  Likelihood: P(E|H) = probability of observing E if source is reliable
  Posterior: P(H|E) = P(E|H) · P(H) / P(E)

Time Decay for indicators (IPs, domains, signatures):
  T(t) = T_0 · e^{−λt}
  where λ is chosen so half-life matches domain (OSINT: 7 days, C2: 24h)
"""

from __future__ import annotations

import math
import time
from dataclasses import dataclass, field
from enum import Enum


# ---------------------------------------------------------------------------
# Admiralty A-F Scale
# ---------------------------------------------------------------------------

class AdmiraltyGrade(str, Enum):
    A = "A"  # Completely reliable (>95% confirmation)
    B = "B"  # Usually reliable (75-95%)
    C = "C"  # Fairly reliable (50-75%)
    D = "D"  # Not usually reliable (25-50%)
    E = "E"  # Unreliable (5-25%)
    F = "F"  # Cannot be judged (initial / unknown)


ADMIRALTY_PRIORS: dict[AdmiraltyGrade, float] = {
    AdmiraltyGrade.A: 0.975,
    AdmiraltyGrade.B: 0.85,
    AdmiraltyGrade.C: 0.625,
    AdmiraltyGrade.D: 0.375,
    AdmiraltyGrade.E: 0.15,
    AdmiraltyGrade.F: 0.5,  # neutral prior
}

ADMIRALTY_THRESHOLDS: list[tuple[float, AdmiraltyGrade]] = [
    (0.95, AdmiraltyGrade.A),
    (0.75, AdmiraltyGrade.B),
    (0.50, AdmiraltyGrade.C),
    (0.25, AdmiraltyGrade.D),
    (0.05, AdmiraltyGrade.E),
]


def grade_from_credibility(credibility: float) -> AdmiraltyGrade:
    """Map credibility score [0,1] → Admiralty grade."""
    for threshold, grade in ADMIRALTY_THRESHOLDS:
        if credibility >= threshold:
            return grade
    return AdmiraltyGrade.E


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class SourceAssessment:
    """An assessment event: a piece of intelligence was later confirmed/refuted."""
    source_id: str
    timestamp: float           # unix time when intel was received
    assessment_time: float     # unix time when truth was determined
    confirmed: bool            # True = intel was accurate, False = false positive/disinfo
    confidence: float = 1.0    # how confident we are in this assessment (0-1)
    evidence_description: str = ""


@dataclass
class SourceProfile:
    """Bayesian reputation profile for a single intelligence source."""
    source_id: str
    source_type: str = "unknown"       # "CVE/NVD", "Twitter", "DarkWeb", "ThreatIntel", ...
    credibility: float = 0.5           # P(H) — current belief in reliability
    assessments: list[SourceAssessment] = field(default_factory=list)
    total_reports: int = 0
    confirmed_reports: int = 0
    refuted_reports: int = 0
    admiralty_grade: AdmiraltyGrade = AdmiraltyGrade.F
    credential_score: float = 1.0      # RAGRank: accumulated author authority
    decay_rate: float = 0.0            # time-decay λ (reputation drifts toward 0.5)
    last_updated: float = field(default_factory=time.time)
    metadata: dict = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.admiralty_grade = grade_from_credibility(self.credibility)


@dataclass
class Indicator:
    """A time-sensitive intelligence indicator (IP, domain, hash, etc.)."""
    indicator_type: str   # "ip", "domain", "hash", "cve", "email", "url"
    value: str
    initial_trust: float  # T_0
    timestamp: float      # when first observed
    decay_rate: float     # λ — controls half-life
    source_id: str = "unknown"
    context: str = ""

    def trust_at(self, t: float | None = None) -> float:
        """
        Current trust value with exponential decay: T(t) = T_0 · e^{−λ·Δt}
        """
        if t is None:
            t = time.time()
        dt = max(0.0, t - self.timestamp)
        return self.initial_trust * math.exp(-self.decay_rate * dt)

    def half_life(self) -> float:
        """Half-life in seconds: t_{1/2} = ln(2) / λ"""
        if self.decay_rate <= 0:
            return float("inf")
        return math.log(2) / self.decay_rate

    def is_stale(self, threshold: float = 0.1, t: float | None = None) -> bool:
        """Has trust decayed below threshold?"""
        return self.trust_at(t) < threshold


# ── Decay rate presets ────────────────────────────────────────────────

def decay_rate_from_half_life(half_life_seconds: float) -> float:
    """λ = ln(2) / half_life"""
    if half_life_seconds <= 0:
        return 0.0
    return math.log(2) / half_life_seconds


# Standard half-lives for OSINT domains
HALF_LIFE_PRESETS: dict[str, float] = {
    "c2_ip":        24 * 3600,        # 1 day — C2 infrastructure rotates fast
    "phishing_domain": 3 * 24 * 3600, # 3 days
    "malware_hash":  7 * 24 * 3600,   # 1 week
    "cve":          30 * 24 * 3600,   # 30 days — CVEs remain relevant longer
    "threat_report": 14 * 24 * 3600,  # 2 weeks
    "social_media":  6 * 3600,        # 6 hours — social media moves fast
    "darkweb_post":  3 * 24 * 3600,   # 3 days
    "ip_scan":       1 * 3600,        # 1 hour — scanning IPs stale quickly
}


def create_indicator(
    indicator_type: str,
    value: str,
    initial_trust: float = 1.0,
    source_id: str = "unknown",
    context: str = "",
    half_life_seconds: float | None = None,
) -> Indicator:
    """Create an indicator with appropriate decay rate from presets."""
    if half_life_seconds is None:
        half_life_seconds = HALF_LIFE_PRESETS.get(indicator_type, 7 * 24 * 3600)
    return Indicator(
        indicator_type=indicator_type,
        value=value,
        initial_trust=initial_trust,
        timestamp=time.time(),
        decay_rate=decay_rate_from_half_life(half_life_seconds),
        source_id=source_id,
        context=context,
    )


# ---------------------------------------------------------------------------
# Bayesian reputation engine
# ---------------------------------------------------------------------------

class ReputationEngine:
    """
    Manages source profiles and performs Bayesian updates.

    P(H|E) = P(E|H) · P(H) / P(E)

    Where:
      P(H)   = prior credibility of the source
      P(E|H) = likelihood of observing this evidence if source is reliable
               (0.95 for confirmed, 0.05 for refuted — small error margin)
      P(E)   = P(E|H)·P(H) + P(E|¬H)·(1-P(H))
    """

    def __init__(self):
        self.sources: dict[str, SourceProfile] = {}
        self.indicators: list[Indicator] = []

    # ── Source management ───────────────────────────────────────────

    def get_or_create_source(
        self,
        source_id: str,
        source_type: str = "unknown",
        initial_credibility: float | None = None,
        credential_score: float = 1.0,
    ) -> SourceProfile:
        """Get existing source profile or create a new one."""
        if source_id in self.sources:
            return self.sources[source_id]

        cred = initial_credibility if initial_credibility is not None else 0.5
        profile = SourceProfile(
            source_id=source_id,
            source_type=source_type,
            credibility=cred,
            credential_score=credential_score,
            admiralty_grade=grade_from_credibility(cred),
            last_updated=time.time(),
        )
        self.sources[source_id] = profile
        return profile

    # ── Bayesian update ─────────────────────────────────────────────

    def assess_intelligence(
        self,
        source_id: str,
        confirmed: bool,
        confidence: float = 1.0,
        evidence_description: str = "",
        assessment_time: float | None = None,
    ) -> SourceProfile:
        """
        Record an assessment event and update source credibility via Bayes' rule.

        Args:
            source_id:     Which source this intelligence came from
            confirmed:     True = intel was accurate, False = false positive
            confidence:    How confident we are in this assessment
            evidence_description: Human-readable context
            assessment_time: When truth was determined (default: now)

        Returns:
            Updated SourceProfile
        """
        profile = self.get_or_create_source(source_id)
        now = time.time()
        if assessment_time is None:
            assessment_time = now

        # Record assessment
        assessment = SourceAssessment(
            source_id=source_id,
            timestamp=now,
            assessment_time=assessment_time,
            confirmed=confirmed,
            confidence=confidence,
            evidence_description=evidence_description,
        )
        profile.assessments.append(assessment)
        profile.total_reports += 1

        if confirmed:
            profile.confirmed_reports += 1
        else:
            profile.refuted_reports += 1

        # ── Bayesian update ─────────────────────────────────────────
        prior = profile.credibility

        # Likelihood: P(E|H)
        if confirmed:
            likelihood_given_reliable = 0.95 * confidence  # reliable source → most likely confirms
            likelihood_given_unreliable = 0.10 * confidence  # even unreliable may get lucky
        else:
            likelihood_given_reliable = 0.05 * confidence   # reliable source rarely wrong
            likelihood_given_unreliable = 0.70 * confidence  # unreliable often wrong

        # Marginal: P(E)
        p_e = (likelihood_given_reliable * prior +
               likelihood_given_unreliable * (1.0 - prior))

        if p_e > 0:
            posterior = (likelihood_given_reliable * prior) / p_e
        else:
            posterior = prior

        # Apply confidence weighting — lower confidence = less update
        posterior = prior + (posterior - prior) * confidence
        posterior = max(0.01, min(0.99, posterior))

        profile.credibility = round(posterior, 4)
        profile.admiralty_grade = grade_from_credibility(posterior)
        profile.last_updated = now

        # ── RAGRank adjustment ─────────────────────────────────────
        # Boost credibility based on accumulated author authority
        if profile.confirmed_reports > 5:
            raw_accuracy = profile.confirmed_reports / max(profile.total_reports, 1)
            # Blend Bayesian posterior with empirical accuracy
            blend_weight = min(0.5, profile.total_reports / 50)  # more data → higher blend
            blended = (1 - blend_weight) * profile.credibility + blend_weight * raw_accuracy
            profile.credibility = round(blended, 4)

        return profile

    # ── RAGRank: Author credibility from document authority ─────────

    def update_ragrank(
        self,
        source_id: str,
        document_citations: int = 0,
        peer_references: int = 0,
        avg_document_quality: float = 0.5,
    ) -> float:
        """
        RAGRank: compute author credibility score as accumulated authority.

        Credential = f(citations, peer_refs, avg_quality) normalized to [0.5, 2.0]
        Values > 1.0 = source has positive authority premium
        Values < 1.0 = source has no established authority
        """
        profile = self.get_or_create_source(source_id)

        # Base score from citations and references
        citation_score = math.log(1 + document_citations) / math.log(10)  # log-scaled
        ref_score = math.log(1 + peer_references) / math.log(10)

        # Combine
        raw = 0.5 + 0.3 * citation_score + 0.2 * ref_score + 0.5 * avg_document_quality
        profile.credential_score = round(max(0.5, min(2.0, raw)), 4)
        return profile.credential_score

    # ── Time decay for source credibility ───────────────────────────

    def apply_reputation_decay(
        self,
        source_id: str,
        decay_rate: float | None = None,
        current_time: float | None = None,
    ) -> SourceProfile:
        """
        Apply time decay to source credibility.
        If source hasn't reported recently, credibility drifts toward 0.5 (neutral).

        Default decay: credibility halves every 90 days of inactivity.
        """
        profile = self.get_or_create_source(source_id)
        now = current_time or time.time()

        if decay_rate is None:
            # Default: half-life of 90 days
            decay_rate = decay_rate_from_half_life(90 * 24 * 3600)

        dt = max(0.0, now - profile.last_updated)

        if dt > 0 and decay_rate > 0:
            # Drift toward neutral (0.5) with exponential decay
            deviation = profile.credibility - 0.5
            decayed_deviation = deviation * math.exp(-decay_rate * dt)
            profile.credibility = round(0.5 + decayed_deviation, 4)
            profile.admiralty_grade = grade_from_credibility(profile.credibility)
            profile.last_updated = now

        return profile

    # ── Bulk indicator management ───────────────────────────────────

    def add_indicator(self, indicator: Indicator) -> None:
        """Add an intelligence indicator to the decay-tracked pool."""
        self.indicators.append(indicator)

    def get_active_indicators(
        self,
        trust_threshold: float = 0.1,
        current_time: float | None = None,
    ) -> list[Indicator]:
        """Return indicators whose trust has not yet decayed below threshold."""
        t = current_time or time.time()
        return [ind for ind in self.indicators if ind.trust_at(t) >= trust_threshold]

    def purge_stale_indicators(
        self,
        trust_threshold: float = 0.05,
        current_time: float | None = None,
    ) -> int:
        """Remove stale indicators. Returns count purged."""
        t = current_time or time.time()
        before = len(self.indicators)
        self.indicators = [ind for ind in self.indicators if ind.trust_at(t) >= trust_threshold]
        return before - len(self.indicators)

    # ── Export ────────────────────────────────────────────────────

    def source_summary(self, source_id: str) -> dict:
        """Full summary of a source's reputation."""
        profile = self.get_or_create_source(source_id)
        return {
            "source_id": profile.source_id,
            "source_type": profile.source_type,
            "credibility": profile.credibility,
            "admiralty_grade": profile.admiralty_grade.value,
            "total_reports": profile.total_reports,
            "confirmed": profile.confirmed_reports,
            "refuted": profile.refuted_reports,
            "accuracy": (
                round(profile.confirmed_reports / max(profile.total_reports, 1), 4)
                if profile.total_reports > 0 else None
            ),
            "credential_score": profile.credential_score,
            "last_updated": profile.last_updated,
            "assessments_count": len(profile.assessments),
        }

    def all_sources_summary(self) -> list[dict]:
        """Summarize all tracked sources."""
        return [self.source_summary(sid) for sid in self.sources]

    def indicator_stats(self) -> dict:
        """Statistics on the indicator pool."""
        active = self.get_active_indicators()
        stale = len(self.indicators) - len(active)
        return {
            "total_indicators": len(self.indicators),
            "active": len(active),
            "stale": stale,
            "by_type": {},
        }


# ---------------------------------------------------------------------------
# Reputation Loop — continuous re-evaluation
# ---------------------------------------------------------------------------

class ReputationLoop:
    """
    Orchestrates continuous re-evaluation of sources and indicators.

    Runs periodically:
      1. Apply time decay to all source reputations
      2. Purge stale indicators
      3. Recompute Admiralty grades
      4. Return actionable intelligence summary
    """

    def __init__(self, engine: ReputationEngine | None = None):
        self.engine = engine or ReputationEngine()

    def tick(self, current_time: float | None = None) -> dict:
        """
        Execute one cycle of the reputation loop.

        Returns:
          {
            "sources_updated": int,
            "indicators_purged": int,
            "active_indicators": int,
            "source_summaries": [...],
            "grade_changes": [...],
          }
        """
        t = current_time or time.time()
        grade_before: dict[str, AdmiraltyGrade] = {
            sid: s.admiralty_grade for sid, s in self.engine.sources.items()
        }

        # Decay all source reputations
        for sid in list(self.engine.sources.keys()):
            self.engine.apply_reputation_decay(sid, current_time=t)

        # Purge stale indicators
        purged = self.engine.purge_stale_indicators(current_time=t)

        # Detect grade changes
        grade_after: dict[str, AdmiraltyGrade] = {
            sid: s.admiralty_grade for sid, s in self.engine.sources.items()
        }
        changes = [
            {
                "source_id": sid,
                "before": grade_before.get(sid, AdmiraltyGrade.F).value,
                "after": grade_after[sid].value,
            }
            for sid in grade_before
            if grade_before.get(sid) != grade_after.get(sid)
        ]

        return {
            "sources_updated": len(self.engine.sources),
            "indicators_purged": purged,
            "active_indicators": len(self.engine.get_active_indicators(current_time=t)),
            "source_summaries": self.engine.all_sources_summary(),
            "grade_changes": changes,
        }


# ---------------------------------------------------------------------------
# Quick test / demo
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("=== Reputation Engine Demo ===\n")

    engine = ReputationEngine()

    # Create sources
    engine.get_or_create_source("nvd", source_type="CVE/NVD", initial_credibility=0.95)
    engine.get_or_create_source("twitter_user_1", source_type="Twitter", initial_credibility=0.5)
    engine.get_or_create_source("darkweb_forum_x", source_type="DarkWeb", initial_credibility=0.3)

    # Simulate assessments
    print("--- Initial state ---")
    for sid in ["nvd", "twitter_user_1", "darkweb_forum_x"]:
        print(f"  {sid}: cred={engine.sources[sid].credibility}, grade={engine.sources[sid].admiralty_grade.value}")

    # NVD confirms a report (strengthens reliability)
    engine.assess_intelligence("nvd", confirmed=True, evidence_description="CVE-2026-1234 confirmed")
    engine.assess_intelligence("nvd", confirmed=True, evidence_description="CVE-2026-1235 confirmed")
    engine.assess_intelligence("nvd", confirmed=True, evidence_description="CVE-2026-1236 confirmed")

    # Twitter user gets mixed results
    engine.assess_intelligence("twitter_user_1", confirmed=True, evidence_description="Correct exploit prediction")
    engine.assess_intelligence("twitter_user_1", confirmed=False, evidence_description="False alarm on CVE")
    engine.assess_intelligence("twitter_user_1", confirmed=True, evidence_description="Correct APT attribution")

    # DarkWeb source mostly wrong
    engine.assess_intelligence("darkweb_forum_x", confirmed=False, evidence_description="Fake exploit claim")
    engine.assess_intelligence("darkweb_forum_x", confirmed=False, evidence_description="Nonexistent zero-day")

    print("\n--- After assessments ---")
    for sid in ["nvd", "twitter_user_1", "darkweb_forum_x"]:
        s = engine.source_summary(sid)
        print(f"  {sid}: cred={s['credibility']:.4f}, grade={s['admiralty_grade']}, "
              f"confirmed={s['confirmed']}/{s['total_reports']}, accuracy={s['accuracy']}")

    # RAGRank
    engine.update_ragrank("nvd", document_citations=5000, peer_references=2000, avg_document_quality=0.95)
    print(f"\n  NVD RAGRank credential score: {engine.sources['nvd'].credential_score:.4f}")

    # Indicators with time decay
    print("\n--- Indicator Time Decay ---")
    ip_indicator = create_indicator("c2_ip", "192.168.1.100", initial_trust=1.0, source_id="threat_intel")
    cve_indicator = create_indicator("cve", "CVE-2026-9999", initial_trust=1.0, source_id="nvd")

    engine.add_indicator(ip_indicator)
    engine.add_indicator(cve_indicator)

    print(f"  C2 IP trust now: {ip_indicator.trust_at():.4f}")
    print(f"  C2 IP half-life: {ip_indicator.half_life() / 3600:.1f} hours")
    print(f"  CVE trust now:   {cve_indicator.trust_at():.4f}")
    print(f"  CVE half-life:   {cve_indicator.half_life() / 86400:.1f} days")

    # Reputation Loop
    print("\n--- Reputation Loop Tick ---")
    loop = ReputationLoop(engine)
    result = loop.tick()
    print(f"  Sources updated: {result['sources_updated']}")
    print(f"  Indicators purged: {result['indicators_purged']}")
    print(f"  Active indicators: {result['active_indicators']}")
    print(f"  Grade changes: {result['grade_changes']}")
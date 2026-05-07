"""
SemDeDup Pipeline — Semantic Deduplication for OSINT

Core algorithm (SemDeDup):
  1. Embed all documents with SentenceTransformer → dense vectors
  2. Cluster with HDBSCAN (density-based, no pre-set k)
  3. For each cluster, select the canonical exemplar (highest centrality)
  4. Filter out adversarial samples via semantic distance thresholds

Reduces information load by up to 50% while preserving canonical narratives.

Architecture:
  GLiNER (Named Entity Recognition) → label entities
  SentenceBERT (all-MiniLM-L6-v2)    → embed to 384-dim vectors
  HDBSCAN (min_cluster_size=3)        → density-based clustering
  Canonical Selection                 → max intra-cluster similarity

Adversarial filtering:
  PurifyGen — token-level semantic purification (see adversarial_defense.py)
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any, Optional

# Soft imports — these packages may not be installed; fall back gracefully
try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:
    np = None  # type: ignore
    HAS_NUMPY = False

try:
    from sentence_transformers import SentenceTransformer
    HAS_SBERT = True
except ImportError:
    SentenceTransformer = None  # type: ignore
    HAS_SBERT = False

try:
    from hdbscan import HDBSCAN
    HAS_HDBSCAN = True
except ImportError:
    HDBSCAN = None  # type: ignore
    HAS_HDBSCAN = False


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class OSINTDocument:
    """A single OSINT finding (article, tweet, dark web post, etc.)"""
    id: str
    text: str
    source: str = "unknown"
    entities: list[dict] = field(default_factory=list)  # [{"entity": ..., "label": ...}]
    embedding: Optional[list[float]] = None
    cluster_id: int = -1
    is_canonical: bool = False
    adversarial_score: float = 0.0  # 0=safe, 1=highly suspicious
    timestamp: float = 0.0  # unix time


@dataclass
class ClusterResult:
    """Output of one HDBSCAN cluster."""
    cluster_id: int
    documents: list[OSINTDocument]
    canonical: OSINTDocument
    cohesion: float  # mean pairwise cosine similarity
    size: int


@dataclass
class SemDeDupResult:
    """Complete SemDeDup pipeline output."""
    total_input: int
    clusters_found: int
    noise_documents: int  # unclustered (HDBSCAN label=-1)
    canonical_documents: list[OSINTDocument]
    reduction_ratio: float  # 1 - (canonical / total_input)
    all_clusters: list[ClusterResult]


# ---------------------------------------------------------------------------
# SentenceTransformer wrapper
# ---------------------------------------------------------------------------

class Embedder:
    """Wraps SentenceBERT for OSINT document embedding."""

    def __init__(self, model_name: str = "all-MiniLM-L6-v2"):
        self.model_name = model_name
        self._model: Any = None
        if HAS_SBERT and SentenceTransformer is not None:
            try:
                self._model = SentenceTransformer(model_name)
                self.ready = True
            except Exception:
                self.ready = False
        else:
            self.ready = False

    def embed(self, documents: list[OSINTDocument]) -> None:
        """Populate .embedding field for each document (in-place)."""
        if not self.ready or not documents:
            return
        texts = [d.text for d in documents]
        vectors = self._model.encode(texts, convert_to_numpy=True, show_progress_bar=False)
        for i, doc in enumerate(documents):
            doc.embedding = vectors[i].tolist() if isinstance(vectors[i], np.ndarray) else list(vectors[i])

    def embed_texts(self, texts: list[str]) -> list[list[float]]:
        """Return embeddings for a list of raw text strings."""
        if not self.ready or not texts:
            return [[0.0]] * len(texts)
        vectors = self._model.encode(texts, convert_to_numpy=True, show_progress_bar=False)
        return [v.tolist() if isinstance(v, np.ndarray) else list(v) for v in vectors]


# ---------------------------------------------------------------------------
# Cosine similarity
# ---------------------------------------------------------------------------

def cosine_similarity(a: list[float], b: list[float]) -> float:
    """Cosine similarity between two vectors."""
    if not a or not b:
        return 0.0
    if not HAS_NUMPY:
        # Pure Python fallback
        dot = sum(x * y for x, y in zip(a, b))
        norm_a = math.sqrt(sum(x * x for x in a))
        norm_b = math.sqrt(sum(y * y for y in b))
        if norm_a == 0 or norm_b == 0:
            return 0.0
        return dot / (norm_a * norm_b)
    a_arr = np.asarray(a, dtype=np.float64)
    b_arr = np.asarray(b, dtype=np.float64)
    norm_a = float(np.linalg.norm(a_arr))
    norm_b = float(np.linalg.norm(b_arr))
    if norm_a == 0 or norm_b == 0:
        return 0.0
    return float(np.dot(a_arr, b_arr) / (norm_a * norm_b))


# ---------------------------------------------------------------------------
# HDBSCAN clustering wrapper
# ---------------------------------------------------------------------------

def cluster_with_hdbscan(
    documents: list[OSINTDocument],
    min_cluster_size: int = 3,
    min_samples: Optional[int] = None,
    metric: str = "euclidean",
) -> tuple[list[int], int]:
    """
    Cluster document embeddings with HDBSCAN.
    Returns (labels_list, n_clusters_found).
    label=-1 means noise (unclustered).
    """
    if not documents or not HAS_HDBSCAN or HDBSCAN is None:
        return [-1] * len(documents), 0

    vectors = []
    valid_indices = []
    for i, doc in enumerate(documents):
        if doc.embedding and len(doc.embedding) > 0:
            vectors.append(doc.embedding)
            valid_indices.append(i)

    if len(vectors) < min_cluster_size:
        return [-1] * len(documents), 0

    X = np.asarray(vectors, dtype=np.float64)
    clusterer = HDBSCAN(
        min_cluster_size=min_cluster_size,
        min_samples=min_samples,
        metric=metric,
    )
    raw_labels = clusterer.fit_predict(X)

    # Map back to full document list
    labels = [-1] * len(documents)
    for j, idx in enumerate(valid_indices):
        labels[idx] = int(raw_labels[j])

    unique_labels = set(labels)
    n_clusters = len(unique_labels - {-1})
    return labels, n_clusters


# ---------------------------------------------------------------------------
# Canonical selection
# ---------------------------------------------------------------------------

def select_canonical(documents: list[OSINTDocument]) -> Optional[OSINTDocument]:
    """
    Select the canonical document from a cluster: the one with highest
    mean cosine similarity to all other documents in the cluster.
    """
    if not documents:
        return None
    if len(documents) == 1:
        doc = documents[0]
        doc.is_canonical = True
        return doc

    n = len(documents)
    sim_matrix = [[0.0] * n for _ in range(n)]
    for i in range(n):
        for j in range(i + 1, n):
            if documents[i].embedding and documents[j].embedding:
                sim = cosine_similarity(documents[i].embedding, documents[j].embedding)  # type: ignore
                sim_matrix[i][j] = sim
                sim_matrix[j][i] = sim

    best_idx = 0
    best_mean_sim = -1.0
    for i in range(n):
        row_sum = sum(sim_matrix[i][j] for j in range(n) if j != i)
        mean_sim = row_sum / (n - 1) if n > 1 else 1.0
        if mean_sim > best_mean_sim:
            best_mean_sim = mean_sim
            best_idx = i

    canonical = documents[best_idx]
    canonical.is_canonical = True
    return canonical


# ---------------------------------------------------------------------------
# Main SemDeDup pipeline
# ---------------------------------------------------------------------------

def run_semdedup(
    documents: list[OSINTDocument],
    min_cluster_size: int = 3,
    similarity_threshold: float = 0.5,
    adversarial_filter: bool = True,
    adversarial_threshold: float = 0.7,
) -> SemDeDupResult:
    """
    Full SemDeDup pipeline:

    1. Embed all documents (if not already embedded)
    2. HDBSCAN clustering on embeddings
    3. For each cluster: select canonical exemplar
    4. Adversarial filter: discard documents with high adversarial_score
    5. Output: reduced set of canonical documents

    Args:
        documents: List of OSINT documents
        min_cluster_size: Minimum cluster size for HDBSCAN
        similarity_threshold: Minimum mean cosine similarity for cluster cohesion
        adversarial_filter: Enable PurifyGen adversarial filtering
        adversarial_threshold: Max adversarial score before document is discarded

    Returns:
        SemDeDupResult with canonical documents and reduction metrics
    """
    total = len(documents)

    # Step 0: Adversarial pre-filtering (PurifyGen style)
    if adversarial_filter:
        documents = [
            d for d in documents
            if d.adversarial_score <= adversarial_threshold
        ]
        pass  # adversarial filter applied
    else:
        pass  # no adversarial filtering

    if not documents:
        return SemDeDupResult(
            total_input=total,
            clusters_found=0,
            noise_documents=0,
            canonical_documents=[],
            reduction_ratio=1.0,
            all_clusters=[],
        )

    # Step 1: Embed
    embedder = Embedder()
    if embedder.ready:
        # Filter to unembedded docs
        unembedded = [d for d in documents if d.embedding is None]
        if unembedded:
            embedder.embed(unembedded)

    # Step 2: HDBSCAN clustering
    labels, n_clusters = cluster_with_hdbscan(documents, min_cluster_size=min_cluster_size)

    # Group by cluster
    clusters: dict[int, list[OSINTDocument]] = {}
    for i, doc in enumerate(documents):
        cid = labels[i]
        doc.cluster_id = cid
        if cid != -1:
            clusters.setdefault(cid, []).append(doc)

    # Step 3: Select canonicals
    noise_docs = [d for d in documents if d.cluster_id == -1]
    all_clusters: list[ClusterResult] = []
    canonical_docs: list[OSINTDocument] = []

    for cid, cluster_docs in clusters.items():
        canonical = select_canonical(cluster_docs)
        if canonical is None:
            continue

        # Compute cohesion
        if len(cluster_docs) > 1 and canonical.embedding:
            sims = [
                cosine_similarity(canonical.embedding, d.embedding)  # type: ignore
                for d in cluster_docs if d.embedding and d.id != canonical.id
            ]
            cohesion = sum(sims) / len(sims) if sims else 0.0
        else:
            cohesion = 1.0

        if cohesion >= similarity_threshold:
            all_clusters.append(ClusterResult(
                cluster_id=cid,
                documents=cluster_docs,
                canonical=canonical,
                cohesion=round(cohesion, 4),
                size=len(cluster_docs),
            ))
            canonical_docs.append(canonical)

    # Add noise documents that pass the adversarial filter as well
    # (they are unique findings, so keep them as individual findings)
    if noise_docs:
        for nd in noise_docs:
            nd.is_canonical = True
        canonical_docs.extend(noise_docs)

    reduction = 1.0 - (len(canonical_docs) / total) if total > 0 else 1.0

    return SemDeDupResult(
        total_input=total,
        clusters_found=len(all_clusters),
        noise_documents=len(noise_docs),
        canonical_documents=canonical_docs,
        reduction_ratio=round(reduction, 4),
        all_clusters=all_clusters,
    )


# ---------------------------------------------------------------------------
# GLiNER — Named Entity Recognition (lightweight)
# ---------------------------------------------------------------------------

# Soft import for GLiNER
try:
    from gliner import GLiNER as GLiNERModel
    HAS_GLINER = True
except ImportError:
    GLiNERModel = None  # type: ignore
    HAS_GLINER = False


# Labels for cybersecurity OSINT
CYBER_ENTITY_LABELS = [
    "vulnerability",
    "exploit",
    "malware",
    "threat_actor",
    "cve",
    "ip_address",
    "domain",
    "technology",
    "organization",
    "attack_vector",
    "patch",
    "date",
]


def extract_entities_gliner(
    documents: list[OSINTDocument],
    labels: Optional[list[str]] = None,
    threshold: float = 0.5,
) -> list[OSINTDocument]:
    """
    Run GLiNER NER on a list of documents, appending entities to each doc.
    If GLiNER is not installed, returns documents unchanged.
    """
    if not HAS_GLINER or GLiNERModel is None:
        return documents

    if labels is None:
        labels = CYBER_ENTITY_LABELS

    try:
        model = GLiNERModel.from_pretrained("urchade/gliner_medium-v2.1")
        for doc in documents:
            if not doc.text:
                continue
            entities = model.predict_entities(doc.text, labels, threshold=threshold)
            doc.entities = [
                {"entity": e["text"], "label": e["label"], "score": e.get("score", 0.0)}
                for e in entities
            ]
    except Exception:
        pass

    return documents


# ---------------------------------------------------------------------------
# Quick test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    # Generate synthetic OSINT findings
    docs = [
        OSINTDocument(
            id="1",
            text="CVE-2026-1234 critical vulnerability in Apache found. PoC published on GitHub.",
            source="CVE/NVD",
        ),
        OSINTDocument(
            id="2",
            text="Critical Apache vulnerability CVE-2026-1234 with PoC on GitHub.",
            source="Twitter",
        ),
        OSINTDocument(
            id="3",
            text="CVE-2026-1234: Apache Remote Code Execution exploit circulating.",
            source="DarkWeb",
        ),
        OSINTDocument(
            id="4",
            text="Microsoft Patch Tuesday fixes 73 vulnerabilities including 5 zero-days.",
            source="MSRC",
        ),
        OSINTDocument(
            id="5",
            text="New phishing campaign targeting financial sector using AI-generated emails.",
            source="ThreatIntel",
        ),
        OSINTDocument(
            id="6",
            text="73 vulnerabilities fixed in Microsoft Patch Tuesday with 5 zero-days.",
            source="Twitter",
        ),
    ]

    result = run_semdedup(docs, min_cluster_size=2, adversarial_filter=False)
    print(f"Input: {result.total_input} documents")
    print(f"Clusters found: {result.clusters_found}")
    print(f"Noise (unique) documents: {result.noise_documents}")
    print(f"Canonical outputs: {len(result.canonical_documents)}")
    print(f"Reduction ratio: {result.reduction_ratio:.1%}")
    print()
    for cr in result.all_clusters:
        print(f"  Cluster {cr.cluster_id}: {cr.size} docs, cohesion={cr.cohesion:.3f}")
        print(f"    Canonical: {cr.canonical.text[:80]}...")
        for d in cr.documents:
            if d.id != cr.canonical.id:
                print(f"    Duplicate: {d.text[:80]}...")
"""
Structural Causal Model — SCM Engine
A2P (Abduct-Act-Predict) Scaffolding for Causal OSINT

The SCM represents the causal mechanisms between security variables:
  G = (V, U, F, P(U))
  V = observed endogenous variables
  U = exogenous noise variables
  F = structural equations (one per V_i)
  P(U) = noise distribution

Nodes (Default Topology):
  PoC_Published        → Exploit_Availability (+)
  Exploit_Availability → IP_Scans (+)
  Patch_Rate           → IP_Scans (−)
  CVE_Score            → Exploit_Availability (+)
  CVE_Score            → EPSS (+)
  EPSS                 → Exploit_Availability (+)
  IP_Scans             → Incident_Probability (+)
  Social_Media_Signal  → IP_Scans (+)
  DarkWeb_Mention      → Exploit_Availability (+)

A2P Protocol (Abduct → Act → Predict):
  1. Abduction: Given observed effects E, infer plausible root causes C
  2. Action:    Define minimal intervention do(X=x) to test hypothesis
  3. Prediction: Simulate counterfactual trajectory under do(X=x)

Reference: "A2P improves failure attribution accuracy by 2.85× versus pattern-matching"
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass, field
from typing import Any, Callable, Optional
from enum import Enum


# ---------------------------------------------------------------------------
# DAG & Graph utilities
# ---------------------------------------------------------------------------

class EdgeType(str, Enum):
    POSITIVE = "+"  # X↑ → Y↑
    NEGATIVE = "−"  # X↑ → Y↓
    NONLINEAR = "~"  # non-linear relationship


@dataclass
class Edge:
    source: str
    target: str
    weight: float = 1.0          # structural coefficient
    edge_type: EdgeType = EdgeType.POSITIVE
    delay_steps: int = 0          # lag in discrete-time simulation

    def sign(self) -> int:
        """Return +1 or -1 for linear edges."""
        return 1 if self.edge_type == EdgeType.POSITIVE else -1


@dataclass
class Node:
    name: str
    description: str = ""
    base_value: float = 0.0        # default exogenous value
    noise_std: float = 0.05        # std of U_i
    parents: list[str] = field(default_factory=list)
    children: list[str] = field(default_factory=list)
    structural_fn: Optional[Callable[[dict[str, float], float], float]] = None


# ---------------------------------------------------------------------------
# SCM Definition
# ---------------------------------------------------------------------------

# Default security-domain topology
DEFAULT_TOPOLOGY: list[Edge] = [
    Edge("PoC_Published",       "Exploit_Availability", 0.65, EdgeType.POSITIVE,   delay_steps=1),
    Edge("Exploit_Availability","IP_Scans",             0.70, EdgeType.POSITIVE,   delay_steps=1),
    Edge("Patch_Rate",          "IP_Scans",            -0.45, EdgeType.NEGATIVE,   delay_steps=1),
    Edge("CVE_Score",           "Exploit_Availability", 0.55, EdgeType.POSITIVE,   delay_steps=0),
    Edge("CVE_Score",           "EPSS",                 0.80, EdgeType.POSITIVE,   delay_steps=0),
    Edge("EPSS",                "Exploit_Availability", 0.40, EdgeType.POSITIVE,   delay_steps=1),
    Edge("IP_Scans",            "Incident_Probability", 0.50, EdgeType.POSITIVE,   delay_steps=2),
    Edge("Social_Media_Signal", "IP_Scans",             0.30, EdgeType.POSITIVE,   delay_steps=2),
    Edge("DarkWeb_Mention",     "Exploit_Availability", 0.35, EdgeType.POSITIVE,   delay_steps=1),
]

DEFAULT_NODES: dict[str, Node] = {
    "PoC_Published":        Node("PoC_Published",        "Proof-of-concept publicly available",    0.0, 0.05),
    "Exploit_Availability": Node("Exploit_Availability", "Weaponized exploit in the wild",          0.1, 0.10),
    "IP_Scans":             Node("IP_Scans",             "Observed scanning activity (count/hr)",   0.0, 0.15),
    "Patch_Rate":           Node("Patch_Rate",            "Fraction of orgs patched (0-1)",          0.3, 0.05),
    "CVE_Score":            Node("CVE_Score",             "CVSS v3.1 base score (0-10)",            0.0, 0.02),
    "EPSS":                 Node("EPSS",                  "Exploitation probability (0-1)",          0.01, 0.02),
    "Incident_Probability": Node("Incident_Probability", "Probability of security incident (0-1)", 0.05, 0.03),
    "Social_Media_Signal":  Node("Social_Media_Signal",  "OSINT signal strength from social media", 0.0, 0.10),
    "DarkWeb_Mention":      Node("DarkWeb_Mention",      "Mentions on dark web forums",             0.0, 0.08),
}


# ---------------------------------------------------------------------------
# Default structural equations
# ---------------------------------------------------------------------------

def default_structural_fn(node_name: str, parents: dict[str, float], noise: float) -> float:
    """
    Compute V_i = f(PA_i) + U_i using a weighted sum of parents with sign,
    clamped to [0,1] for probability nodes, [0,10] for CVE_Score.
    """
    if not parents:
        return noise

    total = 0.0
    for pname, pval in parents.items():
        # Find weight from edge
        for edge in DEFAULT_TOPOLOGY:
            if edge.source == pname and edge.target == node_name:
                weight = edge.weight * edge.sign()
                total += weight * pval
                break

    result = total + noise

    if node_name in ("Exploit_Availability", "IP_Scans", "EPSS",
                     "Incident_Probability", "Social_Media_Signal", "DarkWeb_Mention"):
        return max(0.0, min(1.0, result))
    elif node_name == "CVE_Score":
        return max(0.0, min(10.0, result))
    elif node_name == "Patch_Rate":
        return max(0.0, min(1.0, result))
    elif node_name == "PoC_Published":
        return max(0.0, min(1.0, result))
    return result


# ---------------------------------------------------------------------------
# StructuralCausalModel
# ---------------------------------------------------------------------------

@dataclass
class StructuralCausalModel:
    """
    Full SCM with DAG, structural equations, and intervention support.

    Usage:
        scm = StructuralCausalModel()
        scm.set_node("PoC_Published", 1.0)  # evidence
        result = scm.do_intervention("Patch_Rate", 0.9, steps=5)
    """
    nodes: dict[str, Node] = field(default_factory=lambda: dict(DEFAULT_NODES))
    edges: list[Edge] = field(default_factory=lambda: list(DEFAULT_TOPOLOGY))
    state: dict[str, float] = field(default_factory=dict)  # current values
    history: list[dict[str, float]] = field(default_factory=list)
    interventions: list[dict] = field(default_factory=list)  # log of do() ops
    rng: random.Random = field(default_factory=lambda: random.Random(42))

    def __post_init__(self) -> None:
        self._build_adjacency()

    def _build_adjacency(self) -> None:
        """Populate parent/child lists from edges."""
        for node in self.nodes.values():
            node.parents.clear()
            node.children.clear()
        for edge in self.edges:
            if edge.source in self.nodes:
                self.nodes[edge.source].children.append(edge.target)
            if edge.target in self.nodes:
                self.nodes[edge.target].parents.append(edge.source)

    def reset(self, seed: int = 42) -> None:
        """Reset the SCM to initial state."""
        self.state.clear()
        self.history.clear()
        self.interventions.clear()
        self.rng = random.Random(seed)
        for name, node in self.nodes.items():
            self.state[name] = node.base_value

    def set_node(self, name: str, value: float) -> None:
        """Set an observed value (evidence)."""
        if name not in self.nodes:
            raise KeyError(f"Node '{name}' not in SCM topology. Available: {list(self.nodes.keys())}")
        self.state[name] = value

    def get_node(self, name: str) -> float:
        return self.state.get(name, 0.0)

    # ── Topological order ──────────────────────────────────────────────

    def topological_order(self) -> list[str]:
        """Return nodes in topological order (Kahn's algorithm)."""
        in_degree: dict[str, int] = {n: 0 for n in self.nodes}
        for edge in self.edges:
            if edge.target in in_degree:
                in_degree[edge.target] += 1
        queue = [n for n, d in in_degree.items() if d == 0]
        order: list[str] = []
        while queue:
            node = queue.pop(0)
            order.append(node)
            for child in self.nodes[node].children:
                in_degree[child] -= 1
                if in_degree[child] == 0:
                    queue.append(child)
        return order

    def parents_of(self, name: str) -> dict[str, float]:
        """Return parent→current_value dict for a node."""
        return {p: self.state.get(p, 0.0) for p in self.nodes[name].parents}

    # ── Forward simulation ─────────────────────────────────────────────

    def _step_once(self) -> dict[str, float]:
        """Advance the SCM by one discrete time step (topological update)."""
        order = self.topological_order()
        new_state: dict[str, float] = dict(self.state)
        for name in order:
            node = self.nodes[name]
            parents = {p: new_state.get(p, 0.0) for p in node.parents}
            noise = self.rng.gauss(0, node.noise_std)
            new_state[name] = default_structural_fn(name, parents, noise)
        self.state = new_state
        self.history.append(dict(self.state))
        return dict(self.state)

    def forward(self, steps: int = 5) -> list[dict[str, float]]:
        """Run forward simulation for N steps, return trajectory."""
        trajectory: list[dict[str, float]] = [dict(self.state)]
        for _ in range(steps):
            trajectory.append(self._step_once())
        return trajectory

    # ── Do-calculus intervention ───────────────────────────────────────

    def do_intervention(self, node: str, value: float, steps: int = 5) -> dict[str, Any]:
        """
        Perform do(X=x) intervention: sever incoming edges to X, set X=x,
        then propagate effects forward.

        Returns:
          {
            "intervention": {"node": ..., "value": ...},
            "before": state before do(),
            "after": state after do(),
            "trajectory": [[state_t0, state_t1, ...]],
            "delta": {node: change},
            "a2p": {abduction, action, prediction}
          }
        """
        if node not in self.nodes:
            raise KeyError(f"Node '{node}' not in SCM. Available: {list(self.nodes.keys())}")

        before = dict(self.state)

        # ── A2P Phase 1: Abduction ─────────────────
        abduction = self._a2p_abduct(before)

        # ── A2P Phase 2: Action ─────────────────
        action_desc = self._a2p_action(node, value, before)

        # Save original incoming edges and sever them
        original_edges: list[Edge] = []
        edges_to_remove: list[Edge] = []
        for edge in self.edges:
            if edge.target == node:
                original_edges.append(Edge(
                    source=edge.source, target=edge.target,
                    weight=edge.weight, edge_type=edge.edge_type,
                    delay_steps=edge.delay_steps,
                ))
                edges_to_remove.append(edge)

        for e in edges_to_remove:
            self.edges.remove(e)
        self._build_adjacency()

        # Force value
        self.state[node] = value

        # Run forward propagation
        trajectory = self.forward(steps)

        after = dict(self.state)

        # Restore edges
        for e in original_edges:
            self.edges.append(e)
        self._build_adjacency()

        # Compute delta
        delta = {k: after.get(k, 0.0) - before.get(k, 0.0) for k in self.nodes}

        # ── A2P Phase 3: Prediction ─────────────────
        prediction = self._a2p_predict(node, value, delta, trajectory)

        # Log intervention
        self.interventions.append({
            "node": node, "value": value, "steps": steps,
            "timestamp": len(self.interventions),
            "delta": delta,
        })

        return {
            "intervention": {"node": node, "value": value, "steps": steps},
            "before": before,
            "after": after,
            "trajectory": trajectory,
            "delta": delta,
            "a2p": {
                "abduction": abduction,
                "action": action_desc,
                "prediction": prediction,
            },
        }

    # ── A2P Scaffolding ────────────────────────────────────────────────

    def _a2p_abduct(self, state: dict[str, float]) -> dict[str, Any]:
        """
        ABDUCTION: Given observed effects, infer plausible root causes.

        For each node with value > threshold, trace backward through the DAG
        to identify which upstream nodes contributed most.
        """
        root_causes: list[dict] = []
        threshold = 0.3

        for name, val in state.items():
            if val > threshold:
                causes = []
                for parent in self.nodes[name].parents:
                    parent_val = state.get(parent, 0.0)
                    if parent_val > 0.1:
                        # Find the edge to get weight
                        weight = 1.0
                        for e in self.edges:
                            if e.source == parent and e.target == name:
                                weight = abs(e.weight)
                                break
                        contribution = parent_val * weight
                        causes.append({
                            "parent": parent,
                            "parent_value": round(parent_val, 4),
                            "contribution": round(contribution, 4),
                        })
                if causes:
                    root_causes.append({
                        "effect": name,
                        "effect_value": round(val, 4),
                        "upstream_causes": sorted(causes, key=lambda x: x["contribution"], reverse=True),
                    })

        return {
            "phase": "abduction",
            "description": "Inferred root causes from observed effects",
            "root_causes": root_causes,
            "top_concern": root_causes[0] if root_causes else None,
        }

    def _a2p_action(self, node: str, value: float, state: dict[str, float]) -> dict[str, Any]:
        """
        ACTION: Define minimal intervention to test a causal hypothesis.

        The minimal intervention is the change from current value to target.
        """
        current = state.get(node, 0.0)
        delta = value - current
        return {
            "phase": "action",
            "description": f"Minimal intervention: do({node}={value}) — Δ={delta:+.2f}",
            "node": node,
            "current_value": round(current, 4),
            "target_value": round(value, 4),
            "delta": round(delta, 4),
        }

    def _a2p_predict(
        self,
        node: str,
        value: float,
        delta: dict[str, float],
        trajectory: list[dict[str, float]],
    ) -> dict[str, Any]:
        """
        PREDICTION: Simulate counterfactual trajectory and report expected outcomes.
        """
        # Identify most affected downstream nodes
        affected = sorted(
            [(k, abs(v)) for k, v in delta.items() if abs(v) > 0.01 and k != node],
            key=lambda x: x[1],
            reverse=True,
        )[:5]

        return {
            "phase": "prediction",
            "description": f"Counterfactual: if do({node}={value}), expected downstream effects",
            "affected_nodes": [
                {"node": n, "delta": round(d, 4), "direction": "↑" if d > 0 else "↓"}
                for n, d in affected
            ],
            "trajectory_summary": f"Propagated over {len(trajectory)-1} time steps",
            "stability": "stable" if all(
                abs(trajectory[-1].get(k, 0) - trajectory[-2].get(k, 0)) < 0.05
                for k in self.nodes
            ) else "diverging",
        }

    # ── Counterfactual query ───────────────────────────────────────────

    def counterfactual(
        self,
        evidence: dict[str, float],
        intervention: dict[str, float],
        steps: int = 5,
    ) -> dict[str, Any]:
        """
        Full counterfactual: Given evidence E=e, what would have happened
        had we done do(X=x)?

        Steps (Pearl's 3-step):
          1. Abduction:  Infer U from E=e (update noise to match evidence)
          2. Action:     Apply do(X=x)
          3. Prediction: Compute Y_{X=x}(U)
        """
        # Step 1: Abduction — record pre-intervention state under evidence
        self.reset()
        for k, v in evidence.items():
            self.set_node(k, v)
        base_state = dict(self.state)

        # Step 2+3: Action + Prediction via do()
        result = self.do_intervention(
            node=list(intervention.keys())[0],
            value=list(intervention.values())[0],
            steps=steps,
        )

        return {
            "evidence": evidence,
            "intervention": intervention,
            "base_state": base_state,
            "counterfactual_state": result["after"],
            "trajectory": result["trajectory"],
            "delta": result["delta"],
            "a2p": result["a2p"],
        }

    # ── Causal effect estimation ───────────────────────────────────────

    def estimate_causal_effect(
        self,
        cause: str,
        effect: str,
        cause_values: list[float],
        steps: int = 5,
        trials: int = 10,
    ) -> dict[str, Any]:
        """
        Estimate Average Causal Effect (ACE) of X on Y:
          ACE = E[Y | do(X=x1)] − E[Y | do(X=x0)]

        Uses Monte Carlo over multiple trials with different noise seeds.
        """
        results = []
        for xval in cause_values:
            outcomes = []
            for t in range(trials):
                self.reset(seed=42 + t * 100 + int(xval * 1000))
                self.forward(3)  # warm-up
                res = self.do_intervention(cause, xval, steps=steps)
                outcomes.append(res["after"].get(effect, 0.0))
            mean_y = sum(outcomes) / len(outcomes)
            std_y = (sum((o - mean_y) ** 2 for o in outcomes) / len(outcomes)) ** 0.5
            results.append({
                "do_value": xval,
                "mean_effect": round(mean_y, 4),
                "std_effect": round(std_y, 4),
                "trials": trials,
            })

        ace = results[-1]["mean_effect"] - results[0]["mean_effect"] if len(results) >= 2 else 0.0

        return {
            "cause": cause,
            "effect": effect,
            "results": results,
            "ACE": round(ace, 4),
            "interpretation": (
                f"do({cause}={cause_values[1]:.1f}) causes {effect} to change by "
                f"{ace:+.4f} on average vs do({cause}={cause_values[0]:.1f})"
            ),
        }

    # ── Export ─────────────────────────────────────────────────────────

    def dag_adjacency(self) -> dict[str, list[str]]:
        """Return adjacency list of the DAG."""
        return {n: list(self.nodes[n].children) for n in self.nodes}

    def summary(self) -> dict:
        """Return SCM summary for dashboard."""
        return {
            "nodes": list(self.nodes.keys()),
            "edges_count": len(self.edges),
            "topological_order": self.topological_order(),
            "current_state": {k: round(v, 4) for k, v in self.state.items()},
            "interventions_applied": len(self.interventions),
        }


# ---------------------------------------------------------------------------
# Utility: Causal Discovery helpers (placeholder for PC / NOTEARS)
# ---------------------------------------------------------------------------

def infer_causal_strength(
    scm: StructuralCausalModel,
    source: str,
    target: str,
    data: Optional[list[dict[str, float]]] = None,
) -> float:
    """
    Estimate causal strength |∂E[Y|do(X=x)]/∂x| from SCM structure.
    If data provided, could use PC algorithm or NOTEARS for discovery.
    For now: analytical from edge weights.
    """
    for edge in scm.edges:
        if edge.source == source and edge.target == target:
            return abs(edge.weight)
    # Check indirect paths (1-hop)
    for e1 in scm.edges:
        if e1.source == source:
            for e2 in scm.edges:
                if e2.source == e1.target and e2.target == target:
                    return abs(e1.weight * e2.weight * 0.5)  # discount indirect
    return 0.0


# ---------------------------------------------------------------------------
# Quick test / demo
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    scm = StructuralCausalModel()
    scm.reset()

    # Set evidence: PoC published, high CVE
    scm.set_node("PoC_Published", 0.9)
    scm.set_node("CVE_Score", 8.5)
    scm.set_node("DarkWeb_Mention", 0.6)
    scm.set_node("Social_Media_Signal", 0.7)

    print("=== SCM Summary ===")
    print(scm.summary())

    print("\n=== Forward Simulation (5 steps) ===")
    traj = scm.forward(5)
    for i, state in enumerate(traj):
        print(f"  t={i}: IP_Scans={state.get('IP_Scans', 0):.4f}, "
              f"Exploit={state.get('Exploit_Availability', 0):.4f}, "
              f"Incident={state.get('Incident_Probability', 0):.4f}")

    print("\n=== do(Patch_Rate=0.9) ===")
    result = scm.do_intervention("Patch_Rate", 0.9, steps=5)
    print(f"  A2P Abduction: {result['a2p']['abduction']['top_concern']}")
    print(f"  A2P Action:    {result['a2p']['action']['description']}")
    print(f"  A2P Predict:   {result['a2p']['prediction']['affected_nodes']}")
    print(f"  Delta IP_Scans: {result['delta'].get('IP_Scans', 0):+.4f}")
    print(f"  Delta Incident: {result['delta'].get('Incident_Probability', 0):+.4f}")

    print("\n=== ACE: CVE_Score → Incident_Probability ===")
    ace = scm.estimate_causal_effect("CVE_Score", "Incident_Probability", [3.0, 9.0], steps=5, trials=10)
    print(f"  {ace['interpretation']}")
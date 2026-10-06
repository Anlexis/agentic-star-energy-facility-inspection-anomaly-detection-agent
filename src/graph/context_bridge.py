"""AgentCore Platform v1.0"""

# src/graph/context_bridge.py — carries the outer graph's per-invocation handoff
# across the outer→inner graph boundary.
#
# Why this exists: GraphNode.execute() (framework) invokes the inner graph as
# `subgraph.invoke(user_input, session_id=..., ctx=...)`. Only `user_input` and
# the invocation context cross that call — the outer state does not. So without
# a bridge the inner nodes see:
#
#   input_context      → {}   (the caller's structured parameters are lost)
#   equipment_type     → None (the type the outer validator detected is lost,
#                              so every report silently falls back to the
#                              "unknown" baseline set and only the generic
#                              temperature threshold is ever applied)
#   inspection_settings → {}  (the validated caller overrides are lost)
#
# The sanctioned subclass hooks bridge it:
#
#   FacilityInspectionGraphNode.extract_input(state)   [runs BEFORE subgraph.invoke]
#       → set_graph_handoff(state)
#   DomainWorkflowGraph._extra_initial_state()         [runs INSIDE subgraph.invoke]
#       → returns get_graph_handoff()
#
# A ContextVar keeps the hand-off correct per thread/task, so concurrent
# invocations in one process cannot see each other's handoff.

from contextvars import ContextVar
from typing import Any, Dict, Optional

# The outer-state keys the inner graph needs. Everything else stays in the
# outer layer: this is a narrow, explicit hand-off, not a state mirror.
HANDOFF_KEYS = ("input_context", "equipment_type", "inspection_settings")

_GRAPH_HANDOFF: ContextVar[Optional[Dict[str, Any]]] = ContextVar("ene_c2_011_graph_handoff", default=None)


def set_graph_handoff(state: Dict[str, Any]) -> None:
    """Stash the outer state's handoff keys for the imminent inner-graph invoke."""
    handoff: Dict[str, Any] = {}
    for key in HANDOFF_KEYS:
        value = state.get(key)
        handoff[key] = dict(value) if isinstance(value, dict) else value
    _GRAPH_HANDOFF.set(handoff)


def get_graph_handoff() -> Dict[str, Any]:
    """Read (without consuming) the stashed handoff.

    Returns a dict with every handoff key present — `input_context` and
    `inspection_settings` default to `{}` and `equipment_type` to `"unknown"`,
    so an inner graph built standalone (no outer layer) still runs on the
    documented defaults instead of raising.
    """
    stashed = _GRAPH_HANDOFF.get() or {}
    return {
        "input_context": stashed.get("input_context") or {},
        "equipment_type": stashed.get("equipment_type") or "unknown",
        "inspection_settings": stashed.get("inspection_settings") or {},
    }

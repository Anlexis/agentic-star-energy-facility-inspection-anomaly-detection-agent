"""AgentCore Platform v1.0"""

# ENE-C2-011 — Outer graph (AgentBaseGraph; Cat 2 two-layer nested architecture)
#
# Architecture (Cat 2):
#
#   Outer backbone (fixed — identical to Cat 1, do NOT override add_edges()):
#     START → initialize → pre_process → main → {route} → post_process → finalize → END
#                                             ↓ (RETRY, max 3)
#                                          pre_process
#
#   `main` slot is a GraphNode subclass (FacilityInspectionGraphNode) that
#   delegates the full domain workflow to DomainWorkflowGraph (inner BaseGraph).
#
#   Domain complexity is fully encapsulated inside the inner graph. The outer
#   backbone is never modified.
#
# Directory layout:
#   src/graph/graph.py                 ← outer graph (this file)
#   src/graph/domain_workflow_graph.py ← inner graph (multi-step topology)
#   src/graph/context_bridge.py        ← outer→inner per-invocation handoff
#
# Rules enforced:
#   ✅ FacilityInspectionAnomalyDetectionAgent inherits AgentBaseGraph
#   ✅ super().register_nodes() called first (fills initialize + finalize)
#   ✅ FacilityInspectionGraphNode assigned to self._nodes["main"]
#   ✅ merge_output() returns only changed keys
#   ✅ class name matches config/agent.yaml `class:` and src/api/server.py import
#   ❌ add_edges() NOT overridden on the outer graph
#   ❌ No platform-SDK imports

import math
import pathlib
from typing import Any, ClassVar, Dict, Optional

from framework.schemas.agent_status import AgentStatus
from framework.graph.agent_base_graph import AgentBaseGraph
from framework.nodes.graph_node import GraphNode
from framework.schemas.agent_state import AgentState
from src.graph.context_bridge import set_graph_handoff
from src.nodes.security_gate_output_node import SecurityGateOutputNode
from src.nodes.validate_input_node import ValidateInputNode
from src.schemas.state import State

# Runtime parameters live in config/config.yaml — the same file the platform
# registry loads and passes as Graph(config=...). config/agent.yaml is the
# static manifest and carries no runtime block.
_RUNTIME_CONFIG_PATH = pathlib.Path(__file__).resolve().parents[2] / "config" / "config.yaml"

# Bounds for the declared severity thresholds. A threshold outside these is a
# configuration error; the node default is used instead of a nonsense value.
_DEVIATION_MIN = 0.0
_DEVIATION_MAX = 1000.0


def _runtime_config() -> Dict[str, Any]:
    """Read the runtime parameters from config/config.yaml.

    The standalone server (src/api/server.py) reads this so a deployed agent
    and a registry-loaded agent see identical configuration. Returns an empty
    dict — never raises — when the file is absent, unreadable, not valid YAML,
    or not a mapping; the graph then runs on its built-in defaults.
    """
    try:
        import yaml

        loaded = yaml.safe_load(_RUNTIME_CONFIG_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {}
    if not isinstance(loaded, dict):
        return {}
    return loaded


def _config_number(value: Any, lo: float, hi: float) -> Optional[float]:
    """Validate a declared numeric setting: a real, finite number within [lo, hi].

    Bools, strings, non-numerics, NaN/Infinity and out-of-range values return
    None, and the consumer keeps its built-in default. The non-finite case is
    the dangerous one: NaN comparisons are always False, so a NaN deviation
    threshold would classify every reading as within tolerance and silently
    suppress every alert this agent exists to raise.
    """
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    number = float(value)
    if not math.isfinite(number) or not lo <= number <= hi:
        return None
    return number


class FacilityInspectionGraphNode(GraphNode):
    """GraphNode subclass assigned to the `main` slot of FacilityInspectionAnomalyDetectionAgent.

    Wraps DomainWorkflowGraph (inner Cat 2 BaseGraph).
    Called by AgentBaseGraph backbone after pre_process and before post_process.

    Contracts:
      get_subgraph()    — instantiate and return DomainWorkflowGraph
      extract_input()   — pass validated_input into the inner graph and bridge
                          the outer handoff (see src/graph/context_bridge.py)
      merge_output()    — map sub_result fields into outer state delta (changed keys only)
      error_strategy    — "propagate": re-raise inner errors as SubgraphError (fail-fast)
    """

    # "propagate": re-raise inner graph exceptions as SubgraphError (default — fail fast).
    # "handle": call on_subgraph_error() instead — use for graceful degradation.
    error_strategy: ClassVar[str] = "propagate"

    # False: HITL interrupts are handled inside the inner graph only.
    # True: surface inner HITL interrupt to the outer caller.
    propagate_hitl: ClassVar[bool] = False

    def get_subgraph(self) -> Any:
        """Instantiate and return the inner domain workflow graph.

        DomainWorkflowGraph is imported lazily (inside the method) to avoid
        circular-import risk at module load time and to match the Cat 2 pattern.
        The declared runtime settings are forwarded so the thresholds in
        config/config.yaml actually reach the domain nodes.
        """
        from src.graph.domain_workflow_graph import DomainWorkflowGraph

        return DomainWorkflowGraph(config=self._parent_config())

    def execute(self, state: AgentState) -> dict[str, Any]:
        """Skip the inner graph when the request was already found unacceptable.

        A request declined by pre_process has no validated input to act on, so
        running the inner graph would only produce a second, vaguer reason for
        the same rejection - and overwrite the specific one already settled.
        """
        marker = state.get("error_code")
        if marker:
            return {"status": AgentStatus.SUCCESS.value, "error_code": marker}
        result: dict[str, Any] = super().execute(state)
        return result

    def extract_input(self, state: AgentState) -> str:
        """Return the string input passed into inner_graph.invoke().

        ValidateInputNode validates and sanitizes the raw user_input and writes
        the result to validated_input.

        This is also the last hook in this repo's code that sees the outer
        state before the inner invoke, so it bridges the per-invocation handoff
        (caller input_context, resolved equipment type, validated caller
        overrides) — the framework forwards none of them on subgraph.invoke().
        See src/graph/context_bridge.py.
        """
        set_graph_handoff(dict(state))
        validated = state.get("validated_input")
        if isinstance(validated, str) and validated:
            return validated
        user_input = state.get("user_input", "")
        return user_input if isinstance(user_input, str) else ""

    def merge_output(self, state: AgentState, sub_result: Dict[str, Any]) -> Dict[str, Any]:
        """Map inner graph sub_result back into the outer state delta.

        sub_result is the dict returned by DomainWorkflowGraph.get_output().
        Returns ONLY changed keys — never the full state.

        Key coupling (designed together with DomainWorkflowGraph.get_output()):
          Inner get_output()   emits: "result", "anomaly_alert", "has_critical",
                                      "status", "trace_id", "correlation_id",
                                      "node_history"
          This merge_output() reads: sub_result.get("result"),
                                     sub_result.get("anomaly_alert"),
                                     sub_result.get("has_critical"),
                                     sub_result.get("status")

        result (str | None): JSON-serialized anomaly alert from GenerateAnomalyAlertNode.
          Mapped to state["result"] so SecurityGateOutputNode (outer post_process)
          can apply the output boundary to the alert.
        anomaly_alert (dict | None): the structured alert; the output boundary
          enforces the rendering schema on this dict and re-serializes it.
        has_critical (bool): propagated to outer state for FinalizeNode.
        status (str | None): terminal AgentStatus value from the inner graph run.
        """
        return {
            # Outer reason wins: a reason settled before the inner run is the real
            # one, and a plain sub_result.get() would erase it.
            "error_code": state.get("error_code") or sub_result.get("error_code", ""),
            "result": sub_result.get("result"),
            "anomaly_alert": sub_result.get("anomaly_alert"),
            "has_critical": sub_result.get("has_critical", False),
            "status": sub_result.get("status"),
        }

    @staticmethod
    def _parent_config() -> Dict[str, Any]:
        """Forward the declared runtime settings to the inner graph.

        Reads config/config.yaml (see _runtime_config) and returns a flat
        settings dict that DomainWorkflowGraph.register_nodes() injects into the
        domain node constructors. Constructor injection is the config route
        because the node contract is ``execute(self, state) -> dict`` — a node
        never receives a per-invocation config argument, so a node that reads
        one is reading a value that is always absent.

        Every forwarded value is validated here (type, finiteness, range) so a
        malformed configuration file can neither crash graph construction nor
        weaken the severity classification. Invalid or absent keys are simply
        not forwarded and the node keeps its module default.
        """
        cfg = _runtime_config()
        severity_raw = cfg.get("severity")
        severity: Dict[str, Any] = severity_raw if isinstance(severity_raw, dict) else {}

        settings: Dict[str, Any] = {}
        for key in ("critical_deviation_pct", "warning_deviation_pct"):
            number = _config_number(severity.get(key), _DEVIATION_MIN, _DEVIATION_MAX)
            if number is not None and number > _DEVIATION_MIN:
                settings[key] = number

        # A warning threshold above the critical threshold would make the
        # warning band unreachable; drop the pair rather than run inverted.
        critical = settings.get("critical_deviation_pct")
        warning = settings.get("warning_deviation_pct")
        if critical is not None and warning is not None and warning > critical:
            settings.pop("warning_deviation_pct")

        return settings


class FacilityInspectionAnomalyDetectionAgent(AgentBaseGraph):
    """Outer graph for ENE-C2-011 (Cat 2).

    Inherits AgentBaseGraph directly (L1 Base). Domain logic is fully
    encapsulated in FacilityInspectionGraphNode (main slot), which delegates
    to DomainWorkflowGraph (inner BaseGraph).

    Backbone (fixed — identical to Cat 1):
        START → initialize → pre_process → main → post_process → finalize → END

    register_nodes() is the ONLY override:
      - super().register_nodes() fills: initialize, finalize (framework defaults)
      - pre_process:  ValidateInputNode (input validation + caller contract)
      - main:         FacilityInspectionGraphNode (delegates to DomainWorkflowGraph)
      - post_process: SecurityGateOutputNode (output boundary + audit log)

    add_edges() is NOT overridden — backbone wiring belongs to the framework.

    Class name MUST match:
      - config/agent.yaml `class: src.graph.graph.FacilityInspectionAnomalyDetectionAgent`
      - src/api/server.py `from src.graph.graph import FacilityInspectionAnomalyDetectionAgent`
    """

    @property
    def name(self) -> str:
        """Agent identifier registered with the platform registry."""
        return "ene_c2_011"

    @property
    def state_schema(self) -> type:
        return State

    def register_nodes(self) -> None:
        """Fill all 5 backbone slots.

        super().register_nodes() MUST be called first — it injects the
        framework's default InitializeNode (sets schema_version, session_id,
        trust_level) and FinalizeNode (builds response_metadata, total_time_ms).
        """
        super().register_nodes()  # fills: initialize, finalize

        self._nodes["pre_process"] = ValidateInputNode()
        self._nodes["main"] = FacilityInspectionGraphNode()
        self._nodes["post_process"] = SecurityGateOutputNode()

    def _enrich_output(self, output: Dict[str, Any], result: Dict[str, Any]) -> None:
        """Surface the domain result fields alongside the framework's output keys.

        The framework's output carries `output` (the gated alert JSON), status
        and the trace ids. Callers of this agent act on the alert itself, so the
        parsed alert and the critical flag are surfaced too — they are the two
        fields an operations pipeline routes on, and re-parsing the JSON string
        to recover them would push that cost onto every caller.
        """
        output["anomaly_alert"] = result.get("anomaly_alert")
        output["has_critical"] = bool(result.get("has_critical", False))
        output["out_of_scope"] = bool(result.get("out_of_scope", False))

    # add_edges() is NOT overridden — backbone wiring belongs to the framework.


# Back-compat alias — callers may reference either name.
Graph = FacilityInspectionAnomalyDetectionAgent

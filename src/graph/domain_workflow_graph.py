"""AgentCore Platform v1.0"""

# ENE-C2-011 — DomainWorkflowGraph (inner BaseGraph)
#
# This is the INNER graph for the Cat 2 two-layer nested architecture.
# It encapsulates the full facility inspection anomaly detection domain workflow:
#
#   START → load_baseline_parameters → parse_sensor_data → parse_field_notes
#         → detect_anomalies → check_mandatory_items → assess_severity
#         → generate_anomaly_alert → END
#
# Called by FacilityInspectionGraphNode.get_subgraph() (graph.py).
# get_output() shapes the sub_result dict consumed by merge_output() there.
#
# The framework invokes an inner graph as subgraph.invoke(user_input, ...), so
# nothing else from the outer state crosses the boundary. _extra_initial_state()
# seeds the per-invocation handoff (caller input_context, resolved equipment
# type, validated caller overrides) from src/graph/context_bridge.py, and the
# declared runtime settings arrive as this graph's `config`.
#
# Rules enforced:
#   ✅ Inherits BaseGraph (fully custom topology — no forced backbone)
#   ✅ Implements all 7 BaseGraph ABC methods
#   ✅ register_nodes() does NOT call super() (abstract in BaseGraph)
#   ✅ Does NOT register initialize / finalize (outer backbone concerns)
#   ✅ get_output() designed together with FacilityInspectionGraphNode.merge_output()
#   ❌ No platform-SDK imports
#   ❌ Not placed under src/subagents/

from typing import Any, Dict

from langgraph.graph import END, START

from framework.graph.base_graph import BaseGraph
from framework.schemas.agent_state import AgentState
from framework.schemas.agent_status import AgentStatus
from src.graph.context_bridge import get_graph_handoff
from src.nodes.assess_severity_node import AssessSeverityNode
from src.nodes.check_mandatory_items_node import CheckMandatoryItemsNode
from src.nodes.detect_anomalies_node import DetectAnomaliesNode
from src.nodes.generate_anomaly_alert_node import GenerateAnomalyAlertNode
from src.nodes.load_baseline_parameters_node import LoadBaselineParametersNode
from src.nodes.parse_field_notes_node import ParseFieldNotesNode
from src.nodes.parse_sensor_data_node import ParseSensorDataNode
from src.schemas.state import State


class DomainWorkflowGraph(BaseGraph):
    """Inner domain workflow graph for ENE-C2-011.

    Inherits BaseGraph directly for a fully custom node topology.
    Called by FacilityInspectionGraphNode.get_subgraph() in graph.py.

    Pipeline (linear):
        START
          → load_baseline_parameters  (LoadBaselineParametersNode)
          → parse_sensor_data         (ParseSensorDataNode)
          → parse_field_notes         (ParseFieldNotesNode)
          → detect_anomalies          (DetectAnomaliesNode)
          → check_mandatory_items     (CheckMandatoryItemsNode)
          → assess_severity           (AssessSeverityNode)
          → generate_anomaly_alert    (GenerateAnomalyAlertNode)
          → END

    All nodes are FunctionNode subclasses returning partial-dict state updates.
    initialize / finalize are outer backbone concerns — not registered here.
    """

    # ── Identity ──────────────────────────────────────────────────────────────

    @property
    def name(self) -> str:
        """Unique identifier for this inner graph."""
        return "ene_c2_011_domain_workflow"

    @property
    def state_schema(self) -> type:
        """TypedDict subclass shared across inner and outer graph."""
        return State

    # ── Config validation ─────────────────────────────────────────────────────

    def _validate_config(self) -> None:
        """Validate inner graph config before compilation.

        No mandatory keys: every setting forwarded by
        FacilityInspectionGraphNode._parent_config() has already been checked
        for type, finiteness and range there, and an absent setting simply
        leaves the owning node on its documented built-in default.
        """
        pass

    # ── Per-invocation handoff ────────────────────────────────────────────────

    def _extra_initial_state(self) -> Dict[str, Any]:
        """Seed the outer graph's per-invocation handoff into the inner state.

        The framework calls subgraph.invoke(user_input, session_id=..., ctx=...)
        and forwards nothing else from the outer state, so without this hook the
        inner nodes would see no caller input_context, no resolved equipment
        type (every report would score against the generic fallback baseline)
        and no validated caller overrides. See src/graph/context_bridge.py.
        """
        handoff = get_graph_handoff()
        return {
            "input_context": handoff["input_context"],
            "equipment_type": handoff["equipment_type"],
            "inspection_settings": handoff["inspection_settings"],
        }

    # ── Node registration ─────────────────────────────────────────────────────

    def register_nodes(self) -> None:
        """Register all 7 domain nodes.

        No super() call — BaseGraph.register_nodes() is abstract.
        Do NOT register initialize or finalize; those are outer backbone
        concerns handled by AgentBaseGraph in graph.py.
        Every key registered here is referenced in add_edges().

        Config injection: the node contract is ``execute(self, state) -> dict``
        — a node never receives a per-invocation config argument. The one
        config-driven node therefore takes the declared settings (read from
        config/config.yaml and forwarded by
        FacilityInspectionGraphNode._parent_config() into this graph's
        `config`) through its constructor. Built standalone
        (``DomainWorkflowGraph()``), `self.config` is empty and the node falls
        back to its module defaults.
        """
        settings: Dict[str, Any] = self.config or {}

        self._nodes["load_baseline_parameters"] = LoadBaselineParametersNode()
        self._nodes["parse_sensor_data"] = ParseSensorDataNode()
        self._nodes["parse_field_notes"] = ParseFieldNotesNode()
        self._nodes["detect_anomalies"] = DetectAnomaliesNode()
        self._nodes["check_mandatory_items"] = CheckMandatoryItemsNode()
        self._nodes["assess_severity"] = AssessSeverityNode(config=settings)
        self._nodes["generate_anomaly_alert"] = GenerateAnomalyAlertNode()

    # ── Edge wiring ───────────────────────────────────────────────────────────

    def add_edges(self) -> None:
        """Wire the linear facility inspection anomaly detection domain topology.

        Each step passes its partial-dict output into the shared State.
        The topology is intentionally linear — no conditional branching
        between domain nodes. route() is implemented as required by the ABC
        but add_conditional_edges() is not used.

        Flow:
          load_baseline_parameters → parse_sensor_data → parse_field_notes
                                   → detect_anomalies → check_mandatory_items
                                   → assess_severity → generate_anomaly_alert
        """
        self._sg.add_edge(START, "load_baseline_parameters")
        self._sg.add_edge("load_baseline_parameters", "parse_sensor_data")
        self._sg.add_edge("parse_sensor_data", "parse_field_notes")
        self._sg.add_edge("parse_field_notes", "detect_anomalies")
        self._sg.add_edge("detect_anomalies", "check_mandatory_items")
        self._sg.add_edge("check_mandatory_items", "assess_severity")
        self._sg.add_edge("assess_severity", "generate_anomaly_alert")
        self._sg.add_edge("generate_anomaly_alert", END)

    # ── Routing ───────────────────────────────────────────────────────────────

    def route(self, state: AgentState) -> str:
        """Conditional routing — required by BaseGraph ABC.

        For this linear topology add_conditional_edges() is not used, so this
        method is never called at runtime. It is implemented to satisfy the ABC
        contract. Returns END on error so an unexpected call does not re-enter
        a processing node.
        """
        if state.get("status") == AgentStatus.ERROR.value:
            return END
        return "generate_anomaly_alert"

    # ── Output shape ──────────────────────────────────────────────────────────

    def get_output(self, state: AgentState) -> Dict[str, Any]:
        """Shape the output dict returned to the outer graph as sub_result.

        This dict is received by FacilityInspectionGraphNode.merge_output()
        in graph.py as the `sub_result` argument. Both methods are designed
        together to guarantee field-name consistency:

            Inner get_output()   emits: "result", "anomaly_alert", "status",
                                        "has_critical", "trace_id",
                                        "correlation_id", "node_history"
            Outer merge_output() reads: sub_result.get("result"),
                                        sub_result.get("anomaly_alert"),
                                        sub_result.get("status"),
                                        sub_result.get("has_critical")
        """
        return {
            # the reason must leave the subgraph or the outer graph cannot report it
            "error_code": state.get("error_code"),
            "result": state.get("result"),
            "anomaly_alert": state.get("anomaly_alert"),
            "has_critical": state.get("has_critical", False),
            "status": state.get("status"),
            "trace_id": state.get("trace_id"),
            "correlation_id": state.get("correlation_id"),
            "node_history": state.get("node_history", []),
        }

    # ── Lifecycle helpers ─────────────────────────────────────────────────────

    def get_state_class(self) -> type:
        """Return the State TypedDict used by both inner and outer graphs."""
        return State

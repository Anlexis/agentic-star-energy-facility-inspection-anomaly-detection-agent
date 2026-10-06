"""AgentCore Platform v1.0"""

# State must be a flat TypedDict — never a Pydantic BaseModel. Graph
# checkpoints use msgpack serialization; Pydantic objects cause silent
# corruption. Extend AgentState with agent-specific fields only. Do NOT add
# credentials, secrets, or Pydantic models.
#
# ENE-C2-011 — Energy Facility Inspection Report Anomaly Detection Agent
# Two-layer nested Cat 2 graph: outer backbone (AgentBaseGraph) + inner
# domain workflow (BaseGraph).  Fields below cover both layers.
#
# Facility data note: sensor readings and field notes may contain sensitive
# facility topology / equipment configuration information.
# Nodes must never log raw sensor payloads — audit payloads carry counts,
# flags and identifiers only.

from typing import Any, Dict, List, Optional

from framework.schemas.agent_state import AgentState


class State(AgentState):
    """Flat TypedDict for ENE-C2-011.

    All shared fields (user_input, status, session_id, node_history,
    error_log, hitl_*, etc.) are inherited from AgentState.
    """

    # ------------------------------------------------------------------
    # Outer layer — ValidateInputNode (pre_process slot)
    # ------------------------------------------------------------------

    # Validated inspection report text produced by ValidateInputNode.
    # Raw user_input is not persisted beyond ValidateInputNode.
    validated_input: Optional[str]

    # Equipment type for this run: the caller's validated selector when one was
    # supplied, otherwise the type detected from the report header.
    # Used by LoadBaselineParametersNode to select the correct thresholds.
    # One of: 変電設備 (substation), 送電線 (transmission), 発電設備 (generation),
    # 石油精製設備 (refinery), or "unknown".
    equipment_type: Optional[str]

    # The caller's validated input_context overrides for this run, as returned
    # by src/nodes/caller_context.py: equipment selector, deviation thresholds,
    # per-sensor baseline overrides and mandatory item codes. Empty when the
    # caller supplied none. Never contains raw caller values — every entry has
    # passed the finite/bounded/inert checks.
    inspection_settings: Optional[Dict[str, Any]]

    # ------------------------------------------------------------------
    # Inner domain workflow — LoadBaselineParametersNode
    # ------------------------------------------------------------------

    # Baseline parameters keyed by equipment type and sensor name, built from
    # the built-in defaults with the caller's validated overrides applied.
    # Example: {"変電設備": {"temperature_c": {"min": 0, "max": 80, "warning": 70},
    #                        "voltage_kv": {"min": 95, "max": 115, "warning": 110}}}
    # Written by LoadBaselineParametersNode; read by ParseSensorDataNode.
    baseline_parameters: Optional[Dict[str, Any]]

    # ------------------------------------------------------------------
    # Inner domain workflow — ParseSensorDataNode
    # ------------------------------------------------------------------

    # Parsed sensor readings extracted from the structured section of the
    # inspection report.  Each entry: {"sensor": str, "value": float,
    # "unit": str, "timestamp": str}.
    # Written by ParseSensorDataNode; read by DetectAnomaliesNode.
    sensor_readings: Optional[List[Dict[str, Any]]]

    # Sensor readings that exceeded tolerance thresholds against baseline.
    # Each entry: {"sensor": str, "value": float, "threshold": float,
    # "deviation": float, "direction": "above"|"below"}.
    # Written by ParseSensorDataNode; read by DetectAnomaliesNode.
    sensor_anomalies: Optional[List[Dict[str, Any]]]

    # ------------------------------------------------------------------
    # Inner domain workflow — ParseFieldNotesNode
    # ------------------------------------------------------------------

    # Extracted observations from field notes text (NLP extraction).
    # Each entry: {"observation": str, "equipment_ref": str, "severity_hint": str}.
    # Written by ParseFieldNotesNode; read by DetectAnomaliesNode.
    field_note_observations: Optional[List[Dict[str, Any]]]

    # ------------------------------------------------------------------
    # Inner domain workflow — DetectAnomaliesNode
    # ------------------------------------------------------------------

    # Unified anomaly list cross-referencing sensor readings and field notes
    # against baseline parameters.
    # Each entry: {"anomaly_id": str, "source": "sensor"|"field_note"|"both",
    # "equipment_ref": str, "description": str, "deviation_pct": float}.
    # Written by DetectAnomaliesNode; read by AssessSeverityNode.
    detected_anomalies: Optional[List[Dict[str, Any]]]

    # ------------------------------------------------------------------
    # Inner domain workflow — CheckMandatoryItemsNode
    # ------------------------------------------------------------------

    # List of mandatory inspection items missing from the report.
    # Each entry: {"item_code": str, "description": str, "equipment_ref": str}.
    # Written by CheckMandatoryItemsNode; read by GenerateAnomalyAlertNode.
    missing_mandatory_items: Optional[List[Dict[str, Any]]]

    # True when all mandatory inspection items are present in the report.
    # A False value causes the alert to include a compliance warning.
    mandatory_check_passed: bool

    # ------------------------------------------------------------------
    # Inner domain workflow — AssessSeverityNode
    # ------------------------------------------------------------------

    # Per-anomaly severity assessments.
    # Each entry: {"anomaly_id": str, "severity": "critical"|"warning"|"info",
    # "rationale": str, "equipment_ref": str, "description": str}.
    # Written by AssessSeverityNode; read by GenerateAnomalyAlertNode.
    severity_assessments: Optional[List[Dict[str, Any]]]

    # True when at least one detected anomaly is classified as critical.
    # Critical anomalies are non-suppressible (GX推進法 / 電気事業法 §§).
    has_critical: bool

    # ------------------------------------------------------------------
    # Inner domain workflow — GenerateAnomalyAlertNode
    # ------------------------------------------------------------------

    # Structured anomaly alert dict produced by GenerateAnomalyAlertNode and
    # re-enforced against the published rendering schema by SecurityGateOutputNode.
    # Keys: "alert_id" (str), "equipment_type" (str),
    # "anomaly_count" (int), "has_critical" (bool),
    # "severity_summary" (dict: critical/warning/info counts),
    # "anomalies" (list of severity_assessments),
    # "missing_items" (list of missing_mandatory_items),
    # "baseline_deviations" (list of sensor_anomalies),
    # "recommendations" (list of str),
    # "rendering_schema" (dict: the bounds the alert was rendered under).
    # Written by GenerateAnomalyAlertNode; consumed by SecurityGateOutputNode.
    anomaly_alert: Optional[Dict[str, Any]]

    # ------------------------------------------------------------------
    # Outer layer — SecurityGateOutputNode (post_process slot)
    # ------------------------------------------------------------------

    # The serialized anomaly alert as published by SecurityGateOutputNode,
    # after the output boundary screened it and applied the rendering bounds.
    # Consumed by FinalizeNode for the caller response.
    formatted_output: Optional[str]

    # ------------------------------------------------------------------
    # Control / routing flags
    # ------------------------------------------------------------------

    # True when the inspection report falls outside the supported domain.
    # Out-of-scope is NOT a separate AgentStatus — status stays SUCCESS,
    # and the anomaly_alert will be None.
    out_of_scope: bool

    # ------------------------------------------------------------------
    # Status and audit — populated by all nodes
    # ------------------------------------------------------------------

    # AgentStatus string value set by each node.
    status: Optional[str]

    # Accumulated error messages appended by any node that catches an exception.
    error_log: List[str]

    # ------------------------------------------------------------------
    # Tracing / audit
    # ------------------------------------------------------------------

    # Trace ID injected by InitializeNode for audit log correlation.
    # Every emit_trace_event() call includes this for the 電気事業法 audit trail.
    trace_id: Optional[str]

    # Correlation ID for cross-system tracing (matches InvocationContext).
    correlation_id: Optional[str]
    error_code: Optional[str]

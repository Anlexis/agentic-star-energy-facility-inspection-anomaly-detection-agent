"""AgentCore Platform v1.0"""

# Node contract:
#  - Extend FunctionNode; implement execute(state) -> dict
#  - Return ONLY the fields this node changes (never full state)
#  - Return the status as AgentStatus.<X>.value — the enum's string value,
#    not the enum object itself
#  - Never import from mediator/, api/, or other agents
#
# ENE-C2-011 — DetectAnomaliesNode
# Inner DomainWorkflowGraph node 4: unify sensor anomalies and field note
# observations into a single detected anomaly list, applying cross-reference
# logic to identify corroborated anomalies (same equipment, both signal types).
#
# Input state keys:
#   equipment_type:          str — canonical equipment type
#   sensor_anomalies:        list[dict] — from ParseSensorDataNode
#   field_note_observations: list[dict] — from ParseFieldNotesNode
#
# Output state keys (partial dict):
#   detected_anomalies: list[dict] — unified anomaly list
#   status: AgentStatus string value
#   error_log: list[str] — accumulated errors

import logging
import uuid
from typing import Any, ClassVar, Dict, List

from framework.nodes.function_node import FunctionNode
from framework.schemas.agent_status import AgentStatus
from framework.schemas.trust_level import TrustLevel

from shared.utils.audit_logger import emit_trace_event

logger = logging.getLogger(__name__)


def _short_id() -> str:
    """Return a short anomaly ID (8 hex chars from UUID4)."""
    return uuid.uuid4().hex[:8].upper()


def _build_sensor_anomalies(sensor_anomalies: List[Dict[str, Any]], equipment_type: str) -> List[Dict[str, Any]]:
    """Convert sensor anomaly dicts into unified anomaly entries."""
    result: List[Dict[str, Any]] = []
    for sa in sensor_anomalies:
        result.append(
            {
                "anomaly_id": _short_id(),
                "source": "sensor",
                "equipment_ref": equipment_type,
                "sensor": sa.get("sensor", ""),
                "description": (
                    f"Sensor '{sa.get('sensor', '')}' reads {sa.get('value', '')} "
                    f"{sa.get('unit', '')} — {sa.get('direction', 'above/below')} "
                    f"threshold {sa.get('threshold', '')} "
                    f"by {sa.get('deviation_pct', 0):.1f}%"
                ),
                "deviation_pct": sa.get("deviation_pct", 0.0),
                "severity_hint": sa.get("severity_hint", "warning"),
            }
        )
    return result


def _build_field_note_anomalies(
    observations: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Convert field note observations into unified anomaly entries."""
    result: List[Dict[str, Any]] = []
    for obs in observations:
        result.append(
            {
                "anomaly_id": _short_id(),
                "source": "field_note",
                "equipment_ref": obs.get("equipment_ref", "unknown"),
                "sensor": "",
                "description": obs.get("observation", ""),
                "deviation_pct": 0.0,
                "severity_hint": obs.get("severity_hint", "info"),
            }
        )
    return result


def _merge_corroborated(
    sensor_anomalies: List[Dict[str, Any]],
    field_note_anomalies: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Merge sensor and field-note anomalies.

    When both sources reference the same equipment, upgrade the severity of the
    corroborated anomaly (sensor already flagged + field note confirms = escalate).
    Currently appends both lists; corroboration is noted via source="both".
    """
    # Build a set of equipment_refs from field notes for cross-reference.
    fn_refs = {a["equipment_ref"].lower() for a in field_note_anomalies}

    merged: List[Dict[str, Any]] = []

    for sa in sensor_anomalies:
        eq_ref = sa["equipment_ref"].lower()
        corroborated = any(fn_ref in eq_ref or eq_ref in fn_ref for fn_ref in fn_refs)
        if corroborated:
            # Upgrade source tag; keep sensor's severity_hint (already calibrated).
            entry = dict(sa)
            entry["source"] = "both"
            entry["description"] += " [corroborated by field notes]"
            merged.append(entry)
        else:
            merged.append(sa)

    # Add field note anomalies that are NOT already corroborated.
    sensor_refs = {a["equipment_ref"].lower() for a in merged}
    for fna in field_note_anomalies:
        eq_ref = fna["equipment_ref"].lower()
        already_merged = any(sr in eq_ref or eq_ref in sr for sr in sensor_refs) and fna.get("source") != "field_note"
        if not already_merged:
            merged.append(fna)

    return merged


# ---------------------------------------------------------------------------
# Node
# ---------------------------------------------------------------------------


class DetectAnomaliesNode(FunctionNode):
    """Unify sensor anomalies + field note observations into a detected anomaly list.

    Inner DomainWorkflowGraph node 4 for ENE-C2-011.

    Combines the outputs of ParseSensorDataNode and ParseFieldNotesNode.
    Cross-references to identify corroborated anomalies (same equipment appearing
    in both sensor data AND field notes) — corroborated entries are tagged
    source="both" and their description is annotated.

    Output (partial dict — only changed keys):
        detected_anomalies, status, error_log.
    """

    required_trust_level: ClassVar[TrustLevel] = TrustLevel.ANONYMOUS

    def execute(self, state: Dict[str, Any]) -> Dict[str, Any]:
        error_log: List[str] = list(state.get("error_log") or [])
        equipment_type: str = state.get("equipment_type") or "unknown"
        raw_sensor_anomalies: List[Dict[str, Any]] = list(state.get("sensor_anomalies") or [])
        raw_field_observations: List[Dict[str, Any]] = list(state.get("field_note_observations") or [])

        # ------------------------------------------------------------------
        # 1. Build unified entries from each source.
        # ------------------------------------------------------------------
        sensor_entries = _build_sensor_anomalies(raw_sensor_anomalies, equipment_type)
        field_entries = _build_field_note_anomalies(raw_field_observations)

        # ------------------------------------------------------------------
        # 2. Merge with corroboration logic.
        # ------------------------------------------------------------------
        detected = _merge_corroborated(sensor_entries, field_entries)

        # ------------------------------------------------------------------
        # 3. Audit trace.
        # ------------------------------------------------------------------
        emit_trace_event(
            "anomalies_detected",
            {
                "equipment_type": equipment_type,
                "sensor_anomaly_count": len(sensor_entries),
                "field_note_anomaly_count": len(field_entries),
                "total_detected": len(detected),
                "corroborated_count": sum(1 for a in detected if a.get("source") == "both"),
            },
            state,
        )

        logger.info(
            "DetectAnomaliesNode: %d total anomalies (%d sensor, %d field_note, %d corroborated)",
            len(detected),
            len(sensor_entries),
            len(field_entries),
            sum(1 for a in detected if a.get("source") == "both"),
        )

        return {
            "detected_anomalies": detected,
            "status": AgentStatus.SUCCESS.value,
            "error_log": error_log,
        }

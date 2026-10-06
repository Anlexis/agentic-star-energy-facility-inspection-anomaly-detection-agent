"""AgentCore Platform v1.0"""

# Node contract:
#  - Extend FunctionNode; implement execute(state) -> dict
#  - Return ONLY the fields this node changes (never full state)
#  - Return the status as AgentStatus.<X>.value — the enum's string value,
#    not the enum object itself
#  - Never import from mediator/, api/, or other agents
#
# ENE-C2-011 — GenerateAnomalyAlertNode
# Inner DomainWorkflowGraph node 7 (final inner node): produce the structured
# anomaly alert dict from severity assessments and missing mandatory items.
#
# The output anomaly_alert dict is picked up by merge_output() in the outer
# GraphNode (FacilityInspectionGraphNode) and handed to SecurityGateOutputNode,
# which independently re-enforces the rendering bounds applied here.
#
# Input state keys:
#   equipment_type:       str — canonical equipment type
#   severity_assessments: list[dict] — from AssessSeverityNode
#   missing_mandatory_items: list[dict] — from CheckMandatoryItemsNode
#   has_critical:         bool — True if any critical anomaly
#   mandatory_check_passed: bool — True if all mandatory items present
#
# Output state keys (partial dict):
#   anomaly_alert: dict — structured alert
#   result:        str  — JSON serialization of anomaly_alert (for outer merge)
#   status:        AgentStatus string value
#   error_log:     list[str] — accumulated errors

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, ClassVar, Dict, List

from framework.nodes.function_node import FunctionNode
from framework.schemas.agent_status import AgentStatus
from framework.schemas.trust_level import TrustLevel

from shared.utils.audit_logger import emit_trace_event
from src.nodes.output_schema import MAX_RENDERED_FINDINGS, bound_excerpt, order_by_severity

logger = logging.getLogger(__name__)


def _generate_recommendations(
    severity_assessments: List[Dict[str, Any]],
    missing_items: List[Dict[str, Any]],
    equipment_type: str,
    has_critical: bool,
) -> List[str]:
    """Generate human-readable recommendations from the severity assessments.

    Critical findings → immediate action recommendations.
    Warning findings → scheduled inspection recommendations.
    Missing items → compliance action recommendations.
    """
    recs: List[str] = []

    if has_critical:
        recs.append(
            f"【緊急対応】{equipment_type}に重篤な異常を検出しました。"
            " 即時運転停止・点検を推奨します。"
            " (CRITICAL: Immediate shutdown and inspection recommended.)"
        )

    # Sensor-based critical and warning.
    critical_sensors = [
        a["sensor"]
        for a in severity_assessments
        if a["severity"] == "critical" and a.get("source") in ("sensor", "both") and a.get("sensor")
    ]
    if critical_sensors:
        recs.append(
            f"センサー異常 (CRITICAL): {', '.join(set(critical_sensors))}" " — 専門技術者による確認を実施してください。"
        )

    warning_count = sum(1 for a in severity_assessments if a["severity"] == "warning")
    if warning_count > 0:
        recs.append(
            f"警告レベル異常 {warning_count}件を検出。"
            " 次回定期点検時に重点確認を実施してください。"
            f" ({warning_count} warning-level anomalies: schedule priority inspection.)"
        )

    if missing_items:
        codes = [m["item_code"] for m in missing_items]
        recs.append(
            f"必須点検項目が未完了です: {', '.join(codes)}。"
            " GX推進法 / 電気事業法の遵守のため、速やかに実施してください。"
            " (Mandatory inspection items incomplete — complete for regulatory compliance.)"
        )

    if not recs:
        recs.append(
            "異常は検出されませんでした。次回定期点検を予定通り実施してください。"
            " (No anomalies detected. Proceed with scheduled next inspection.)"
        )

    return recs


def _bounded_findings(assessments: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Apply the published rendering bounds to the findings list.

    Free-text excerpts carried out of the report are truncated and the list is
    capped, highest severity first so a critical finding is never dropped. The
    output boundary re-derives both bounds from the alert it receives, so this
    is the producing side of a two-layer rule, not the only enforcement.
    """
    bounded: List[Dict[str, Any]] = []
    for assessment in order_by_severity(assessments)[:MAX_RENDERED_FINDINGS]:
        entry = dict(assessment)
        entry["description"] = bound_excerpt(entry.get("description"))
        bounded.append(entry)
    return bounded


# ---------------------------------------------------------------------------
# Node
# ---------------------------------------------------------------------------


class GenerateAnomalyAlertNode(FunctionNode):
    """Produce the structured anomaly alert from severity assessments.

    Inner DomainWorkflowGraph node 7 (final) for ENE-C2-011.

    Assembles the anomaly_alert dict and serializes it to a JSON string
    in state["result"] so that FacilityInspectionGraphNode.merge_output()
    can pass it cleanly to the outer post_process (SecurityGateOutputNode).

    Output (partial dict — only changed keys):
        anomaly_alert, result, status, error_log.
    """

    required_trust_level: ClassVar[TrustLevel] = TrustLevel.ANONYMOUS

    def execute(self, state: Dict[str, Any]) -> Dict[str, Any]:
        error_log: List[str] = list(state.get("error_log") or [])
        equipment_type: str = state.get("equipment_type") or "unknown"
        severity_assessments: List[Dict[str, Any]] = list(state.get("severity_assessments") or [])
        missing_items: List[Dict[str, Any]] = list(state.get("missing_mandatory_items") or [])
        has_critical: bool = bool(state.get("has_critical", False))
        mandatory_check_passed: bool = bool(state.get("mandatory_check_passed", True))
        sensor_anomalies: List[Dict[str, Any]] = list(state.get("sensor_anomalies") or [])

        # ------------------------------------------------------------------
        # 1. Build severity summary counts.
        # ------------------------------------------------------------------
        severity_summary = {
            "critical": sum(1 for a in severity_assessments if a["severity"] == "critical"),
            "warning": sum(1 for a in severity_assessments if a["severity"] == "warning"),
            "info": sum(1 for a in severity_assessments if a["severity"] == "info"),
        }

        # ------------------------------------------------------------------
        # 2. Generate recommendations.
        # ------------------------------------------------------------------
        recommendations = _generate_recommendations(severity_assessments, missing_items, equipment_type, has_critical)

        # ------------------------------------------------------------------
        # 3. Assemble the structured alert dict.
        # ------------------------------------------------------------------
        alert_id = uuid.uuid4().hex[:12].upper()
        alert_timestamp = datetime.now(tz=timezone.utc).isoformat()
        rendered_findings = _bounded_findings(severity_assessments)

        anomaly_alert: Dict[str, Any] = {
            "alert_id": alert_id,
            "timestamp": alert_timestamp,
            "equipment_type": equipment_type,
            "anomaly_count": len(rendered_findings),
            "has_critical": has_critical,
            "mandatory_check_passed": mandatory_check_passed,
            "severity_summary": severity_summary,
            "anomalies": rendered_findings,
            "missing_items": missing_items,
            "baseline_deviations": sensor_anomalies,
            "recommendations": recommendations,
        }

        # Serialize to JSON for state["result"] — outer merge_output reads this.
        try:
            result_str = json.dumps(anomaly_alert, ensure_ascii=False, default=str)
        except (TypeError, ValueError) as exc:
            return {
                "anomaly_alert": None,
                "result": "",
                "status": AgentStatus.ERROR.value,
                "error_log": error_log + [f"GenerateAnomalyAlertNode: failed to serialize alert — {exc}"],
            }

        # ------------------------------------------------------------------
        # 4. Audit trace (alert metadata only — no raw sensor values).
        # ------------------------------------------------------------------
        emit_trace_event(
            "anomaly_alert_generated",
            {
                "alert_id": alert_id,
                "equipment_type": equipment_type,
                "anomaly_count": len(severity_assessments),
                "has_critical": has_critical,
                "severity_summary": severity_summary,
                "mandatory_check_passed": mandatory_check_passed,
            },
            state,
        )

        logger.info(
            "GenerateAnomalyAlertNode: alert=%s equipment=%s anomalies=%d critical=%s",
            alert_id,
            equipment_type,
            len(severity_assessments),
            has_critical,
        )

        return {
            "anomaly_alert": anomaly_alert,
            "result": result_str,
            "status": AgentStatus.SUCCESS.value,
            "error_log": error_log,
        }

"""AgentCore Platform v1.0"""

# Node contract:
#  - Extend FunctionNode; implement execute(state) -> dict
#  - Return ONLY the fields this node changes (never full state)
#  - Return the status as AgentStatus.<X>.value — the enum's string value,
#    not the enum object itself
#  - Never import from mediator/, api/, or other agents
#
# ENE-C2-011 — AssessSeverityNode
# Inner DomainWorkflowGraph node 6: classify detected anomalies as
# critical / warning / info based on configurable severity rules.
#
# Severity classification rules:
#   critical  — sensor deviation > 20% OR source="both" OR severity_hint="critical"
#               OR missing mandatory GX/regulatory items (non-suppressible per GX推進法)
#   warning   — sensor deviation 5–20% OR severity_hint="warning"
#   info      — deviation < 5% OR source="field_note" with severity_hint="info"
#
# Critical anomalies are non-suppressible (GX推進法 / 電気事業法).
#
# Threshold precedence: caller override (input_context, validated) > declared
# setting (config/config.yaml, validated at graph construction) > module
# default. Every level is checked for finiteness before it is used — a NaN
# threshold compares False against every deviation and would silently classify
# a facility in breach as within tolerance.
#
# Input state keys:
#   detected_anomalies:      list[dict] — from DetectAnomaliesNode
#   missing_mandatory_items: list[dict] — from CheckMandatoryItemsNode
#   equipment_type:          str — canonical equipment type
#   inspection_settings:     dict — validated caller overrides
#
# Output state keys (partial dict):
#   severity_assessments: list[dict] — per-anomaly severity with rationale
#   has_critical:         bool — True if any critical anomaly exists
#   status:               AgentStatus string value
#   error_log:            list[str] — accumulated errors

import logging
import math
from typing import Any, ClassVar, Dict, List, Optional, Tuple

from framework.nodes.function_node import FunctionNode
from framework.schemas.agent_status import AgentStatus
from framework.schemas.trust_level import TrustLevel

from shared.utils.audit_logger import emit_trace_event

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Severity thresholds (module defaults; see the precedence note above).
# ---------------------------------------------------------------------------

_DEFAULT_CRITICAL_DEVIATION_PCT = 20.0  # sensor deviation > 20% → critical
_DEFAULT_WARNING_DEVIATION_PCT = 5.0  # sensor deviation > 5% → warning


def _finite_or(value: Any, fallback: float) -> float:
    """Return *value* as a finite float, or *fallback* when it is not one.

    Every comparison against NaN is False, so a non-finite deviation or
    threshold would classify a facility in breach as within tolerance. Nothing
    in this node compares a number it has not first established is real.
    """
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return fallback
    number = float(value)
    return number if math.isfinite(number) else fallback


def _classify_anomaly(
    anomaly: Dict[str, Any],
    critical_threshold: float,
    warning_threshold: float,
) -> Tuple[str, str]:
    """Return (severity, rationale) for a single anomaly dict.

    Severity hierarchy: critical > warning > info.
    Critical is non-suppressible when source includes corroboration ("both")
    or the severity_hint from upstream nodes is already "critical".
    """
    source = anomaly.get("source", "sensor")
    hint = anomaly.get("severity_hint", "info")
    deviation = _finite_or(anomaly.get("deviation_pct"), 0.0)

    # Critical conditions (non-suppressible).
    if hint == "critical":
        return "critical", f"upstream severity_hint=critical ({source})"
    if source == "both":
        return "critical", "corroborated by both sensor data and field notes"
    if deviation > critical_threshold:
        return (
            "critical",
            f"sensor deviation {deviation:.1f}% exceeds critical threshold {critical_threshold:.0f}%",
        )

    # Warning conditions.
    if hint == "warning":
        return "warning", f"upstream severity_hint=warning ({source})"
    if deviation > warning_threshold:
        return (
            "warning",
            f"sensor deviation {deviation:.1f}% exceeds warning threshold {warning_threshold:.0f}%",
        )

    # Info — field note observation without sensor corroboration or high deviation.
    return "info", f"low-impact observation (deviation={deviation:.1f}%, source={source})"


def _classify_missing_item(item: Dict[str, Any]) -> Tuple[str, str]:
    """Return (severity, rationale) for a missing mandatory inspection item.

    GX推進法 / 電気事業法 regulatory items → critical (non-suppressible).
    Other items → warning.
    """
    code = item.get("item_code", "")
    desc = item.get("description", "")

    if code.startswith("GX-") or "GX推進法" in desc or "電気事業法" in desc:
        return "critical", f"mandatory regulatory item missing: {code} (non-suppressible)"
    return "warning", f"mandatory inspection item missing: {code}"


# ---------------------------------------------------------------------------
# Node
# ---------------------------------------------------------------------------


class AssessSeverityNode(FunctionNode):
    """Classify detected anomalies as critical / warning / info.

    Inner DomainWorkflowGraph node 6 for ENE-C2-011.

    Applies configurable severity rules to each detected anomaly and each
    missing mandatory inspection item.  Critical anomalies from either source
    are non-suppressible (GX推進法 / 電気事業法).

    Output (partial dict — only changed keys):
        severity_assessments, has_critical, status, error_log.
    """

    required_trust_level: ClassVar[TrustLevel] = TrustLevel.ANONYMOUS

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        """Take the declared severity thresholds injected by the inner graph.

        DomainWorkflowGraph.register_nodes() passes the settings it received
        from config/config.yaml; they are already validated for type,
        finiteness and range. Built with no argument, the node runs on its
        module defaults.
        """
        super().__init__()
        self._declared: Dict[str, Any] = dict(config or {})

    def _thresholds(self, settings: Dict[str, Any]) -> Tuple[float, float]:
        """Resolve the critical/warning deviation thresholds for this run.

        Caller override beats declared setting beats module default. Both
        sources are pre-validated as finite and in range, so no non-finite
        value can reach a comparison here.
        """
        critical = settings.get("critical_deviation_pct")
        if critical is None:
            critical = self._declared.get("critical_deviation_pct")
        warning = settings.get("warning_deviation_pct")
        if warning is None:
            warning = self._declared.get("warning_deviation_pct")
        # Both sources are validated before they get here. Re-establishing that
        # the resolved values are real numbers costs nothing and means no route
        # into this node — including direct construction in a test or a caller
        # that builds the graph itself — can reach a comparison against NaN.
        return (
            _finite_or(critical, _DEFAULT_CRITICAL_DEVIATION_PCT),
            _finite_or(warning, _DEFAULT_WARNING_DEVIATION_PCT),
        )

    def execute(self, state: Dict[str, Any]) -> Dict[str, Any]:
        error_log: List[str] = list(state.get("error_log") or [])
        equipment_type: str = state.get("equipment_type") or "unknown"
        detected_anomalies: List[Dict[str, Any]] = list(state.get("detected_anomalies") or [])
        missing_items: List[Dict[str, Any]] = list(state.get("missing_mandatory_items") or [])

        # ------------------------------------------------------------------
        # 1. Resolve the severity thresholds for this run.
        # ------------------------------------------------------------------
        settings: Dict[str, Any] = state.get("inspection_settings") or {}
        critical_threshold, warning_threshold = self._thresholds(settings)

        # ------------------------------------------------------------------
        # 2. Classify each detected anomaly.
        # ------------------------------------------------------------------
        assessments: List[Dict[str, Any]] = []

        for anomaly in detected_anomalies:
            severity, rationale = _classify_anomaly(anomaly, critical_threshold, warning_threshold)
            assessments.append(
                {
                    "anomaly_id": anomaly.get("anomaly_id", ""),
                    "severity": severity,
                    "rationale": rationale,
                    "equipment_ref": anomaly.get("equipment_ref", equipment_type),
                    "description": anomaly.get("description", ""),
                    "source": anomaly.get("source", "unknown"),
                    "sensor": anomaly.get("sensor", ""),
                    "deviation_pct": anomaly.get("deviation_pct", 0.0),
                }
            )

        # ------------------------------------------------------------------
        # 3. Classify missing mandatory items (appended as separate assessments).
        # ------------------------------------------------------------------
        for item in missing_items:
            severity, rationale = _classify_missing_item(item)
            assessments.append(
                {
                    "anomaly_id": f"MISSING-{item.get('item_code', '?')}",
                    "severity": severity,
                    "rationale": rationale,
                    "equipment_ref": item.get("equipment_ref", equipment_type),
                    "description": f"Mandatory item not found: {item.get('description', '')}",
                    "source": "mandatory_check",
                    "sensor": "",
                    "deviation_pct": 0.0,
                }
            )

        # ------------------------------------------------------------------
        # 4. Determine has_critical flag.
        # ------------------------------------------------------------------
        has_critical = any(a["severity"] == "critical" for a in assessments)

        # ------------------------------------------------------------------
        # 5. Audit trace.
        # ------------------------------------------------------------------
        emit_trace_event(
            "severity_assessed",
            {
                "equipment_type": equipment_type,
                "critical_threshold_pct": critical_threshold,
                "warning_threshold_pct": warning_threshold,
                "total_assessments": len(assessments),
                "critical_count": sum(1 for a in assessments if a["severity"] == "critical"),
                "warning_count": sum(1 for a in assessments if a["severity"] == "warning"),
                "info_count": sum(1 for a in assessments if a["severity"] == "info"),
                "has_critical": has_critical,
            },
            state,
        )

        logger.info(
            "AssessSeverityNode: %d assessments — critical=%s has_critical=%s",
            len(assessments),
            sum(1 for a in assessments if a["severity"] == "critical"),
            has_critical,
        )

        return {
            "severity_assessments": assessments,
            "has_critical": has_critical,
            "status": AgentStatus.SUCCESS.value,
            "error_log": error_log,
        }

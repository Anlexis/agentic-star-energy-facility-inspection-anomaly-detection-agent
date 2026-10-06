"""AgentCore Platform v1.0"""

# Node contract:
#  - Extend FunctionNode; implement execute(state) -> dict
#  - Return ONLY the fields this node changes (never full state)
#  - Return the status as AgentStatus.<X>.value — the enum's string value,
#    not the enum object itself
#  - Never import from mediator/, api/, or other agents
#
# ENE-C2-011 — LoadBaselineParametersNode
# Inner DomainWorkflowGraph node 1: load the baseline tolerance parameters for
# the equipment type under inspection, then overlay any per-sensor override the
# caller supplied for this run.
#
# Input state keys:
#   equipment_type:      str  — canonical equipment type resolved by ValidateInputNode
#   inspection_settings: dict — validated caller overrides (see caller_context.py)
#
# Output state keys (partial dict):
#   baseline_parameters: dict — thresholds keyed by equipment_type → sensor_name → {min, max, warning}
#   status:              AgentStatus string value
#   error_log:           list[str] — accumulated errors
#
# The overrides are already validated (finite, bounded, ordered min<=warning<=max,
# inert sensor names) before they reach this node; anything invalid failed the
# request closed in ValidateInputNode, so nothing here can be reached with a
# NaN threshold that would compare False against every reading.

import logging
from typing import Any, ClassVar, Dict, List

from framework.nodes.function_node import FunctionNode
from framework.schemas.agent_status import AgentStatus
from framework.schemas.trust_level import TrustLevel

from shared.utils.audit_logger import emit_trace_event

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Built-in baseline parameters per equipment type.
# Callers tune them per run through input_context.baseline_overrides; the
# defaults below reflect common Japanese energy facility inspection standards.
# ---------------------------------------------------------------------------

_DEFAULT_BASELINES: Dict[str, Dict[str, Dict[str, float]]] = {
    "変電設備": {
        "temperature_c": {"min": -10.0, "max": 80.0, "warning": 70.0},
        "voltage_kv": {"min": 95.0, "max": 115.0, "warning": 110.0},
        "current_a": {"min": 0.0, "max": 1000.0, "warning": 900.0},
        "oil_level_pct": {"min": 70.0, "max": 100.0, "warning": 75.0},
        "humidity_pct": {"min": 0.0, "max": 85.0, "warning": 80.0},
    },
    "送電線": {
        "temperature_c": {"min": -20.0, "max": 75.0, "warning": 65.0},
        "tension_kn": {"min": 10.0, "max": 50.0, "warning": 45.0},
        "sag_m": {"min": 0.0, "max": 12.0, "warning": 10.0},
        "insulation_mohm": {"min": 100.0, "max": 9999.0, "warning": 200.0},
    },
    "発電設備": {
        "temperature_c": {"min": -10.0, "max": 120.0, "warning": 110.0},
        "vibration_mms": {"min": 0.0, "max": 11.2, "warning": 7.1},
        "rpm": {"min": 2800.0, "max": 3200.0, "warning": 3100.0},
        "pressure_kpa": {"min": 0.0, "max": 5000.0, "warning": 4500.0},
        "oil_pressure_kpa": {"min": 200.0, "max": 600.0, "warning": 250.0},
    },
    "石油精製設備": {
        "temperature_c": {"min": 0.0, "max": 500.0, "warning": 450.0},
        "pressure_kpa": {"min": 0.0, "max": 10000.0, "warning": 9000.0},
        "flow_rate_m3h": {"min": 0.0, "max": 1000.0, "warning": 950.0},
        "h2s_ppm": {"min": 0.0, "max": 1.0, "warning": 0.5},
        "vibration_mms": {"min": 0.0, "max": 7.1, "warning": 4.5},
    },
    # Fallback for unknown equipment type.
    "unknown": {
        "temperature_c": {"min": -20.0, "max": 100.0, "warning": 90.0},
    },
}


# ---------------------------------------------------------------------------
# Node
# ---------------------------------------------------------------------------


class LoadBaselineParametersNode(FunctionNode):
    """Load the baseline tolerance parameters for the equipment under inspection.

    First node of the inner DomainWorkflowGraph for ENE-C2-011.

    Starts from the built-in baselines for every supported equipment type, then
    overlays the caller's validated per-sensor overrides onto the entry for the
    equipment type this run is scoring against. An unrecognised equipment type
    inherits the generic fallback entry.

    Output (partial dict — only changed keys):
        baseline_parameters, status, error_log.
    """

    required_trust_level: ClassVar[TrustLevel] = TrustLevel.ANONYMOUS

    def execute(self, state: Dict[str, Any]) -> Dict[str, Any]:
        error_log: List[str] = list(state.get("error_log") or [])
        equipment_type: str = state.get("equipment_type") or "unknown"
        settings: Dict[str, Any] = state.get("inspection_settings") or {}
        overrides: Dict[str, Dict[str, float]] = settings.get("baseline_overrides") or {}

        # ------------------------------------------------------------------
        # 1. Start from the built-in baselines (local copies — never mutate the
        #    module-level defaults).
        # ------------------------------------------------------------------
        baselines: Dict[str, Any] = {
            eq_type: {sensor: dict(thresholds) for sensor, thresholds in sensors.items()}
            for eq_type, sensors in _DEFAULT_BASELINES.items()
        }

        # ------------------------------------------------------------------
        # 2. Ensure the equipment type under inspection has a baseline entry.
        # ------------------------------------------------------------------
        if equipment_type not in baselines:
            logger.warning(
                "LoadBaselineParametersNode: no baseline for equipment_type=%s — using the fallback set",
                equipment_type,
            )
            baselines[equipment_type] = {
                sensor: dict(thresholds) for sensor, thresholds in baselines["unknown"].items()
            }

        # ------------------------------------------------------------------
        # 3. Overlay the caller's per-sensor overrides. A partial override
        #    (say `max` only) merges into the built-in thresholds for that
        #    sensor, so the remaining bounds stay in force.
        # ------------------------------------------------------------------
        for sensor, thresholds in overrides.items():
            merged = dict(baselines[equipment_type].get(sensor) or {})
            merged.update(thresholds)
            baselines[equipment_type][sensor] = merged

        # ------------------------------------------------------------------
        # 4. Audit trace (parameter counts, never the raw values).
        # ------------------------------------------------------------------
        eq_params = baselines.get(equipment_type, {})
        emit_trace_event(
            "baseline_parameters_loaded",
            {
                "equipment_type": equipment_type,
                "sensor_count": len(eq_params),
                "override_count": len(overrides),
                "source": "caller_overlay" if overrides else "defaults",
            },
            state,
        )

        logger.info(
            "LoadBaselineParametersNode: loaded %d sensor baselines for equipment_type=%s (%d overridden)",
            len(eq_params),
            equipment_type,
            len(overrides),
        )

        return {
            "baseline_parameters": baselines,
            "status": AgentStatus.SUCCESS.value,
            "error_log": error_log,
        }

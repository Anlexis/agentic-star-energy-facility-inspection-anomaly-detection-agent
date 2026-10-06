"""AgentCore Platform v1.0"""

# Node contract:
#  - Extend FunctionNode; implement execute(state) -> dict
#  - Return ONLY the fields this node changes (never full state)
#  - Return the status as AgentStatus.<X>.value — the enum's string value,
#    not the enum object itself
#  - Never import from mediator/, api/, or other agents
#
# ENE-C2-011 — ParseSensorDataNode
# Inner DomainWorkflowGraph node 2: extract structured sensor readings from the
# validated inspection report text, normalize units, and detect out-of-range
# values against the baseline parameters loaded by LoadBaselineParametersNode.
#
# Input state keys:
#   validated_input:     str — sanitized inspection report text
#   equipment_type:      str — canonical equipment type
#   baseline_parameters: dict — thresholds per equipment_type per sensor
#
# Output state keys (partial dict):
#   sensor_readings: list[dict] — parsed sensor readings
#   sensor_anomalies: list[dict] — readings exceeding baseline thresholds
#   status: AgentStatus string value
#   error_log: list[str] — accumulated errors
#
# Security note:
#   Audit: raw sensor values are emitted only as counts (not raw data) to the
#   audit trace — facility topology data must not appear in log stores.

import logging
import math
import re
from typing import Any, ClassVar, Dict, List, Optional, Set, Tuple

from framework.nodes.function_node import FunctionNode
from framework.schemas.agent_status import AgentStatus
from framework.schemas.trust_level import TrustLevel

from shared.utils.audit_logger import emit_trace_event

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Sensor parsing patterns.
# Matches lines like:
#   温度: 85.2 ℃
#   voltage: 116.5 kV
#   pressure 4800 kPa
# ---------------------------------------------------------------------------

_SENSOR_LINE_RE = re.compile(
    r"(?P<sensor>[a-zA-Z　-鿿゠-ヿ_]+)"  # sensor name (ASCII or CJK)
    r"[\s:：]+(?P<value>[-+]?\d+(?:\.\d+)?)"  # numeric value
    r"\s*(?P<unit>[a-zA-Z%℃°Ω]+)?",  # optional unit
    re.UNICODE,
)

# A reading outside this magnitude is not a measurement — it is a typo, a
# concatenated identifier, or a padded digit run. Reading it as a number matters
# beyond plausibility: a long enough run of digits parses to float('inf'), and an
# infinite value then flows through the deviation arithmetic into the published
# alert, where it serializes as the bare token `Infinity` — not valid JSON, so
# every strict consumer of the alert breaks. Readings are therefore required to
# be finite and within range, and anything else is discarded rather than scored.
_MAX_READING_MAGNITUDE = 1e12

# ---------------------------------------------------------------------------
# Unit normalization map: raw unit → canonical unit.
# ---------------------------------------------------------------------------

_UNIT_MAP: Dict[str, str] = {
    "℃": "°C",
    "C": "°C",
    "°c": "°C",
    "deg": "°C",
    "kv": "kV",
    "KV": "kV",
    "a": "A",
    "amp": "A",
    "kpa": "kPa",
    "KPA": "kPa",
    "mpa": "MPa",
    "MPA": "MPa",
    "kn": "kN",
    "KN": "kN",
    "mms": "mm/s",
    "ppm": "ppm",
    "pct": "%",
    "mohm": "MΩ",
    "m3h": "m³/h",
}

# Sensor name normalization: map common aliases to canonical names.
_SENSOR_NAME_MAP: Dict[str, str] = {
    "温度": "temperature_c",
    "temperature": "temperature_c",
    "temp": "temperature_c",
    "電圧": "voltage_kv",
    "voltage": "voltage_kv",
    "電流": "current_a",
    "current": "current_a",
    "圧力": "pressure_kpa",
    "pressure": "pressure_kpa",
    "油面": "oil_level_pct",
    "oil_level": "oil_level_pct",
    "湿度": "humidity_pct",
    "humidity": "humidity_pct",
    "張力": "tension_kn",
    "tension": "tension_kn",
    "たるみ": "sag_m",
    "sag": "sag_m",
    "絶縁": "insulation_mohm",
    "insulation": "insulation_mohm",
    "振動": "vibration_mms",
    "vibration": "vibration_mms",
    "回転数": "rpm",
    "rpm": "rpm",
    "流量": "flow_rate_m3h",
    "flow": "flow_rate_m3h",
    "h2s": "h2s_ppm",
}


def _normalize_sensor_name(raw_name: str) -> str:
    """Return canonical sensor name from raw text (case/language normalization)."""
    cleaned = raw_name.strip().lower().replace(" ", "_").replace("　", "_")
    return _SENSOR_NAME_MAP.get(cleaned, cleaned)


def _normalize_unit(raw_unit: Optional[str]) -> str:
    """Return normalized unit string."""
    if not raw_unit:
        return "unknown"
    cleaned = raw_unit.strip()
    return _UNIT_MAP.get(cleaned, _UNIT_MAP.get(cleaned.lower(), cleaned))


def _parse_sensor_lines(text: str) -> List[Dict[str, Any]]:
    """Extract (sensor_name, value, unit) triples from report text.

    Returns list of {"sensor": str, "value": float, "unit": str}.
    Only lines inside a plausible 'measurement' / 'sensor' section are scanned.
    """
    readings: List[Dict[str, Any]] = []
    seen: Set[Tuple[str, float]] = set()

    for match in _SENSOR_LINE_RE.finditer(text):
        raw_sensor = match.group("sensor")
        raw_value = match.group("value")
        raw_unit = match.group("unit")

        sensor = _normalize_sensor_name(raw_sensor)
        try:
            value = float(raw_value)
        except (ValueError, OverflowError):
            continue
        if not math.isfinite(value) or abs(value) > _MAX_READING_MAGNITUDE:
            logger.warning("ParseSensorDataNode: discarding an out-of-range reading for sensor=%s", sensor)
            continue

        unit = _normalize_unit(raw_unit)

        # Deduplicate (first occurrence wins).
        dedup_key = (sensor, value)
        if dedup_key in seen:
            continue
        seen.add(dedup_key)

        readings.append({"sensor": sensor, "value": value, "unit": unit})

    return readings


def _finite(value: Any) -> Optional[float]:
    """Return *value* as a float when it is a real, finite number, else None.

    A threshold that is not a usable number is treated as absent: comparing
    against NaN is always False, which would silently wave every reading
    through the bound it was supposed to enforce.
    """
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    number = float(value)
    return number if math.isfinite(number) else None


def _check_against_baseline(
    readings: List[Dict[str, Any]],
    baselines: Dict[str, Any],
    equipment_type: str,
) -> List[Dict[str, Any]]:
    """Return readings that deviate from baseline thresholds.

    Returns list of {"sensor", "value", "unit", "threshold", "deviation_pct",
    "direction": "above"|"below", "severity_hint": "warning"|"critical"}.
    """
    eq_baselines = baselines.get(equipment_type, baselines.get("unknown", {}))
    anomalies: List[Dict[str, Any]] = []

    for reading in readings:
        sensor = reading["sensor"]
        value = reading["value"]
        params = eq_baselines.get(sensor)
        if params is None:
            continue

        max_val = _finite(params.get("max"))
        min_val = _finite(params.get("min"))
        warn_val = _finite(params.get("warning"))

        # Determine threshold breach.
        if max_val is not None and value > max_val:
            ref = max_val
            direction = "above"
            severity_hint = "critical"
        elif warn_val is not None and value > warn_val:
            ref = warn_val
            direction = "above"
            severity_hint = "warning"
        elif min_val is not None and value < min_val:
            ref = min_val
            direction = "below"
            severity_hint = "critical"
        else:
            continue

        deviation_pct = abs(value - ref) / ref * 100.0 if ref != 0 else 0.0
        if not math.isfinite(deviation_pct):
            deviation_pct = 0.0

        anomalies.append(
            {
                "sensor": sensor,
                "value": value,
                "unit": reading["unit"],
                "threshold": ref,
                "deviation_pct": round(deviation_pct, 2),
                "direction": direction,
                "severity_hint": severity_hint,
            }
        )

    return anomalies


# ---------------------------------------------------------------------------
# Node
# ---------------------------------------------------------------------------


class ParseSensorDataNode(FunctionNode):
    """Extract and normalize sensor readings; detect out-of-range values.

    Inner DomainWorkflowGraph node 2 for ENE-C2-011.

    Parses numeric sensor readings from the inspection report text using
    regex-based extraction, normalizes sensor names and units, then
    cross-references against the baseline parameters from LoadBaselineParametersNode.

    Output (partial dict — only changed keys):
        sensor_readings, sensor_anomalies, status, error_log.
    """

    required_trust_level: ClassVar[TrustLevel] = TrustLevel.ANONYMOUS

    def execute(self, state: Dict[str, Any]) -> Dict[str, Any]:
        error_log: List[str] = list(state.get("error_log") or [])
        # Fall back to user_input when validated_input is not set (inner graph context:
        # GraphNode.extract_input() returns validated_input but BaseGraph.invoke() places
        # it under the "user_input" key, not "validated_input").
        validated_input: str = state.get("validated_input") or state.get("user_input", "")
        equipment_type: str = state.get("equipment_type") or "unknown"
        baseline_parameters: Dict[str, Any] = state.get("baseline_parameters") or {}

        if not validated_input.strip():
            return {
                "sensor_readings": [],
                "sensor_anomalies": [],
                "status": AgentStatus.SUCCESS.value,
                "error_log": error_log,
            }

        # ------------------------------------------------------------------
        # 1. Parse sensor readings from report text.
        # ------------------------------------------------------------------
        readings = _parse_sensor_lines(validated_input)

        # ------------------------------------------------------------------
        # 2. Cross-reference against baseline parameters.
        # ------------------------------------------------------------------
        anomalies = _check_against_baseline(readings, baseline_parameters, equipment_type)

        # ------------------------------------------------------------------
        # 3. Audit trace (counts only — no raw sensor values).
        # ------------------------------------------------------------------
        emit_trace_event(
            "sensor_data_parsed",
            {
                "equipment_type": equipment_type,
                "readings_count": len(readings),
                "anomalies_count": len(anomalies),
                "critical_count": sum(1 for a in anomalies if a.get("severity_hint") == "critical"),
            },
            state,
        )

        logger.info(
            "ParseSensorDataNode: parsed %d readings, %d anomalies for equipment_type=%s",
            len(readings),
            len(anomalies),
            equipment_type,
        )

        return {
            "sensor_readings": readings,
            "sensor_anomalies": anomalies,
            "status": AgentStatus.SUCCESS.value,
            "error_log": error_log,
        }

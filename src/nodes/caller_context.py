"""AgentCore Platform v1.0"""

# ENE-C2-011 — the caller-data contract for `input_context`.
#
# `POST /invoke` accepts a structured `input_context` alongside the report text.
# It is the one channel through which an operator tunes a run: which equipment
# baseline to score against, the tolerance thresholds, and which mandatory
# inspection items apply. Everything in it is untrusted.
#
# The framework's input gate masks PII and screens prompt injection on
# `user_input` / `validated_input` only — the context channel is not covered by
# it, so every guarantee below is owned by this template.
#
# Contract, enforced field by field:
#   - Every NUMBER goes through _finite_in_range(): bools, strings, NaN,
#     ±Infinity and out-of-range magnitudes are all refused. NaN is the
#     dangerous one — it parses through float() and arrives intact through raw
#     JSON, and every comparison against it is False, so a NaN threshold would
#     silently classify every reading as within tolerance. That is a fail-OPEN
#     on the exact decision this agent exists to make, so numbers fail CLOSED.
#   - Every STRING that selects behaviour is an inert identifier of bounded
#     length. Free text in such a field is caller-controlled output and log
#     injection; it is refused before it is even compared.
#   - Structural caps bound every collection (sensor overrides, item codes).
#   - Errors name the FIELD, never the rejected value.
#   - Unsupported keys are refused rather than ignored, so a misspelled
#     override cannot silently leave the run on defaults.
#   - Absent fields are fine: the run falls back to the documented built-in
#     baselines and thresholds.
#
# What is deliberately NOT caller-controlled: the alert's rendering bounds and
# the severity floor. A caller can raise or lower a tolerance threshold, but
# cannot suppress a finding that has already been classified critical, and
# cannot widen the excerpt/finding caps the output boundary enforces.

import math
import re
from typing import Any, Dict, List, Optional, Tuple

# Caller-facing equipment selector → the canonical internal equipment name.
# The selector alphabet is inert by construction; the CJK canonical names are
# never accepted from a caller.
EQUIPMENT_SLUGS: Dict[str, str] = {
    "substation": "変電設備",
    "transmission_line": "送電線",
    "generation": "発電設備",
    "refinery": "石油精製設備",
    "unknown": "unknown",
}

# Behaviour-selecting caller strings: lowercase alphanumerics/underscore only.
_INERT_IDENTIFIER_RE = re.compile(r"^[a-z0-9_]{1,32}$")

# Mandatory-item codes as they appear in inspection checklists: up to three
# hyphen-joined uppercase alphanumeric groups (e.g. "SUB-01", "GX-01").
_ITEM_CODE_RE = re.compile(r"^[A-Z0-9]{1,8}(?:-[A-Z0-9]{1,8}){0,2}$")

# Structural caps.
MAX_SENSOR_OVERRIDES = 32
MAX_ITEM_CODES = 64

# Tolerance thresholds are percentages; a deviation above 1000% is a data
# error, not a tolerance.
_DEVIATION_MIN = 0.0
_DEVIATION_MAX = 1000.0

# Sensor thresholds span temperatures, pressures and resistances; this bound
# is a sanity ceiling, not a unit-aware range.
_THRESHOLD_MIN = -1_000_000.0
_THRESHOLD_MAX = 1_000_000.0

# The keys this template understands. Anything else from the caller is refused.
SUPPORTED_KEYS = frozenset(
    {
        "equipment_type",
        "critical_deviation_pct",
        "warning_deviation_pct",
        "baseline_overrides",
        "mandatory_item_codes",
    }
)

# Fields the hosting runtime puts on the context channel itself. They are not
# part of the caller contract and this template reads none of them, but
# refusing them would refuse every invocation served that way — the caller
# cannot remove what it never added. They are accepted and ignored, which is
# sound precisely because no constraint is attached to them: there is nothing
# for the caller to be misled about. The refusal message below still names
# only SUPPORTED_KEYS, so a caller is never told it may set one of these.
RUNTIME_KEYS = frozenset({"conversation_history"})

_ACCEPTED_KEYS = SUPPORTED_KEYS | RUNTIME_KEYS

_THRESHOLD_KEYS = ("min", "warning", "max")


def _finite_in_range(value: Any, lo: float, hi: float) -> Optional[float]:
    """Return *value* as a float when it is a real, finite number within [lo, hi].

    Returns None for anything else — bools (which are ints in Python), strings,
    None, NaN, ±Infinity, and out-of-range magnitudes. The caller turns a None
    into a field-naming rejection; nothing falls through to a default, because
    an unusable override is a caller error, not a reason to run differently
    than the caller asked.
    """
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    number = float(value)
    if not math.isfinite(number):
        return None
    if not lo <= number <= hi:
        return None
    return number


def _validate_equipment_type(value: Any, errors: List[str]) -> Optional[str]:
    """Map a caller equipment selector to its canonical name, or record an error."""
    if value is None:
        return None
    if not isinstance(value, str):
        errors.append("input_context.equipment_type must be one of the supported equipment selectors.")
        return None
    candidate = value.strip().lower()
    if not candidate:
        return None
    if not _INERT_IDENTIFIER_RE.match(candidate) or candidate not in EQUIPMENT_SLUGS:
        errors.append("input_context.equipment_type must be one of the supported equipment selectors.")
        return None
    return EQUIPMENT_SLUGS[candidate]


def _validate_deviation(value: Any, field: str, errors: List[str]) -> Optional[float]:
    """Validate one tolerance-threshold percentage."""
    if value is None:
        return None
    number = _finite_in_range(value, _DEVIATION_MIN, _DEVIATION_MAX)
    if number is None or number <= _DEVIATION_MIN:
        errors.append(
            f"input_context.{field} must be a finite number greater than "
            f"{_DEVIATION_MIN:.0f} and at most {_DEVIATION_MAX:.0f}."
        )
        return None
    return number


def _validate_baseline_overrides(value: Any, errors: List[str]) -> Dict[str, Dict[str, float]]:
    """Validate the per-sensor threshold overrides.

    Shape: {"<sensor_name>": {"min": float, "warning": float, "max": float}}.
    Sensor names are inert identifiers; every threshold is finite and bounded;
    the three thresholds must be ordered min <= warning <= max, otherwise the
    override would describe a band no reading can satisfy.
    """
    overrides: Dict[str, Dict[str, float]] = {}
    if value is None:
        return overrides
    if not isinstance(value, dict):
        errors.append("input_context.baseline_overrides must be a mapping of sensor name to thresholds.")
        return overrides
    if len(value) > MAX_SENSOR_OVERRIDES:
        errors.append(f"input_context.baseline_overrides accepts at most {MAX_SENSOR_OVERRIDES} sensors.")
        return overrides

    # A sensor name only ever appears in an error message AFTER it has passed
    # the inert-identifier check, so no caller free text reaches the error log.
    for sensor, thresholds in value.items():
        if not isinstance(sensor, str) or not _INERT_IDENTIFIER_RE.match(sensor):
            errors.append("input_context.baseline_overrides keys must be sensor identifiers.")
            continue
        if not isinstance(thresholds, dict):
            errors.append(f"input_context.baseline_overrides.{sensor} must be a mapping of threshold name to number.")
            continue
        unsupported = set(thresholds) - set(_THRESHOLD_KEYS)
        if unsupported:
            errors.append(f"input_context.baseline_overrides.{sensor} accepts only " f"{', '.join(_THRESHOLD_KEYS)}.")
            continue
        parsed: Dict[str, float] = {}
        rejected = False
        for key in _THRESHOLD_KEYS:
            if key not in thresholds:
                continue
            number = _finite_in_range(thresholds[key], _THRESHOLD_MIN, _THRESHOLD_MAX)
            if number is None:
                errors.append(
                    f"input_context.baseline_overrides.{sensor}.{key} must be a finite number "
                    f"between {_THRESHOLD_MIN:.0f} and {_THRESHOLD_MAX:.0f}."
                )
                rejected = True
                continue
            parsed[key] = number
        if rejected or not parsed:
            continue
        ordered = [parsed[key] for key in _THRESHOLD_KEYS if key in parsed]
        if ordered != sorted(ordered):
            errors.append(
                f"input_context.baseline_overrides.{sensor} thresholds must be ordered "
                f"{' <= '.join(_THRESHOLD_KEYS)}."
            )
            continue
        overrides[sensor] = parsed
    return overrides


def _validate_item_codes(value: Any, errors: List[str]) -> List[str]:
    """Validate the caller's mandatory-item code list.

    Codes only — never descriptions. The rendered description for a code comes
    from this template's built-in checklist, so no caller free text can reach
    the alert through this field.
    """
    codes: List[str] = []
    if value is None:
        return codes
    if not isinstance(value, list):
        errors.append("input_context.mandatory_item_codes must be a list of item codes.")
        return codes
    if len(value) > MAX_ITEM_CODES:
        errors.append(f"input_context.mandatory_item_codes accepts at most {MAX_ITEM_CODES} codes.")
        return codes
    for entry in value:
        if not isinstance(entry, str):
            errors.append("input_context.mandatory_item_codes entries must be item codes.")
            continue
        candidate = entry.strip().upper()
        if not _ITEM_CODE_RE.match(candidate):
            errors.append("input_context.mandatory_item_codes entries must be item codes.")
            continue
        if candidate not in codes:
            codes.append(candidate)
    return codes


def validate_caller_context(input_context: Any) -> Tuple[Dict[str, Any], List[str]]:
    """Validate the caller's `input_context`.

    Returns ``(settings, errors)``. When *errors* is non-empty the caller's
    request is refused outright — the partially built settings are never used,
    so a run can never proceed on half-applied overrides.

    *settings* keys (each present only when the caller supplied a valid value):
        equipment_type          canonical equipment name
        critical_deviation_pct  float
        warning_deviation_pct   float
        baseline_overrides      {sensor: {min|warning|max: float}}
        mandatory_item_codes    [item code, ...]
    """
    errors: List[str] = []
    if input_context is None:
        return {}, errors
    if not isinstance(input_context, dict):
        return {}, ["input_context must be an object."]

    unsupported = set(input_context) - _ACCEPTED_KEYS
    if unsupported:
        # The rejected key names are caller-controlled strings and are never
        # echoed; the supported set is static text.
        errors.append(
            "input_context contains unsupported fields; supported: " + ", ".join(sorted(SUPPORTED_KEYS)) + "."
        )

    settings: Dict[str, Any] = {}

    equipment_type = _validate_equipment_type(input_context.get("equipment_type"), errors)
    if equipment_type is not None:
        settings["equipment_type"] = equipment_type

    critical = _validate_deviation(input_context.get("critical_deviation_pct"), "critical_deviation_pct", errors)
    if critical is not None:
        settings["critical_deviation_pct"] = critical

    warning = _validate_deviation(input_context.get("warning_deviation_pct"), "warning_deviation_pct", errors)
    if warning is not None:
        settings["warning_deviation_pct"] = warning

    if critical is not None and warning is not None and warning > critical:
        errors.append("input_context.warning_deviation_pct must not exceed input_context.critical_deviation_pct.")

    overrides = _validate_baseline_overrides(input_context.get("baseline_overrides"), errors)
    if overrides:
        settings["baseline_overrides"] = overrides

    codes = _validate_item_codes(input_context.get("mandatory_item_codes"), errors)
    if codes:
        settings["mandatory_item_codes"] = codes

    if errors:
        return {}, errors
    return settings, errors

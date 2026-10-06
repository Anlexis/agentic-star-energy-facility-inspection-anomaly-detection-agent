"""AgentCore Platform v1.0"""

# Node contract:
#  - Extend FunctionNode; implement execute(state) -> dict
#  - Return ONLY the fields this node changes (never full state)
#  - Return the status as AgentStatus.<X>.value — the enum's string value,
#    not the enum object itself
#  - Never import from mediator/, api/, or other agents
#
# ENE-C2-011 — ValidateInputNode
# Outer backbone pre_process slot: input validation for facility inspection
# reports. Rejects malformed, empty, out-of-scope or hostile input before the
# inner domain workflow graph runs, and validates the caller's structured
# `input_context` against the contract in caller_context.py.
#
# Input state keys:
#   user_input:    str  — raw inspection report text (sensor data + field notes)
#   input_context: dict — structured per-invocation parameters from the caller
#
# Output state keys (partial dict):
#   validated_input:     cleaned inspection report text
#   equipment_type:      detected (or caller-selected) equipment type, or "unknown"
#   inspection_settings: the validated caller overrides applied to this run
#   out_of_scope:        bool — True if the report carries no sensor data
#   status:              AgentStatus.SUCCESS or AgentStatus.ERROR
#   error_log:           list[str] — accumulated errors
#
# Security notes this node OWNS (they hold whether or not a platform gate runs
# in front of it — the checks below are executed inside execute(), so calling
# the node directly exercises the same refusals):
#   - Control characters are stripped from the report text.
#   - Instruction-override phrasing aimed at a model rather than at the
#     inspection record is refused outright. The platform input gate refuses
#     these too, but a template that leans on that alone returns SUCCESS
#     wherever the gate is absent or configured off.
#   - Report size is capped, so an oversized payload cannot exhaust memory.
#   - Every caller `input_context` field is validated; a rejected request never
#     runs on half-applied overrides and never echoes the rejected value.
#   - Facility topology data is not emitted to the audit trace (category only).

import logging
import re
from typing import Any, ClassVar, Dict, List

from framework.nodes.function_node import FunctionNode
from framework.schemas.agent_status import AgentStatus
from framework.schemas.trust_level import TrustLevel

from shared.utils.audit_logger import emit_trace_event
from src.services.failure_message import INPUT_REJECTED
from src.services.progress import emit_progress
from src.nodes.caller_context import validate_caller_context

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Maximum allowed inspection report size (characters).
_MAX_REPORT_CHARS = 50_000

# Minimum meaningful report length.
_MIN_REPORT_CHARS = 10

# Recognised equipment type keywords (lower-cased) mapped to canonical names.
_EQUIPMENT_KEYWORDS: Dict[str, str] = {
    "変電設備": "変電設備",
    "substation": "変電設備",
    "送電線": "送電線",
    "transmission": "送電線",
    "発電設備": "発電設備",
    "generation": "発電設備",
    "石油精製設備": "石油精製設備",
    "refinery": "石油精製設備",
    "petrochemical": "石油精製設備",
}

# Minimum sensor data indicators (at least one of these must appear).
_SENSOR_INDICATORS = [
    "温度",
    "電圧",
    "電流",
    "圧力",
    "temperature",
    "voltage",
    "current",
    "pressure",
    "sensor",
    "センサ",
    "計測",
]

# Regex to strip control characters.
_CONTROL_CHARS_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

# Instruction-override phrasing: text addressed to a language model rather than
# an observation recorded about a facility. Deliberately narrow — an inspection
# note that happens to contain "system" or "instructions" does not match,
# because every alternative requires the imperative override shape.
_INSTRUCTION_OVERRIDE_RE = re.compile(
    r"ignore\s+(?:all\s+|any\s+)?(?:previous|prior|above|earlier)\s+"
    r"(?:instruction|instructions|prompt|prompts|rule|rules|direction|directions)"
    r"|disregard\s+(?:all\s+|any\s+)?(?:previous|prior|above|earlier)\s+"
    r"(?:instruction|instructions|prompt|prompts|rule|rules)"
    r"|forget\s+(?:all\s+|any\s+)?(?:previous|prior|above|earlier)\s+"
    r"(?:instruction|instructions|prompt|prompts)"
    r"|(?:reveal|show|print|repeat|output|disclose)\s+(?:me\s+)?(?:your|the)\s+"
    r"(?:system\s+prompt|system\s+message|instructions|initial\s+prompt)"
    r"|you\s+are\s+now\s+(?:a|an)\s"
    r"|act\s+as\s+(?:if\s+you\s+are\s+)?(?:a\s+|an\s+)?(?:developer|admin|root)\s+mode"
    r"|override\s+(?:your|the)\s+(?:instruction|instructions|rules|safety)"
    r"|(?:これまでの|以前の|上記の)\s*(?:指示|命令|ルール)\s*(?:は\s*)?(?:を\s*)?無視"
    r"|システムプロンプト\s*を?\s*(?:表示|出力|教え)",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _detect_equipment_type(text: str) -> str:
    """Return canonical equipment type from inspection report text.

    Scans the first 500 characters (typically the header) for equipment keywords.
    Returns "unknown" when no keyword matches.
    """
    header = text[:500].lower()
    for keyword, canonical in _EQUIPMENT_KEYWORDS.items():
        if keyword.lower() in header:
            return canonical
    return "unknown"


def _has_sensor_data(text: str) -> bool:
    """Return True if the report contains at least one sensor data indicator."""
    text_lower = text.lower()
    return any(indicator.lower() in text_lower for indicator in _SENSOR_INDICATORS)


def _carries_instruction_override(text: str) -> bool:
    """Return True when the report text carries instruction-override phrasing."""
    return bool(_INSTRUCTION_OVERRIDE_RE.search(text))


# ---------------------------------------------------------------------------
# Node
# ---------------------------------------------------------------------------


class ValidateInputNode(FunctionNode):
    """Input validation for facility inspection reports.

    Outer backbone pre_process slot for ENE-C2-011.

    Validation rules:
    - user_input must be a non-empty string within the allowed size limits.
    - Report text carrying instruction-override phrasing is refused.
    - Report must contain at least one sensor data indicator (temperature, voltage, etc.).
    - Equipment type is detected from the report header; a caller-supplied
      selector overrides the detection; "unknown" is accepted (not out-of-scope).
    - Control characters are stripped.
    - The caller's input_context is validated field by field; any rejection
      fails the whole request closed.
    - Out-of-scope: triggered when the report has no sensor data indicators.

    Output (partial dict — only changed keys):
        validated_input, equipment_type, inspection_settings, out_of_scope,
        status, error_log.
    """

    required_trust_level: ClassVar[TrustLevel] = TrustLevel.VERIFIED_EXTERNAL

    def execute(self, state: Dict[str, Any]) -> Dict[str, Any]:
        error_log: List[str] = list(state.get("error_log") or [])
        user_input = state.get("user_input", "")

        # ------------------------------------------------------------------
        # 1. Type and presence check.
        # ------------------------------------------------------------------
        if not isinstance(user_input, str):
            return self._reject(error_log, "ValidateInputNode: user_input must be a string", "INVALID_REQUEST")

        if len(user_input.strip()) < _MIN_REPORT_CHARS:
            return self._reject(error_log, "ValidateInputNode: user_input is empty or too short", "EMPTY_INPUT")

        # ------------------------------------------------------------------
        # 2. Size limit (prevent memory exhaustion).
        # ------------------------------------------------------------------
        if len(user_input) > _MAX_REPORT_CHARS:
            return self._reject(
                error_log,
                f"ValidateInputNode: user_input exceeds the size limit of " f"{_MAX_REPORT_CHARS} characters",
                "QUESTION_TOO_LONG",
            )

        # ------------------------------------------------------------------
        # 3. Sanitize — strip control characters.
        # ------------------------------------------------------------------
        sanitized = _CONTROL_CHARS_RE.sub("", user_input)

        # ------------------------------------------------------------------
        # 4. Refuse instruction-override phrasing. Nothing downstream sees the
        #    text, and no partial result is carried forward.
        # ------------------------------------------------------------------
        if _carries_instruction_override(sanitized):
            emit_trace_event(
                "inspection_report_refused",
                {"reason": "instruction_override", "report_length": len(sanitized)},
                state,
            )
            return self._reject(
                error_log,
                "ValidateInputNode: report text carries instruction-override content " "and cannot be processed",
            )

        # ------------------------------------------------------------------
        # 5. Validate the caller's structured parameters. Fail closed: any
        #    invalid field refuses the whole request rather than silently
        #    dropping the override.
        # ------------------------------------------------------------------
        settings, context_errors = validate_caller_context(state.get("input_context"))
        if context_errors:
            emit_trace_event(
                "caller_context_rejected",
                {"rejected_field_count": len(context_errors)},
                state,
            )
            emit_progress(INPUT_REJECTED)
            # A value the caller can correct: the run COMPLETES carrying the
            # reason so the request can be sent again on the same conversation.
            return {
                "status": AgentStatus.SUCCESS.value,
                "error_code": "INVALID_REQUEST",
                "out_of_scope": False,
                "inspection_settings": {},
                "error_log": error_log + [f"ValidateInputNode: {err}" for err in context_errors],
            }

        # ------------------------------------------------------------------
        # 6. Domain validation — does the report contain sensor data?
        # ------------------------------------------------------------------
        has_sensor = _has_sensor_data(sanitized)
        out_of_scope = not has_sensor

        # ------------------------------------------------------------------
        # 7. Resolve equipment type — a validated caller selector wins over the
        #    header heuristic.
        # ------------------------------------------------------------------
        equipment_type = settings.get("equipment_type") or _detect_equipment_type(sanitized)

        # ------------------------------------------------------------------
        # 8. Audit trace (no raw facility data — emit category only).
        # ------------------------------------------------------------------
        emit_trace_event(
            "inspection_report_validated",
            {
                "equipment_type": equipment_type,
                "report_length": len(sanitized),
                "has_sensor_data": has_sensor,
                "out_of_scope": out_of_scope,
                "caller_override_count": len(settings),
            },
            state,
        )

        if out_of_scope:
            logger.info("ValidateInputNode: inspection report is out of scope " "(no sensor data indicators found)")
        else:
            logger.info(
                "ValidateInputNode: validated report — equipment_type=%s length=%d",
                equipment_type,
                len(sanitized),
            )

        return {
            "validated_input": sanitized.strip(),
            "equipment_type": equipment_type,
            "inspection_settings": settings,
            "out_of_scope": out_of_scope,
            "status": AgentStatus.SUCCESS.value,
            "error_log": error_log,
        }

    @staticmethod
    def _reject(error_log: List[str], message: str, code: str = "") -> Dict[str, Any]:
        """Return the rejection delta. The offending value is never included.

        `code` separates the two kinds of rejection. With a code, the caller can
        correct the request: the run COMPLETES carrying that reason, so the
        reason reaches the caller and the same conversation can carry a
        corrected request. Without one, the content itself is refused and the
        run terminates.
        """
        if code:
            emit_progress(INPUT_REJECTED)
            return {
                "status": AgentStatus.SUCCESS.value,
                "error_code": code,
                "out_of_scope": False,
                "inspection_settings": {},
                "error_log": error_log + [message],
            }
        return {
            "status": AgentStatus.ERROR.value,
            "out_of_scope": False,
            "inspection_settings": {},
            "error_log": error_log + [message],
        }

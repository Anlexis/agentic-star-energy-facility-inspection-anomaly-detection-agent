"""AgentCore Platform v1.0"""

# Node contract:
#  - Extend FunctionNode; implement execute(state) -> dict
#  - Return ONLY the fields this node changes (never full state)
#  - Return the status as AgentStatus.<X>.value — the enum's string value,
#    not the enum object itself
#  - Never import from mediator/, api/, or other agents
#
# ENE-C2-011 — CheckMandatoryItemsNode
# Inner DomainWorkflowGraph node 5: verify that all mandatory inspection items
# per equipment type are present and completed in the report.
#
# The checklist for an equipment type comes from the built-in catalogue below.
# A caller may narrow or extend it by listing item CODES in
# input_context.mandatory_item_codes; the rendered description for a code is
# always looked up here, so no caller free text can reach the alert through
# this field. A code with no catalogue entry renders as the code itself.
#
# Input state keys:
#   validated_input:     str  — sanitized inspection report text
#   equipment_type:      str  — canonical equipment type
#   inspection_settings: dict — validated caller overrides
#
# Output state keys (partial dict):
#   missing_mandatory_items: list[dict] — items absent from the report
#   mandatory_check_passed:  bool — True when all items present
#   status:                  AgentStatus string value
#   error_log:               list[str] — accumulated errors

import logging
from typing import Any, ClassVar, Dict, List

from framework.nodes.function_node import FunctionNode
from framework.schemas.agent_status import AgentStatus
from framework.schemas.trust_level import TrustLevel

from shared.utils.audit_logger import emit_trace_event

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Built-in mandatory inspection items per equipment type.
# Based on 電気事業法 保安規程 / GX推進法 2026 mandatory reporting requirements.
# ---------------------------------------------------------------------------

_DEFAULT_MANDATORY_ITEMS: Dict[str, List[Dict[str, str]]] = {
    "変電設備": [
        {"item_code": "SUB-01", "description": "外観点検 (visual inspection)"},
        {"item_code": "SUB-02", "description": "絶縁抵抗測定 (insulation resistance measurement)"},
        {"item_code": "SUB-03", "description": "油面確認 (oil level check)"},
        {"item_code": "SUB-04", "description": "温度確認 (temperature reading)"},
        {"item_code": "SUB-05", "description": "接地抵抗確認 (grounding resistance check)"},
        {"item_code": "GX-01", "description": "GX推進法 排出量記録 (GX Act emission record)"},
    ],
    "送電線": [
        {"item_code": "TL-01", "description": "外観点検 (visual inspection)"},
        {"item_code": "TL-02", "description": "たるみ確認 (sag check)"},
        {"item_code": "TL-03", "description": "絶縁確認 (insulation check)"},
        {"item_code": "TL-04", "description": "支持物確認 (support structure check)"},
        {"item_code": "GX-01", "description": "GX推進法 排出量記録 (GX Act emission record)"},
    ],
    "発電設備": [
        {"item_code": "GEN-01", "description": "外観点検 (visual inspection)"},
        {"item_code": "GEN-02", "description": "回転数確認 (RPM check)"},
        {"item_code": "GEN-03", "description": "振動確認 (vibration check)"},
        {"item_code": "GEN-04", "description": "油圧確認 (oil pressure check)"},
        {"item_code": "GEN-05", "description": "温度確認 (temperature reading)"},
        {"item_code": "GX-01", "description": "GX推進法 排出量記録 (GX Act emission record)"},
        {"item_code": "GX-02", "description": "GX推進法 効率記録 (GX Act efficiency record)"},
    ],
    "石油精製設備": [
        {"item_code": "REF-01", "description": "外観点検 (visual inspection)"},
        {"item_code": "REF-02", "description": "圧力確認 (pressure check)"},
        {"item_code": "REF-03", "description": "温度確認 (temperature reading)"},
        {"item_code": "REF-04", "description": "H2S検知確認 (H2S detection check)"},
        {"item_code": "REF-05", "description": "漏洩点検 (leak inspection)"},
        {"item_code": "GX-01", "description": "GX推進法 排出量記録 (GX Act emission record)"},
    ],
    "unknown": [
        {"item_code": "GEN-01", "description": "外観点検 (visual inspection)"},
        {"item_code": "GX-01", "description": "GX推進法 排出量記録 (GX Act emission record)"},
    ],
}

# Keywords in the report that signal a mandatory item is "present" (passed).
_COMPLETION_MARKERS = [
    "実施",
    "確認",
    "完了",
    "実施済",
    "点検済",
    "ok",
    "ок",
    "完",
    "✓",
    "○",
    "◯",
    "checked",
    "completed",
    "passed",
    "done",
    "verified",
]


def _item_is_present(text_lower: str, item: Dict[str, str]) -> bool:
    """Return True if the inspection report contains markers for the given item.

    Checks by item code, description keywords, and Japanese description fragments.
    """
    code = item["item_code"].lower()
    desc = item["description"].lower()

    # Extract Japanese part (before parenthesis).
    ja_part = desc.split("(")[0].strip()

    # Check for item code presence.
    if code in text_lower:
        # Item code found — check if a completion marker is nearby.
        idx = text_lower.find(code)
        context = text_lower[max(0, idx - 20) : min(len(text_lower), idx + 100)]
        if any(marker in context for marker in _COMPLETION_MARKERS):
            return True

    # Check for Japanese description keyword.
    if ja_part and ja_part in text_lower:
        idx = text_lower.find(ja_part)
        context = text_lower[max(0, idx - 10) : min(len(text_lower), idx + 100)]
        if any(marker in context for marker in _COMPLETION_MARKERS):
            return True

    return False


def _catalogue() -> Dict[str, Dict[str, str]]:
    """Return every catalogued item keyed by code (first definition wins)."""
    by_code: Dict[str, Dict[str, str]] = {}
    for items in _DEFAULT_MANDATORY_ITEMS.values():
        for item in items:
            by_code.setdefault(item["item_code"], item)
    return by_code


def _resolve_checklist(equipment_type: str, caller_codes: List[str]) -> List[Dict[str, str]]:
    """Return the checklist to verify for this run.

    With no caller codes, the built-in checklist for the equipment type (or the
    generic fallback) applies. With caller codes, exactly those codes are
    checked, each rendered with its catalogued description; a code that is not
    catalogued renders as the code itself, so an operator's own checklist item
    is still reported without letting caller text into the alert.
    """
    if not caller_codes:
        return [
            dict(item) for item in _DEFAULT_MANDATORY_ITEMS.get(equipment_type, _DEFAULT_MANDATORY_ITEMS["unknown"])
        ]
    catalogue = _catalogue()
    return [dict(catalogue.get(code, {"item_code": code, "description": code})) for code in caller_codes]


# ---------------------------------------------------------------------------
# Node
# ---------------------------------------------------------------------------


class CheckMandatoryItemsNode(FunctionNode):
    """Verify all mandatory inspection items are present and completed.

    Inner DomainWorkflowGraph node 5 for ENE-C2-011.

    Scans the validated inspection report text for evidence that each item on
    the resolved checklist is present with a completion marker. Items not found
    are reported as missing_mandatory_items.

    Output (partial dict — only changed keys):
        missing_mandatory_items, mandatory_check_passed, status, error_log.
    """

    required_trust_level: ClassVar[TrustLevel] = TrustLevel.ANONYMOUS

    def execute(self, state: Dict[str, Any]) -> Dict[str, Any]:
        error_log: List[str] = list(state.get("error_log") or [])
        # Fall back to user_input (inner graph context — see ParseSensorDataNode comment).
        validated_input: str = state.get("validated_input") or state.get("user_input", "")
        equipment_type: str = state.get("equipment_type") or "unknown"

        if not validated_input.strip():
            return {
                "missing_mandatory_items": [],
                "mandatory_check_passed": True,
                "status": AgentStatus.SUCCESS.value,
                "error_log": error_log,
            }

        # ------------------------------------------------------------------
        # 1. Resolve the checklist for this run.
        # ------------------------------------------------------------------
        settings: Dict[str, Any] = state.get("inspection_settings") or {}
        caller_codes: List[str] = list(settings.get("mandatory_item_codes") or [])
        items_to_check: List[Dict[str, str]] = _resolve_checklist(equipment_type, caller_codes)

        # ------------------------------------------------------------------
        # 2. Scan report for each mandatory item.
        # ------------------------------------------------------------------
        text_lower = validated_input.lower()
        missing: List[Dict[str, str]] = []

        for item in items_to_check:
            present = _item_is_present(text_lower, item)
            if not present:
                missing.append(
                    {
                        "item_code": item["item_code"],
                        "description": item["description"],
                        "equipment_ref": equipment_type,
                    }
                )

        mandatory_check_passed = len(missing) == 0

        # ------------------------------------------------------------------
        # 3. Audit trace.
        # ------------------------------------------------------------------
        emit_trace_event(
            "mandatory_items_checked",
            {
                "equipment_type": equipment_type,
                "total_items": len(items_to_check),
                "missing_count": len(missing),
                "mandatory_check_passed": mandatory_check_passed,
            },
            state,
        )

        if missing:
            logger.warning(
                "CheckMandatoryItemsNode: %d mandatory items missing for equipment_type=%s: %s",
                len(missing),
                equipment_type,
                [m["item_code"] for m in missing],
            )
        else:
            logger.info(
                "CheckMandatoryItemsNode: all %d mandatory items present for equipment_type=%s",
                len(items_to_check),
                equipment_type,
            )

        return {
            "missing_mandatory_items": missing,
            "mandatory_check_passed": mandatory_check_passed,
            "status": AgentStatus.SUCCESS.value,
            "error_log": error_log,
        }

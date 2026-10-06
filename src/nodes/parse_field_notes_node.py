"""AgentCore Platform v1.0"""

# Node contract:
#  - Extend FunctionNode; implement execute(state) -> dict
#  - Return ONLY the fields this node changes (never full state)
#  - Return the status as AgentStatus.<X>.value — the enum's string value,
#    not the enum object itself
#  - Never import from mediator/, api/, or other agents
#
# ENE-C2-011 — ParseFieldNotesNode
# Inner DomainWorkflowGraph node 3: extract anomaly-relevant observations from
# the field notes text section of the inspection report.
#
# Input state keys:
#   validated_input: str — sanitized inspection report text
#   equipment_type:  str — canonical equipment type
#
# Output state keys (partial dict):
#   field_note_observations: list[dict] — extracted observations with equipment refs
#   status: AgentStatus string value
#   error_log: list[str] — accumulated errors

import logging
import re
from typing import Any, ClassVar, Dict, List, Set

from framework.nodes.function_node import FunctionNode
from framework.schemas.agent_status import AgentStatus
from framework.schemas.trust_level import TrustLevel

from shared.utils.audit_logger import emit_trace_event

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Observation extraction patterns.
# Scan for lines / clauses containing anomaly-related keywords.
# ---------------------------------------------------------------------------

# Keywords that signal a noteworthy field observation.
_ANOMALY_KEYWORDS = [
    # Japanese
    "異常",
    "不具合",
    "損傷",
    "劣化",
    "腐食",
    "漏れ",
    "過熱",
    "過負荷",
    "振動",
    "雑音",
    "異臭",
    "変色",
    "破損",
    "クラック",
    "亀裂",
    "傾き",
    "ゆるみ",
    "固着",
    "焦げ",
    "発熱",
    "変形",
    "さび",
    "水",
    "汚れ",
    # English
    "abnormal",
    "fault",
    "damage",
    "wear",
    "corrosion",
    "leak",
    "overheat",
    "overload",
    "vibration",
    "noise",
    "odor",
    "discolor",
    "crack",
    "tilt",
    "loose",
    "seized",
    "burn",
    "heat",
    "deform",
    "rust",
    "water",
    "stain",
    "warning",
    "critical",
    "alert",
    "inspect",
]

# Sentence / clause splitter (Japanese and ASCII punctuation).
_CLAUSE_SPLIT_RE = re.compile(r"[。．！？!?\n]+")

# Equipment codes as they are written in inspection reports: hyphen-joined
# uppercase alphanumeric segments carrying at least one digit — TR-001, CB-23,
# SKF-6205, SUB-01, ENE-FAC-20260712-001 — or an unhyphenated form like TR001.
#
# The single-character guards on each side are what make the match a WHOLE
# identifier. Without them the pattern matches a prefix and reports a truncated
# reference: "ENE-FAC-20260712-001" would be recorded as "FAC-20260712", which
# points at no real asset. Python lookbehinds must be fixed width, and a
# one-character class satisfies that while covering every character that can
# continue an identifier.
_EQUIPMENT_CODE_RE = re.compile(
    r"(?<![A-Za-z0-9-])" r"(?:[A-Z][A-Z0-9]*(?:-[A-Z0-9]+){1,3}|[A-Z]{1,6}\d{2,})" r"(?![A-Za-z0-9-])"
)

# Equipment named in prose rather than by code.
_EQUIPMENT_NAME_RE = re.compile(
    r"(?:変圧器|遮断器|変電器|発電機|ポンプ|弁|タンク|モーター|送電線)[番号]?\d*"
    r"|(?:transformer|breaker|generator|pump|valve|tank|motor|line)\s*\d+",
    re.IGNORECASE | re.UNICODE,
)


def _find_equipment_ref(clause: str) -> str:
    """Return the equipment reference named in *clause*, or "" when none is.

    A code wins over a prose name, and it is returned exactly as written — the
    reference is what an operator uses to find the asset, so a reformatted or
    shortened one is worse than none.
    """
    for match in _EQUIPMENT_CODE_RE.finditer(clause):
        token = match.group(0)
        if any(character.isdigit() for character in token):
            return token
    name_match = _EQUIPMENT_NAME_RE.search(clause)
    return name_match.group(0) if name_match else ""


# Severity hints from keywords.
_CRITICAL_KEYWORDS = frozenset(
    [
        "異常",
        "過熱",
        "過負荷",
        "漏れ",
        "クラック",
        "亀裂",
        "破損",
        "abnormal",
        "overheat",
        "overload",
        "leak",
        "crack",
        "damage",
        "critical",
    ]
)

_WARNING_KEYWORDS = frozenset(
    [
        "不具合",
        "劣化",
        "腐食",
        "振動",
        "異臭",
        "変色",
        "発熱",
        "fault",
        "wear",
        "corrosion",
        "vibration",
        "odor",
        "discolor",
        "heat",
        "warning",
    ]
)


def _extract_observations(text: str, equipment_type: str) -> List[Dict[str, Any]]:
    """Extract anomaly-relevant observations from report text.

    Returns list of:
      {"observation": str, "equipment_ref": str, "severity_hint": "critical"|"warning"|"info"}
    """
    # Find the field notes section (heuristic: text after 「現地メモ」,「点検コメント」,
    # 「備考」, "field notes", "comments" markers; fall back to full text).
    section_markers = ["現地メモ", "点検コメント", "備考", "コメント", "field notes", "comments", "notes"]
    section_text = text
    text_lower = text.lower()
    for marker in section_markers:
        idx = text_lower.find(marker.lower())
        if idx >= 0:
            section_text = text[idx:]
            break

    observations: List[Dict[str, Any]] = []
    seen_obs: Set[str] = set()

    for clause in _CLAUSE_SPLIT_RE.split(section_text):
        clause = clause.strip()
        if len(clause) < 3:
            continue

        clause_lower = clause.lower()

        # Check if clause contains an anomaly keyword.
        matched_keyword = next((kw for kw in _ANOMALY_KEYWORDS if kw.lower() in clause_lower), None)
        if matched_keyword is None:
            continue

        # Deduplicate on clause text.
        if clause in seen_obs:
            continue
        seen_obs.add(clause)

        # Name the asset the observation is about; fall back to the equipment
        # type when the note does not identify one.
        equipment_ref = _find_equipment_ref(clause) or equipment_type

        # Determine severity hint from the matched keyword.
        kw_lower = matched_keyword.lower()
        if kw_lower in _CRITICAL_KEYWORDS or any(crit.lower() in clause_lower for crit in _CRITICAL_KEYWORDS):
            severity_hint = "critical"
        elif kw_lower in _WARNING_KEYWORDS or any(warn.lower() in clause_lower for warn in _WARNING_KEYWORDS):
            severity_hint = "warning"
        else:
            severity_hint = "info"

        observations.append(
            {
                "observation": clause,
                "equipment_ref": equipment_ref,
                "severity_hint": severity_hint,
            }
        )

    return observations


# ---------------------------------------------------------------------------
# Node
# ---------------------------------------------------------------------------


class ParseFieldNotesNode(FunctionNode):
    """Extract anomaly-relevant observations from field notes text.

    Inner DomainWorkflowGraph node 3 for ENE-C2-011.

    Uses keyword-based clause extraction to find anomaly-related field notes.
    Each extracted observation is tagged with an equipment reference (if present)
    and a severity hint based on the keywords found.

    Output (partial dict — only changed keys):
        field_note_observations, status, error_log.
    """

    required_trust_level: ClassVar[TrustLevel] = TrustLevel.ANONYMOUS

    def execute(self, state: Dict[str, Any]) -> Dict[str, Any]:
        error_log: List[str] = list(state.get("error_log") or [])
        # Fall back to user_input (inner graph context — see ParseSensorDataNode comment).
        validated_input: str = state.get("validated_input") or state.get("user_input", "")
        equipment_type: str = state.get("equipment_type") or "unknown"

        if not validated_input.strip():
            return {
                "field_note_observations": [],
                "status": AgentStatus.SUCCESS.value,
                "error_log": error_log,
            }

        # ------------------------------------------------------------------
        # 1. Extract field note observations.
        # ------------------------------------------------------------------
        observations = _extract_observations(validated_input, equipment_type)

        # ------------------------------------------------------------------
        # 2. Audit trace (observation count only — no raw notes text).
        # ------------------------------------------------------------------
        emit_trace_event(
            "field_notes_parsed",
            {
                "equipment_type": equipment_type,
                "observations_count": len(observations),
                "critical_hints": sum(1 for o in observations if o.get("severity_hint") == "critical"),
                "warning_hints": sum(1 for o in observations if o.get("severity_hint") == "warning"),
            },
            state,
        )

        logger.info(
            "ParseFieldNotesNode: extracted %d observations from field notes",
            len(observations),
        )

        return {
            "field_note_observations": observations,
            "status": AgentStatus.SUCCESS.value,
            "error_log": error_log,
        }

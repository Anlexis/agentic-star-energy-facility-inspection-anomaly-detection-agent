"""AgentCore Platform v1.0"""

# ENE-C2-011 — the published rendering schema for the anomaly alert.
#
# The alert this agent returns reports what an inspection found; it is not a
# channel for handing the submitted report back. Two bounds make that concrete:
#
#   - every free-text excerpt carried out of the report is truncated to
#     MAX_EXCERPT_CHARS;
#   - at most MAX_RENDERED_FINDINGS findings are rendered, ordered
#     critical → warning → info, so the cap can only ever drop informational
#     findings and a critical finding is never suppressed.
#
# Both bounds are applied twice, on purpose: GenerateAnomalyAlertNode applies
# them when it builds the alert, and SecurityGateOutputNode re-derives them
# from the alert it is handed at the output boundary. The constants live here
# so the two layers cannot drift apart while still being independent checks.
#
# They are deliberately NOT caller-configurable — widening them is exactly what
# the invariant exists to prevent.

from typing import Any, Dict, List

# Longest free-text excerpt any single finding may carry out of the report.
MAX_EXCERPT_CHARS = 240

# Most findings the alert renders.
MAX_RENDERED_FINDINGS = 50

# Appended to an excerpt that was shortened, so a reader can tell the text was
# bounded rather than the observation ending there.
TRUNCATION_MARK = "…"

# Severity ordering applied before the finding cap.
SEVERITY_ORDER: Dict[str, int] = {"critical": 0, "warning": 1, "info": 2}

# The finding keys that carry free text out of the report. ONLY these are ever
# rewritten — identifiers, item codes, alert ids and sensor readings are copied
# through byte-for-byte.
EXCERPT_KEYS = ("description",)


def bound_excerpt(value: Any) -> Any:
    """Truncate one free-text excerpt to MAX_EXCERPT_CHARS.

    Non-strings are returned untouched: the bound applies to prose carried out
    of the report, not to structured values.
    """
    if not isinstance(value, str) or len(value) <= MAX_EXCERPT_CHARS:
        return value
    return value[:MAX_EXCERPT_CHARS].rstrip() + TRUNCATION_MARK


def order_by_severity(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Return *findings* ordered critical → warning → info.

    A stable sort, so findings of equal severity keep the order the pipeline
    produced them in.
    """
    return sorted(findings, key=lambda f: SEVERITY_ORDER.get(str(f.get("severity")), 3))

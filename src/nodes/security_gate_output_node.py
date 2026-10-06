"""AgentCore Platform v1.0"""

# Node contract:
#  - Extend FunctionNode; implement execute(state) -> dict
#  - Return ONLY the fields this node changes (never full state)
#  - Return the status as AgentStatus.<X>.value — the enum's string value,
#    not the enum object itself
#  - Never import from mediator/, api/, or other agents
#
# ENE-C2-011 — SecurityGateOutputNode
# Outer backbone post_process slot — the output boundary.
#
# Reads state["anomaly_alert"] (the structured alert produced by
# GenerateAnomalyAlertNode and forwarded by FacilityInspectionGraphNode.merge_output())
# and state["result"] (its JSON rendering), and independently enforces the two
# invariants this template publishes about its external output. "Independently"
# is the point: GenerateAnomalyAlertNode already applies the rendering bounds,
# and this gate re-derives them from the alert it is handed, so a change to the
# producing node cannot quietly widen what ships.
#
# Invariant 1 — no secret material leaves the agent.
#   The rendered alert is scanned for credential shapes. A hit blocks the whole
#   output and replaces it with a fixed notice; nothing partial ships.
#
# Invariant 2 — findings, not the inspection record.
#   The alert reports what was found; it is not a channel for re-emitting the
#   submitted report. Every free-text excerpt carried out of the report is
#   truncated to a bounded length, and the number of rendered findings is
#   capped. The cap keeps critical findings first, so it can never drop one:
#   a critical finding is non-suppressible (電気事業法 保安規程 / GX推進法), and
#   that holds against the cap, against the caller's parameters, and against
#   the summary the alert carries — the gate recomputes the severity counts and
#   the critical flag from what it is actually about to publish.
#
# Layer order (deliberate): the credential scan runs on the alert as received,
# BEFORE any bounding, and again on the final rendering. A pattern scan is
# order-sensitive in a way that field-level redaction is not — truncating a
# free-text field first could cut a secret in half and leave the remainder
# unrecognisable to every pattern, so the scan never runs only after a
# transform. The bounding itself is field-scoped: it rewrites designated
# free-text excerpts and nothing else, so equipment identifiers, item codes,
# alert ids and sensor readings ship byte-identical.
#
# This template renders no monetary aggregates, so the currency-rounding
# rendering grid used by financial templates does not apply here; the two
# invariants above are what this output boundary enforces.
#
# Audit: each layer emits its own event (電気事業法 保安規程 / GX推進法 audit
# requirements). Facility topology data is never included in an audit payload —
# only the alert_id, counts and the outcome.
#
# NOTE: _screen_output is a MODULE-LEVEL function (not an instance method).
# Never implement an output screen as a FunctionNode instance method — the
# framework auto-wraps methods and the wrapped hook returns None on the clean
# path, causing AttributeError when the graph passes None as the next node's
# state.

import json
import logging
import re
from typing import Any, ClassVar, Dict, List, Optional, Tuple

from framework.nodes.function_node import FunctionNode
from framework.schemas.agent_state import AgentState
from framework.schemas.agent_status import AgentStatus
from framework.schemas.trust_level import TrustLevel
from framework.security.credential_detector import detect_credentials

from shared.utils.audit_logger import emit_trace_event
from src.services.failure_message import EMPTY_INPUT, INPUT_REJECTED, INVALID_VALUE, TOO_LONG
from src.nodes.output_schema import (
    EXCERPT_KEYS,
    MAX_EXCERPT_CHARS,
    MAX_RENDERED_FINDINGS,
    bound_excerpt,
    order_by_severity,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Invariant 1 — credential shapes (module-level, not class-level).
#
# framework.security.credential_detector covers Stripe/OpenAI keys, JWTs, AWS
# access key ids, Bearer tokens and database connection strings, and the
# framework applies it to this node's own return value. Screening with it here
# means a hit is BLOCKED with an audit event rather than raised as an
# unhandled gate error, and the patterns below extend it with the shapes an
# inspection report is most likely to carry: credential assignments pasted out
# of a device console, and private key blocks.
# ---------------------------------------------------------------------------

_EXTRA_CREDENTIAL_PATTERNS: List[Tuple[str, "re.Pattern[str]"]] = [
    (
        "credential_assignment",
        re.compile(
            r"\b(?:password|passwd|secret|api_key|apikey|token|access_key|private_key)\s*[:=]\s*\S{8,}",
            re.IGNORECASE,
        ),
    ),
    (
        "private_key_block",
        re.compile(
            r"-----BEGIN(?:\s+[A-Z0-9]+)*\s+PRIVATE KEY-----",
            re.IGNORECASE,
        ),
    ),
    ("generic_api_key", re.compile(r"\b(?:pk|ak)-[A-Za-z0-9]{16,}")),
]

# ---------------------------------------------------------------------------
# Invariant 2 — the published rendering bounds live in src/nodes/output_schema.py
# and are shared with the producing node; see that module for what they mean.
# ---------------------------------------------------------------------------

_BLOCKED_NOTICE = (
    "[OUTPUT BLOCKED — credential-shaped content was detected in the anomaly alert. "
    "Remove the credential from the inspection report and resubmit.]"
)


# ---------------------------------------------------------------------------
# Module-level screens.
# ---------------------------------------------------------------------------


def _screen_output(content: str) -> Optional[str]:
    """Return the name of the first credential shape found in *content*, else None.

    Called from SecurityGateOutputNode.execute() as a module-level function —
    never implemented as an instance method on FunctionNode.
    """
    findings = detect_credentials(content)
    if findings:
        credential_type = findings[0].get("type")
        return str(credential_type) if credential_type else "credential"
    for name, pattern in _EXTRA_CREDENTIAL_PATTERNS:
        if pattern.search(content):
            return name
    return None


def _enforce_rendering_schema(alert: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, int]]:
    """Apply the published rendering bounds to *alert*.

    Returns ``(enforced_alert, adjustments)`` where *adjustments* counts what
    the gate had to change: excerpts shortened, findings dropped, and whether
    the alert's own severity summary understated what is rendered.

    The input alert is never mutated. Only the designated free-text excerpt
    fields are rewritten; every identifier, code and numeric value is copied
    through unchanged.
    """
    enforced: Dict[str, Any] = dict(alert)
    findings_raw = alert.get("anomalies")
    findings: List[Dict[str, Any]] = (
        [f for f in findings_raw if isinstance(f, dict)] if isinstance(findings_raw, list) else []
    )

    # Critical first, then warning, then info, so the cap below can only ever
    # drop informational findings.
    ordered = order_by_severity(findings)
    kept = ordered[:MAX_RENDERED_FINDINGS]
    dropped = len(ordered) - len(kept)

    shortened = 0
    rendered: List[Dict[str, Any]] = []
    for finding in kept:
        copy = dict(finding)
        for key in EXCERPT_KEYS:
            bounded = bound_excerpt(copy.get(key))
            if bounded is not copy.get(key):
                shortened += 1
            copy[key] = bounded
        rendered.append(copy)

    enforced["anomalies"] = rendered

    # Recompute the summary from what is actually rendered. A critical finding
    # is non-suppressible, so the published flag is derived here rather than
    # trusted from upstream.
    summary = {
        level: sum(1 for f in rendered if f.get("severity") == level) for level in ("critical", "warning", "info")
    }
    has_critical = summary["critical"] > 0
    summary_corrected = int(alert.get("severity_summary") != summary or bool(alert.get("has_critical")) != has_critical)
    enforced["severity_summary"] = summary
    enforced["has_critical"] = has_critical
    enforced["anomaly_count"] = len(rendered)

    # State the bounds in the alert itself, so a reader of the JSON knows what
    # the numbers above are counts of.
    enforced["rendering_schema"] = {
        "max_excerpt_chars": MAX_EXCERPT_CHARS,
        "max_rendered_findings": MAX_RENDERED_FINDINGS,
        "ordering": "critical, warning, info",
        "note": (
            "Free-text excerpts are truncated to max_excerpt_chars and at most "
            "max_rendered_findings findings are rendered, highest severity first. "
            "Critical findings are never dropped. Identifiers, item codes and "
            "sensor readings are reported exactly as recorded."
        ),
    }

    return enforced, {
        "excerpts_shortened": shortened,
        "findings_dropped": dropped,
        "summary_corrected": summary_corrected,
    }


def _render(alert: Dict[str, Any]) -> str:
    """Serialize an alert for the caller. Returns "" when it cannot be rendered."""
    try:
        return json.dumps(alert, ensure_ascii=False, default=str)
    except (TypeError, ValueError):
        return ""


# ---------------------------------------------------------------------------
# Node
# ---------------------------------------------------------------------------


# Reason code -> the sentence the caller reads. A code with no entry falls
# back to the generic one rather than leaking the code itself.
_DEGRADED_MESSAGES = {
    "EMPTY_INPUT": EMPTY_INPUT,
    "QUESTION_TOO_LONG": TOO_LONG,
    "INVALID_REQUEST": INVALID_VALUE,
}


class SecurityGateOutputNode(FunctionNode):
    """Output boundary for ENE-C2-011.

    Outer backbone post_process slot.

    Reads the structured alert produced by GenerateAnomalyAlertNode (forwarded
    via FacilityInspectionGraphNode.merge_output()), screens it for credential
    material, enforces the published rendering bounds on it, re-screens the
    final rendering, and writes the result to formatted_output.

    A credential hit blocks the output with a fixed notice and ERROR status.
    A bounds adjustment is applied and audited, never blocked — the alert still
    ships, carrying only what the published schema allows.

    Emits an audit event per layer (電気事業法 保安規程 / GX推進法). Facility
    topology data is not included in audit payloads.
    """

    # ANONYMOUS: the post_process output boundary screens ALL output regardless
    # of caller trust level. The entry-point gate is where caller trust is
    # enforced (ValidateInputNode, VERIFIED_EXTERNAL).
    required_trust_level: ClassVar[TrustLevel] = TrustLevel.ANONYMOUS

    def execute(self, state: AgentState) -> Dict[str, Any]:
        # A run declined upstream has nothing to format. Render the reason as
        # the caller-facing body and carry the marker onward.
        marker = state.get("error_code")
        if marker:
            message = _DEGRADED_MESSAGES.get(marker, INPUT_REJECTED)
            emit_trace_event("post_process_degraded", {"reason": marker}, state)
            return {
                "status": AgentStatus.SUCCESS.value,
                "error_code": marker,
                "result": message,
                "formatted_output": message,
            }
        error_log: List[str] = list(state.get("error_log") or [])
        result: str = state.get("result") or ""
        alert_raw = state.get("anomaly_alert")
        alert: Dict[str, Any] = alert_raw if isinstance(alert_raw, dict) else {}
        alert_id = str(alert.get("alert_id", "unknown"))

        # ------------------------------------------------------------------
        # 1. Nothing to publish (out-of-scope report, or no alert produced).
        # ------------------------------------------------------------------
        if not alert and not result.strip():
            logger.warning("SecurityGateOutputNode: no alert to publish — output boundary skipped")
            emit_trace_event(
                "output_gate_empty",
                {"alert_id": alert_id, "outcome": "empty_skip"},
                state,
            )
            return {
                "formatted_output": result,
                "status": AgentStatus.SUCCESS.value,
            }

        # ------------------------------------------------------------------
        # 2. Credential screen on the alert AS RECEIVED — before any bounding,
        #    so no transform can cut a secret out of recognisability.
        # ------------------------------------------------------------------
        incoming = result if result.strip() else _render(alert)
        violation = _screen_output(incoming)

        if violation is None and alert:
            # ------------------------------------------------------------------
            # 3. Enforce the published rendering bounds.
            # ------------------------------------------------------------------
            enforced_alert, adjustments = _enforce_rendering_schema(alert)
            rendered = _render(enforced_alert)
            if not rendered:
                emit_trace_event(
                    "output_gate_blocked",
                    {"alert_id": alert_id, "violation_type": "unrenderable_alert", "outcome": "blocked"},
                    state,
                )
                return {
                    # The alert is dropped from state as well as from the
                    # rendering: a caller-facing field that still carried the
                    # unpublished alert would be a second, unscreened copy of
                    # the very content this path refused to publish.
                    "anomaly_alert": None,
                    "result": _BLOCKED_NOTICE,
                    "formatted_output": _BLOCKED_NOTICE,
                    "status": AgentStatus.ERROR.value,
                    "error_log": error_log + ["SecurityGateOutputNode: the anomaly alert could not be rendered safely"],
                }

            if any(adjustments.values()):
                emit_trace_event(
                    "output_schema_enforced",
                    {"alert_id": alert_id, **adjustments, "outcome": "adjusted"},
                    state,
                )

            # ------------------------------------------------------------------
            # 4. Re-screen the exact bytes that will ship.
            # ------------------------------------------------------------------
            violation = _screen_output(rendered)
        else:
            enforced_alert = alert
            rendered = incoming

        if violation:
            logger.error(
                "SecurityGateOutputNode: OUTPUT BLOCKED — %s alert_id=%s",
                violation,
                alert_id,
            )
            emit_trace_event(
                "output_gate_blocked",
                {"alert_id": alert_id, "violation_type": violation, "outcome": "blocked"},
                state,
            )
            return {
                # Dropped from state too — see the note above.
                "anomaly_alert": None,
                "result": _BLOCKED_NOTICE,
                "formatted_output": _BLOCKED_NOTICE,
                "status": AgentStatus.ERROR.value,
                "error_log": error_log
                + [f"SecurityGateOutputNode: output blocked — credential-shaped content " f"detected ({violation})"],
            }

        # ------------------------------------------------------------------
        # 5. Publish (alert metadata only in the audit payload).
        # ------------------------------------------------------------------
        emit_trace_event(
            "output_gate_passed",
            {
                "alert_id": alert_id,
                "result_length": len(rendered),
                "has_critical": bool(enforced_alert.get("has_critical", False)),
                "anomaly_count": enforced_alert.get("anomaly_count", 0),
                "outcome": "passed",
            },
            state,
        )

        logger.info(
            "SecurityGateOutputNode: published alert_id=%s length=%d",
            alert_id,
            len(rendered),
        )

        return {
            "anomaly_alert": enforced_alert or None,
            "result": rendered,
            "formatted_output": rendered,
            "has_critical": bool(enforced_alert.get("has_critical", False)),
            "status": AgentStatus.SUCCESS.value,
        }

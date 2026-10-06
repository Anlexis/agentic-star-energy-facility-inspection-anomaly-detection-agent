"""AgentCore Platform v1.0"""

# Standalone HTTP entry point for the agent.
# Entry points are adapters only — no business logic here.
# For platform-level routing, the platform gateway calls agent.invoke() directly.

import json
import os
import secrets
from typing import Any
from uuid import uuid4

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel

from framework.schemas.invocation_context import InvocationContext
from framework.schemas.trust_level import TrustLevel
from framework.secrets.context import bound_secrets
from shared.secrets import factory as secrets_factory
from src.graph.graph import FacilityInspectionAnomalyDetectionAgent, _runtime_config

app = FastAPI(title="Agent")

# The platform registry loads config/config.yaml and passes it as
# Graph(config=...); the standalone server mirrors that exactly so declared
# runtime parameters (max_retry, severity thresholds) are live in both
# deployments.
agent = FacilityInspectionAnomalyDetectionAgent(config=_runtime_config())
agent.compile()
# Namespace matches the manifest `namespace`; agent_name matches the registered
# agent name (config/agent.yaml + the graph's `name` property).
agent.provision_secrets(secrets_factory(namespace="ene", agent_name="ene_c2_011"))

# Upper bound on the serialized input_context (bytes). ValidateInputNode
# enforces per-field bounds (identifier alphabet, finite numeric ranges, entry
# caps); this is the coarse adapter-level guard against an oversized payload
# reaching the graph at all.
_MAX_INPUT_CONTEXT_BYTES = 262_144


class InvokeRequest(BaseModel):
    input: str
    session_id: str = ""
    # Structured invocation parameters (see src/nodes/caller_context.py):
    # equipment_type, critical_deviation_pct, warning_deviation_pct,
    # baseline_overrides, mandatory_item_codes — validated field by field
    # inside the graph, in ValidateInputNode.
    input_context: dict[str, Any] | None = None


@app.post("/invoke")
async def invoke(req: InvokeRequest, request: Request) -> Any:
    trust = getattr(request.state, "trust_level", TrustLevel.ANONYMOUS)
    # Standalone-deployment caller auth: when INVOKE_AUTH_TOKEN is set on the
    # server environment, callers that no upstream middleware vouched for
    # (still ANONYMOUS) must present it as a Bearer token and run at
    # VERIFIED_EXTERNAL. Middleware-established trust is never demoted.
    # This adapter is the entry-point auth boundary (the standalone equivalent
    # of the platform's auth middleware) — a deployment-level caller credential,
    # not an agent secret, so ctx.secrets does not apply: no InvocationContext
    # exists before auth. That is the documented entry-point exception.
    #
    # Required here specifically: ValidateInputNode (src/nodes/validate_input_node.py)
    # occupies the pre_process backbone slot and declares required_trust_level =
    # TrustLevel.VERIFIED_EXTERNAL. Nothing else sets request.state.trust_level in
    # the standalone deployment, so without this boundary every deployed invoke
    # arrives ANONYMOUS, the trust gate denies it, and the agent returns an error
    # for every caller.
    expected = os.environ.get("INVOKE_AUTH_TOKEN")
    if expected and trust is TrustLevel.ANONYMOUS:
        supplied = request.headers.get("authorization", "")
        # Compare bytes: compare_digest raises TypeError on non-ASCII str input
        # (headers decode as latin-1), which would 500 instead of the generic 401.
        if not secrets.compare_digest(supplied.encode(), f"Bearer {expected}".encode()):
            # Generic body on purpose — do not leak whether the token was absent,
            # malformed, or wrong.
            raise HTTPException(status_code=401, detail="Token is invalid or expired.")
        trust = TrustLevel.VERIFIED_EXTERNAL
    input_context = req.input_context or {}
    if input_context and len(json.dumps(input_context, default=str)) > _MAX_INPUT_CONTEXT_BYTES:
        raise HTTPException(status_code=413, detail="input_context exceeds the maximum allowed size.")
    with bound_secrets(agent._secrets_provider):
        ctx = InvocationContext(
            session_id=req.session_id or str(uuid4()),
            caller_trust_level=trust,
            caller_id=getattr(request.state, "caller_id", ""),
        )
        return agent.invoke(req.input, ctx=ctx, input_context=input_context)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "agent": "ene_c2_011"}

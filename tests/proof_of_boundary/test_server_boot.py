# PB: Entry-point auth boundary — src/api/server.py
#
# Covers the standalone-server trust-level boundary for POST /invoke.
#
# Why this file exists (the concrete failure it prevents):
#   ValidateInputNode (src/nodes/validate_input_node.py) occupies the
#   `pre_process` backbone slot and declares
#   required_trust_level = TrustLevel.VERIFIED_EXTERNAL. Nothing in src/api/
#   sets request.state.trust_level — there is no middleware in the standalone
#   deployment — so without the Bearer boundary every deployed invoke arrives
#   ANONYMOUS, the trust gate denies it, and the agent returns an error for
#   every caller.
#
# Contract under test:
#   - INVOKE_AUTH_TOKEN set + no / wrong Bearer   -> 401, generic body
#   - INVOKE_AUTH_TOKEN set + correct Bearer      -> not 401, ctx built at
#                                                    VERIFIED_EXTERNAL
#   - INVOKE_AUTH_TOKEN unset                     -> not 401, ctx stays ANONYMOUS
#   - trust already set by middleware             -> preserved, never demoted
#   - oversized input_context                     -> 413 before the graph runs
#
# The app is driven through its real ASGI interface rather than
# fastapi.testclient.TestClient on purpose: TestClient needs httpx (only a
# transitive framework dependency, and it emits a deprecation warning against
# starlette). A hand-rolled ASGI call keeps this boundary test dependency-free
# so it can never silently skip in CI.
#
# The domain pipeline is stubbed out (see the `recorder` fixture): this file
# tests the ENTRY-POINT auth boundary only, so it must not depend on the
# agent's domain behaviour.

import asyncio
import json

import pytest

# Importing the module IS the boot check: it constructs the app, builds the
# agent, compiles the graph and provisions secrets at import time.
import src.api.server as server_module
from src.api.server import app

_TOKEN = "pb-server-boot-token"
_PAYLOAD = {
    "input": "設備種別: 変電設備\nセンサ計測値:\n温度: 45.0 ℃\n",
    "session_id": "pb-server-boot",
}


def _post_invoke(headers=None, state=None, payload=None):
    """POST /invoke through the real ASGI app. Returns (status_code, body).

    *state* populates ASGI ``scope["state"]``, which is exactly what the web
    framework exposes as ``request.state`` — the channel real auth middleware
    uses to vouch for a caller.
    """
    body = json.dumps(payload if payload is not None else _PAYLOAD).encode()
    raw_headers = [
        (b"content-type", b"application/json"),
        (b"content-length", str(len(body)).encode()),
    ]
    for key, value in (headers or {}).items():
        raw_headers.append((key.lower().encode(), value.encode()))

    scope = {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": "/invoke",
        "raw_path": b"/invoke",
        "root_path": "",
        "query_string": b"",
        "headers": raw_headers,
        "client": ("127.0.0.1", 12345),
        "server": ("127.0.0.1", 8000),
    }
    if state is not None:
        scope["state"] = state

    messages = []
    sent = {"body": b""}

    async def receive():
        return {"type": "http.request", "body": body, "more_body": False}

    async def send(message):
        messages.append(message)
        if message["type"] == "http.response.body":
            sent["body"] += message.get("body", b"")

    asyncio.run(app(scope, receive, send))
    start = next(m for m in messages if m["type"] == "http.response.start")
    return start["status"], json.loads(sent["body"].decode() or "{}")


@pytest.fixture
def recorder(monkeypatch):
    """Replace the compiled agent's invoke with a recorder of the built context."""
    seen = {}

    def fake_invoke(user_input, ctx=None, input_context=None, **kwargs):
        seen["ctx"] = ctx
        seen["input_context"] = input_context
        return {"status": "success", "output": "{}"}

    monkeypatch.setattr(server_module.agent, "invoke", fake_invoke)
    return seen


class TestInvokeAuthBoundary:
    def test_missing_bearer_is_rejected(self, monkeypatch, recorder):
        monkeypatch.setenv("INVOKE_AUTH_TOKEN", _TOKEN)
        status, body = _post_invoke()
        assert status == 401
        assert "ctx" not in recorder, "the graph must not run for an unauthenticated caller"
        assert _TOKEN not in json.dumps(body), "the response must not disclose the expected token"

    @pytest.mark.parametrize(
        "supplied",
        ["Bearer wrong-token", "Basic " + _TOKEN, _TOKEN, "Bearer ", "Bearer " + _TOKEN + "x"],
    )
    def test_wrong_bearer_is_rejected(self, monkeypatch, recorder, supplied):
        monkeypatch.setenv("INVOKE_AUTH_TOKEN", _TOKEN)
        status, _ = _post_invoke(headers={"authorization": supplied})
        assert status == 401
        assert "ctx" not in recorder

    def test_correct_bearer_runs_at_verified_external(self, monkeypatch, recorder):
        from framework.schemas.trust_level import TrustLevel

        monkeypatch.setenv("INVOKE_AUTH_TOKEN", _TOKEN)
        status, _ = _post_invoke(headers={"authorization": f"Bearer {_TOKEN}"})
        assert status == 200
        assert recorder["ctx"].caller_trust_level is TrustLevel.VERIFIED_EXTERNAL

    def test_unset_token_leaves_the_caller_anonymous(self, monkeypatch, recorder):
        from framework.schemas.trust_level import TrustLevel

        monkeypatch.delenv("INVOKE_AUTH_TOKEN", raising=False)
        status, _ = _post_invoke()
        assert status == 200
        assert recorder["ctx"].caller_trust_level is TrustLevel.ANONYMOUS

    def test_middleware_established_trust_is_never_demoted(self, monkeypatch, recorder):
        from framework.schemas.trust_level import TrustLevel

        monkeypatch.setenv("INVOKE_AUTH_TOKEN", _TOKEN)
        status, _ = _post_invoke(state={"trust_level": TrustLevel.INTERNAL, "caller_id": "svc"})
        assert status == 200
        assert recorder["ctx"].caller_trust_level is TrustLevel.INTERNAL
        assert recorder["ctx"].caller_id == "svc"


class TestInputContextAdapterBound:
    def test_oversized_input_context_is_rejected_before_the_graph(self, monkeypatch, recorder):
        monkeypatch.delenv("INVOKE_AUTH_TOKEN", raising=False)
        oversized = {"baseline_overrides": {"temperature_c": {"max": "x" * 300_000}}}
        status, _ = _post_invoke(payload={**_PAYLOAD, "input_context": oversized})
        assert status == 413
        assert "ctx" not in recorder

    def test_input_context_is_forwarded_to_the_graph(self, monkeypatch, recorder):
        monkeypatch.delenv("INVOKE_AUTH_TOKEN", raising=False)
        status, _ = _post_invoke(payload={**_PAYLOAD, "input_context": {"equipment_type": "refinery"}})
        assert status == 200
        assert recorder["input_context"] == {"equipment_type": "refinery"}


def test_health_endpoint_reports_the_agent_name():
    assert server_module.health() == {"status": "ok", "agent": "ene_c2_011"}

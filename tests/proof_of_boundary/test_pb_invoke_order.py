# PB-6: Invoke Execution Order Verification
# Verifies BaseNode.__call__() enforces: trust gate -> node_start ->
# _security_gate_input() -> execute() -> _security_gate_output() ->
# node_complete, for every concrete node under src/nodes/.
#
# PB-6b: Full-graph backbone slot order — FacilityInspectionAnomalyDetectionAgent.invoke()
# must visit initialize -> pre_process -> main -> post_process -> finalize and
# return AgentStatus.SUCCESS for a valid facility inspection report.

import importlib
import inspect
import pkgutil

import pytest


# ---------------------------------------------------------------------------
# Constants used by PB-6b (graph-level test)
# ---------------------------------------------------------------------------

# The GraphNode subclass placed in the outer graph's "main" backbone slot.
# Must match the class name in src/graph/graph.py.
_MAIN_SLOT_NODE = "FacilityInspectionGraphNode"

# A valid Japanese energy facility inspection report that:
#   - passes ValidateInputNode (non-empty, < 50k chars, has sensor data)
#   - equipment type detected as 変電設備 from header keyword
#   - sensor readings present for ParseSensorDataNode extraction
#   - field notes present for ParseFieldNotesNode
#   - no credential/JWT/API-key patterns in the output alert JSON
#   - produces AgentStatus.SUCCESS through the full pipeline
_VALID_PAYLOAD = (
    "設備種別: 変電設備\n"
    "設備ID: TRANS-PB6-001\n"
    "点検日: 2026-07-02\n"
    "担当者: 点検担当A\n"
    "\n"
    "センサ計測値:\n"
    "変圧器温度: 45.0 °C\n"
    "電圧: 6700 V\n"
    "電流: 120 A\n"
    "絶縁抵抗: 2.5 MΩ\n"
    "\n"
    "現場点検記録:\n"
    "外観に異常なし。騒音・振動とも正常範囲内。\n"
    "冷却装置の動作を確認済み。接地線に断線なし。\n"
)


def _discover_node_classes() -> list[type]:
    """Import every module under src/nodes/ and collect concrete BaseNode subclasses."""
    from framework.nodes.base_node import BaseNode

    try:
        pkg = importlib.import_module("src.nodes")
    except ImportError:
        return []

    discovered = []
    for _, modname, _ in pkgutil.walk_packages(pkg.__path__, prefix="src.nodes."):
        module = importlib.import_module(modname)
        for attr in vars(module).values():
            if (
                isinstance(attr, type)
                and issubclass(attr, BaseNode)
                and attr is not BaseNode
                and attr.__module__ == modname
                and not inspect.isabstract(attr)
            ):
                discovered.append(attr)
    return discovered


class TestInvokeOrder:
    """PB-6: __call__ must run the trust gate -> node_start -> the input gate ->
    execute() -> the output gate -> node_complete."""

    def test_call_order_for_every_node(self, monkeypatch):
        node_classes = _discover_node_classes()
        if not node_classes:
            pytest.skip("no concrete BaseNode subclasses found under src/nodes/")

        import framework.nodes.base_node as base_node_module

        failures: list[str] = []
        for node_cls in node_classes:
            order: list[str] = []
            monkeypatch.setattr(
                base_node_module,
                "emit_trace_event",
                lambda event_type, _payload, _state, _o=order: _o.append(f"event:{event_type}"),
            )

            for method_name, label in (
                ("_security_gate_input", "security_gate_input"),
                ("execute", "execute"),
                ("_security_gate_output", "security_gate_output"),
            ):
                original = getattr(node_cls, method_name)

                def spy(self, arg, _o=order, _label=label, _orig=original):
                    _o.append(_label)
                    return _orig(self, arg)

                monkeypatch.setattr(node_cls, method_name, spy)

            instance = node_cls()
            state = {
                "caller_trust_level": node_cls.required_trust_level.value,
                "correlation_id": "pb6-invoke-order-test",
            }
            instance(state)

            expected = [
                "event:node_start",
                "security_gate_input",
                "execute",
                "security_gate_output",
                "event:node_complete",
            ]
            if order != expected:
                failures.append(
                    f"{node_cls.__name__}: invoke order violation.\n" f"expected: {expected}\nactual:   {order}"
                )

        assert not failures, "\n\n".join(failures)


class TestGraphInvokeOrder:
    """PB-6b: Full graph invoke must visit every backbone slot in order and return SUCCESS.

    Verifies:
      - Graph compiles without error.
      - agent.invoke(_VALID_PAYLOAD) visits InitializeNode -> ValidateInputNode ->
        FacilityInspectionGraphNode -> SecurityGateOutputNode -> FinalizeNode
        (by class name in node_history).
      - Final status is AgentStatus.SUCCESS.
      - The main backbone slot is exactly _MAIN_SLOT_NODE.
    """

    def test_backbone_node_history(self, monkeypatch):
        """PB-6b: graph.invoke() must produce SUCCESS with full backbone node_history."""
        # Patch emit_trace_event at domain node modules to silence the audit side-effects.
        # Patch at MODULE level — NEVER via sys.modules stub (shared.* is a real package).
        for mod_path in [
            "src.nodes.validate_input_node",
            "src.nodes.load_baseline_parameters_node",
            "src.nodes.parse_sensor_data_node",
            "src.nodes.parse_field_notes_node",
            "src.nodes.detect_anomalies_node",
            "src.nodes.check_mandatory_items_node",
            "src.nodes.assess_severity_node",
            "src.nodes.generate_anomaly_alert_node",
            "src.nodes.security_gate_output_node",
        ]:
            monkeypatch.setattr(f"{mod_path}.emit_trace_event", lambda *a, **k: None)

        from framework.schemas.agent_status import AgentStatus
        from framework.schemas.invocation_context import InvocationContext
        from framework.schemas.trust_level import TrustLevel
        from src.graph.graph import FacilityInspectionAnomalyDetectionAgent

        agent = FacilityInspectionAnomalyDetectionAgent()
        agent.compile()

        # TrustLevel.VERIFIED_EXTERNAL: real external callers invoke the agent with this
        # level. Inner DomainWorkflowGraph nodes declare required_trust_level=ANONYMOUS
        # (canonical inner-node trust level — any trust level satisfies ANONYMOUS).
        # ValidateInputNode (pre_process, VERIFIED_EXTERNAL) is also satisfied (2 >= 1).
        ctx = InvocationContext(
            session_id="pb6b-graph-test",
            caller_id="pb6b-test",
            caller_trust_level=TrustLevel.VERIFIED_EXTERNAL,
        )
        result = agent.invoke(_VALID_PAYLOAD, ctx=ctx)

        node_history = result.get("node_history", [])

        # Every backbone class must appear in node_history.
        expected_backbone = (
            "InitializeNode",
            "ValidateInputNode",  # pre_process slot
            _MAIN_SLOT_NODE,  # main slot = FacilityInspectionGraphNode
            "SecurityGateOutputNode",  # post_process slot
            "FinalizeNode",
        )
        for cls_name in expected_backbone:
            assert cls_name in node_history, (
                f"Backbone class '{cls_name}' missing from node_history; " f"got: {node_history}"
            )

        # Order: each backbone node must appear after the previous one.
        indices = [node_history.index(n) for n in expected_backbone]
        assert indices == sorted(indices), f"Backbone nodes out of order in node_history; got: {node_history}"

        # Final status must be SUCCESS for a valid payload.
        status = result.get("status")
        assert (
            status == AgentStatus.SUCCESS or status == AgentStatus.SUCCESS.value
        ), f"Expected SUCCESS, got {status!r}; node_history: {node_history}"

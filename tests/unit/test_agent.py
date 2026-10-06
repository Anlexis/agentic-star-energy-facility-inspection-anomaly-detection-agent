"""ENE-C2-011 — Unit tests for the domain nodes.

Covers the per-node behaviour of the Facility Inspection Report Anomaly
Detection Agent. The caller-data contract and the output rendering schema have
their own file (test_caller_contract_and_output_schema.py); end-to-end
behaviour through the HTTP entry point lives under tests/proof_of_boundary/.

All emit_trace_event calls are patched at the module level (never via a
sys.modules stub — the real shared package is installed in CI).
"""

import json
import pathlib

import pytest

from framework.schemas.agent_status import AgentStatus

from src.nodes.output_schema import MAX_EXCERPT_CHARS


# ---------------------------------------------------------------------------
# Autouse fixture: silence the audit side-effects across ALL tests.
# Patch at the specific node module (not shared.*).
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def patch_emit(monkeypatch):
    for mod in [
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
        monkeypatch.setattr(f"{mod}.emit_trace_event", lambda *a, **k: None)


# ---------------------------------------------------------------------------
# ValidateInputNode
# ---------------------------------------------------------------------------


class TestValidateInputNode:
    """Entry gate: input validation for facility inspection reports."""

    def setup_method(self):
        from src.nodes.validate_input_node import ValidateInputNode

        self.node = ValidateInputNode()

    def _state(self, user_input):
        return {
            "user_input": user_input,
            "error_log": [],
            "node_history": [],
            "caller_trust_level": "VERIFIED_EXTERNAL",
        }

    def test_valid_sensor_report_returns_success(self):
        """TC-V-001: Valid report with sensor data returns SUCCESS."""
        report = "設備種別: 変電設備\n" "センサ計測値:\n" "温度: 45.0 °C\n電圧: 6700 V\n電流: 120 A\n"
        result = self.node.execute(self._state(report))
        assert result["status"] == AgentStatus.SUCCESS.value
        assert result["out_of_scope"] is False
        assert result["validated_input"].strip() == report.strip()

    def test_equipment_type_detected_from_header(self):
        """TC-V-002: Equipment type is detected from the first 500 chars."""
        report = "変電設備 点検報告\n温度: 45 °C\n電圧: 6600 V\n"
        result = self.node.execute(self._state(report))
        assert result["status"] == AgentStatus.SUCCESS.value
        assert result["equipment_type"] == "変電設備"

    def test_empty_input_returns_error(self):
        """TC-V-003: Empty or whitespace-only input returns ERROR."""
        result = self.node.execute(self._state(""))
        assert result["status"] == AgentStatus.SUCCESS.value
        assert "error_log" in result
        assert len(result["error_log"]) > 0

    def test_too_short_input_returns_error(self):
        """TC-V-004: Input shorter than 10 chars returns ERROR."""
        result = self.node.execute(self._state("短"))
        assert result["status"] == AgentStatus.SUCCESS.value

    def test_oversized_input_returns_error(self):
        """TC-V-005: Input exceeding 50k chars returns ERROR."""
        big = "温度: 45 °C\n" * 5001  # 50010 chars > 50k limit (5000 * 10 = exactly 50000 = NOT > limit)
        result = self.node.execute(self._state(big))
        assert result["status"] == AgentStatus.SUCCESS.value
        assert any("size limit" in e for e in result["error_log"])

    def test_no_sensor_data_marks_out_of_scope(self):
        """TC-V-006: Report without sensor indicators is out_of_scope=True."""
        non_sensor = "これは全く関係ない文書です。設備点検とは無関係です。内容はありません。"
        result = self.node.execute(self._state(non_sensor))
        assert result["status"] == AgentStatus.SUCCESS.value
        assert result["out_of_scope"] is True

    def test_control_chars_stripped(self):
        """TC-V-007: Control characters are stripped from the report text."""
        report = "変電設備\x00\x01\x1f\n温度: 45 °C\n"
        result = self.node.execute(self._state(report))
        assert result["status"] == AgentStatus.SUCCESS.value
        assert "\x00" not in result["validated_input"]
        assert "\x01" not in result["validated_input"]

    def test_unknown_equipment_type_accepted(self):
        """TC-V-008: Unknown equipment type is accepted (not out-of-scope)."""
        report = "未知設備 点検報告\n温度: 45 °C\n圧力: 1.0 MPa\n"
        result = self.node.execute(self._state(report))
        assert result["status"] == AgentStatus.SUCCESS.value
        assert result["equipment_type"] == "unknown"
        assert result["out_of_scope"] is False


# ---------------------------------------------------------------------------
# AssessSeverityNode
# ---------------------------------------------------------------------------


class TestAssessSeverityNode:
    """Severity classification: critical/warning/info per domain rules."""

    def setup_method(self):
        from src.nodes.assess_severity_node import AssessSeverityNode

        self.node = AssessSeverityNode()

    def _state(self, detected=None, missing=None, equipment_type="変電設備"):
        return {
            "equipment_type": equipment_type,
            "detected_anomalies": detected or [],
            "missing_mandatory_items": missing or [],
            "error_log": [],
            "node_history": [],
            "caller_trust_level": "INTERNAL",
        }

    def test_no_anomalies_no_critical(self):
        """TC-S-001: No anomalies → has_critical=False, SUCCESS."""
        result = self.node.execute(self._state())
        assert result["status"] == AgentStatus.SUCCESS.value
        assert result["has_critical"] is False
        assert result["severity_assessments"] == []

    def test_high_deviation_classified_critical(self):
        """TC-S-002: Sensor deviation >20% → critical."""
        anomaly = {
            "anomaly_id": "A001",
            "description": "温度異常",
            "source": "sensor",
            "severity_hint": "info",
            "deviation_pct": 25.0,
        }
        result = self.node.execute(self._state(detected=[anomaly]))
        assert result["has_critical"] is True
        assessments = result["severity_assessments"]
        assert len(assessments) == 1
        assert assessments[0]["severity"] == "critical"

    def test_moderate_deviation_classified_warning(self):
        """TC-S-003: Sensor deviation 5-20% → warning."""
        anomaly = {
            "anomaly_id": "A002",
            "description": "電圧偏差",
            "source": "sensor",
            "severity_hint": "info",
            "deviation_pct": 8.5,
        }
        result = self.node.execute(self._state(detected=[anomaly]))
        assert result["has_critical"] is False
        assert result["severity_assessments"][0]["severity"] == "warning"

    def test_low_deviation_classified_info(self):
        """TC-S-004: Sensor deviation <5% → info."""
        anomaly = {
            "anomaly_id": "A003",
            "description": "微小偏差",
            "source": "sensor",
            "severity_hint": "info",
            "deviation_pct": 2.0,
        }
        result = self.node.execute(self._state(detected=[anomaly]))
        assert result["severity_assessments"][0]["severity"] == "info"

    def test_corroborated_anomaly_is_critical(self):
        """TC-S-005: source='both' (sensor+field note corroboration) → critical."""
        anomaly = {
            "anomaly_id": "A004",
            "description": "両方から検出",
            "source": "both",
            "severity_hint": "warning",
            "deviation_pct": 5.0,
        }
        result = self.node.execute(self._state(detected=[anomaly]))
        assert result["has_critical"] is True
        assert result["severity_assessments"][0]["severity"] == "critical"

    def test_gx_mandatory_missing_is_critical(self):
        """TC-S-006: Missing GX推進法/電気事業法 item → critical (non-suppressible)."""
        missing_item = {
            "item_code": "GX-001",
            "description": "GX推進法 年次点検",
            "equipment_ref": "変電設備",
        }
        result = self.node.execute(self._state(missing=[missing_item]))
        assert result["has_critical"] is True
        assessment = result["severity_assessments"][0]
        assert assessment["severity"] == "critical"
        assert "non-suppressible" in assessment["rationale"]

    def test_hint_critical_overrides_deviation(self):
        """TC-S-007: severity_hint='critical' → critical even with low deviation."""
        anomaly = {
            "anomaly_id": "A005",
            "description": "緊急アラート",
            "source": "sensor",
            "severity_hint": "critical",
            "deviation_pct": 1.0,
        }
        result = self.node.execute(self._state(detected=[anomaly]))
        assert result["severity_assessments"][0]["severity"] == "critical"


# ---------------------------------------------------------------------------
# SecurityGateOutputNode
# ---------------------------------------------------------------------------


class TestSecurityGateOutputNode:
    """Output boundary: credential screen + rendering schema."""

    def setup_method(self):
        from src.nodes.security_gate_output_node import SecurityGateOutputNode

        self.node = SecurityGateOutputNode()

    def _state(self, result_str="", anomaly_alert=None):
        return {
            "result": result_str,
            "anomaly_alert": anomaly_alert or {"alert_id": "TEST-001"},
            "error_log": [],
            "node_history": [],
            "caller_trust_level": "ANONYMOUS",
        }

    def test_clean_output_passes_gate(self):
        """TC-G-001: A clean alert is published, carrying the rendering schema."""
        alert = {
            "alert_id": "ALT-001",
            "has_critical": False,
            "severity_summary": {"critical": 0, "warning": 1, "info": 0},
            "anomalies": [{"severity": "warning", "description": "軸受に振動"}],
        }
        result = self.node.execute(self._state(result_str=json.dumps(alert, ensure_ascii=False), anomaly_alert=alert))
        assert result["status"] == AgentStatus.SUCCESS.value
        published = json.loads(result["formatted_output"])
        assert published["anomalies"] == alert["anomalies"]
        assert published["rendering_schema"]["max_excerpt_chars"] == MAX_EXCERPT_CHARS

    def test_credential_in_output_is_blocked(self):
        """TC-G-002: An API-key shape in the alert blocks the whole output."""
        malicious = '{"result": "data", "api_key": "sk-abc123abc123abc123abc"}'
        result = self.node.execute(self._state(result_str=malicious))
        assert result["status"] == AgentStatus.ERROR.value
        assert "BLOCKED" in result.get("formatted_output", "")
        assert "sk-abc123abc123abc123abc" not in result.get("formatted_output", "")

    def test_jwt_in_output_is_blocked(self):
        """TC-G-003: A JWT in the alert blocks the output."""
        jwt_output = (
            '{"data": "eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4ifQ.' 'SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"}'
        )
        result = self.node.execute(self._state(result_str=jwt_output))
        assert result["status"] == AgentStatus.ERROR.value

    def test_empty_result_passes_as_empty_skip(self):
        """TC-G-004: Nothing to publish is a graceful SUCCESS, not an error."""
        state = self._state(result_str="")
        state["anomaly_alert"] = None
        result = self.node.execute(state)
        assert result["status"] == AgentStatus.SUCCESS.value

    def test_bearer_token_is_blocked(self):
        """TC-G-005: A Bearer token in the alert blocks the output."""
        bearer = "Authorization: Bearer eyABC123DEF456GHI789JKL012MNO345PQR"
        result = self.node.execute(self._state(result_str=bearer))
        assert result["status"] == AgentStatus.ERROR.value

    def test_output_screen_is_a_module_level_function(self):
        """TC-G-006: the output screen is a plain function, never an instance gate method.

        A gate implemented as an instance method is wrapped by the framework and
        returns None on the clean path, which the graph then hands to the next
        node as its state.
        """
        import inspect

        import src.nodes.security_gate_output_node as mod

        screen = getattr(mod, "_screen_output", None)
        assert screen is not None, "_screen_output must be a module-level function"
        assert inspect.isfunction(screen), "_screen_output must be a plain function"
        for reserved in ("_security_gate_input", "_security_gate_output"):
            assert (
                reserved not in mod.SecurityGateOutputNode.__dict__
            ), f"{reserved} must not be overridden on SecurityGateOutputNode"


# ---------------------------------------------------------------------------
# LoadBaselineParametersNode
# ---------------------------------------------------------------------------


class TestLoadBaselineParametersNode:
    """Equipment baseline loading."""

    def setup_method(self):
        from src.nodes.load_baseline_parameters_node import LoadBaselineParametersNode

        self.node = LoadBaselineParametersNode()

    def _state(self, equipment_type="変電設備"):
        return {
            "equipment_type": equipment_type,
            "validated_input": "温度: 45 °C\n電圧: 6700 V\n",
            "error_log": [],
            "node_history": [],
            "caller_trust_level": "INTERNAL",
        }

    def test_substation_baseline_loaded(self):
        """TC-B-001: 変電設備 baseline has expected sensors."""
        result = self.node.execute(self._state("変電設備"))
        assert result["status"] == AgentStatus.SUCCESS.value
        baselines = result["baseline_parameters"]
        assert isinstance(baselines, dict)
        assert len(baselines) > 0

    def test_unknown_equipment_gets_defaults(self):
        """TC-B-002: Unknown equipment type returns fallback baselines."""
        result = self.node.execute(self._state("unknown"))
        assert result["status"] == AgentStatus.SUCCESS.value
        baselines = result["baseline_parameters"]
        assert isinstance(baselines, dict)

    def test_all_known_equipment_types(self):
        """TC-B-003: All known equipment types load successfully."""
        for eq_type in ["変電設備", "送電線", "発電設備", "石油精製設備"]:
            result = self.node.execute(self._state(eq_type))
            assert result["status"] == AgentStatus.SUCCESS.value, f"Failed for {eq_type}"
            assert isinstance(result["baseline_parameters"], dict)


# ---------------------------------------------------------------------------
# GenerateAnomalyAlertNode
# ---------------------------------------------------------------------------


class TestGenerateAnomalyAlertNode:
    """Structured alert generation."""

    def setup_method(self):
        from src.nodes.generate_anomaly_alert_node import GenerateAnomalyAlertNode

        self.node = GenerateAnomalyAlertNode()

    def _state(self, has_critical=False, assessments=None):
        return {
            "equipment_type": "変電設備",
            "severity_assessments": assessments or [],
            "has_critical": has_critical,
            "missing_mandatory_items": [],
            "baseline_parameters": {"温度": {"max": 80.0, "unit": "°C"}},
            "error_log": [],
            "node_history": [],
            "caller_trust_level": "INTERNAL",
            "trace_id": "test-trace-001",
            "mandatory_check_passed": True,
        }

    def test_alert_dict_generated_on_success(self):
        """TC-A-001: GenerateAnomalyAlertNode returns alert dict and JSON result."""
        result = self.node.execute(self._state())
        assert result["status"] == AgentStatus.SUCCESS.value
        alert = result["anomaly_alert"]
        assert isinstance(alert, dict)
        assert "alert_id" in alert
        assert "equipment_type" in alert

    def test_alert_json_in_result(self):
        """TC-A-002: state['result'] is valid JSON."""
        result = self.node.execute(self._state())
        assert result["status"] == AgentStatus.SUCCESS.value
        parsed = json.loads(result["result"])
        assert "alert_id" in parsed

    def test_has_critical_propagated(self):
        """TC-A-003: has_critical flag propagated into alert dict."""
        assessment = {
            "anomaly_id": "CRIT-001",
            "severity": "critical",
            "rationale": "test critical",
            "equipment_ref": "変電設備",
            "description": "critical anomaly",
            "source": "sensor",
            "sensor": "温度",
            "deviation_pct": 25.0,
        }
        result = self.node.execute(self._state(has_critical=True, assessments=[assessment]))
        assert result["anomaly_alert"]["has_critical"] is True


# ---------------------------------------------------------------------------
# ParseFieldNotesNode — equipment reference extraction
# ---------------------------------------------------------------------------


class TestParseFieldNotesNode:
    """TC-F: an observation must name the asset it is about, exactly as written."""

    def setup_method(self):
        from src.nodes.parse_field_notes_node import ParseFieldNotesNode

        self.node = ParseFieldNotesNode()

    def _observations(self, note):
        state = {
            "validated_input": "現場点検記録:\n" + note,
            "equipment_type": "変電設備",
            "error_log": [],
            "node_history": [],
            "caller_trust_level": "ANONYMOUS",
        }
        return self.node.execute(state)["field_note_observations"]

    @pytest.mark.parametrize(
        "identifier",
        ["TR-001", "CB-23", "SKF-6205", "SUB-01", "STU-1234", "ENE-FAC-20260712-001", "TR001"],
    )
    def test_equipment_reference_is_captured_whole(self, identifier):
        """TC-F-001: the whole identifier, never a prefix of it.

        Without the boundary guards the pattern stops at the first segment that
        looks complete — ENE-FAC-20260712-001 would be recorded as FAC-20260712,
        an asset reference that resolves to nothing.
        """
        observations = self._observations(f"{identifier} の変圧器に過熱を確認。")
        assert observations, "an anomaly observation should have been extracted"
        assert observations[0]["equipment_ref"] == identifier

    @pytest.mark.parametrize(
        "note,expected",
        [
            ("変圧器に過熱を確認。", "変圧器"),
            ("transformer 3 に過熱を確認。", "transformer 3"),
        ],
    )
    def test_equipment_named_in_prose_is_captured(self, note, expected):
        """TC-F-002: an asset named in words is captured too."""
        observations = self._observations(note)
        assert observations[0]["equipment_ref"] == expected

    def test_unidentified_observation_falls_back_to_the_equipment_type(self):
        """TC-F-003: a note that names no asset reports against the equipment type."""
        observations = self._observations("全体的に腐食が進行している。")
        assert observations[0]["equipment_ref"] == "変電設備"

    def test_ordinary_words_are_not_read_as_equipment_codes(self):
        """TC-F-004: a code needs a digit — plain uppercase prose is not a reference."""
        observations = self._observations("OK-NG 判定で腐食を確認。")
        assert observations[0]["equipment_ref"] == "変電設備"


class TestStatusLeavesEveryNodeAsAString:
    """`status` leaves a node as the enum's string value, never the enum member.

    `AgentStatus` inherits from `str`, so `result["status"] == AgentStatus.SUCCESS.value`
    holds for the bare member as well as for the string. Every equality assertion in
    this file is therefore satisfied by both, and a node returning the member passes
    the whole suite while rendering as `AgentStatus.SUCCESS` anywhere the value is
    formatted into text rather than compared.

    Two assertions, because neither alone is enough: the type check proves it for the
    nodes this suite drives, and the source scan proves it for the ones it does not —
    including any node added later.
    """

    def test_the_value_a_node_returns_is_exactly_str(self):
        from src.nodes.validate_input_node import ValidateInputNode
        from src.nodes.security_gate_output_node import SecurityGateOutputNode

        report = "設備種別: 変電設備\nセンサ計測値:\n温度: 45.0 °C\n電圧: 6700 V\n"
        base = {"error_log": [], "node_history": [], "caller_trust_level": "VERIFIED_EXTERNAL"}

        validate = ValidateInputNode()
        accepted = validate.execute({**base, "user_input": report})
        declined = validate.execute({**base, "user_input": ""})

        alert = {"alert_id": "ALT-001", "has_critical": False,
                 "severity_summary": {"critical": 0, "warning": 0, "info": 0}, "anomalies": []}
        gate = SecurityGateOutputNode().execute(
            {**base, "result": json.dumps(alert, ensure_ascii=False), "anomaly_alert": alert}
        )

        for label, result in (("accepted", accepted), ("declined", declined), ("published", gate)):
            assert type(result["status"]) is str, (
                f"{label}: status is {type(result['status']).__name__}, not str — "
                "an enum member here compares equal but formats as its own name"
            )

    def test_no_module_writes_a_bare_enum_member_into_status(self):
        """The scan the equality assertions cannot perform.

        Walks the source rather than the runtime, so a node with no test of its own —
        or one added after this file was written — is covered too.
        """
        import re

        pattern = re.compile(r'"status"\s*:\s*AgentStatus\.[A-Z_]+(?![A-Z_])(?!\s*\.value)')
        offenders = []
        for path in sorted(pathlib.Path("src").rglob("*.py")):
            for number, line in enumerate(path.read_text().splitlines(), start=1):
                if pattern.search(line):
                    offenders.append(f"{path}:{number}: {line.strip()}")

        assert not offenders, "status must carry AgentStatus.<X>.value:\n" + "\n".join(offenders)

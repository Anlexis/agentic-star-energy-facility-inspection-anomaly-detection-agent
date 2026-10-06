# Template Design Specification — ENE-C2-011

## Position in the Framework Architecture

| Field | Value |
|---|---|
| Agent class | `FacilityInspectionAnomalyDetectionAgent` (`src/graph/graph.py`) |
| L1 Base (framework base class) | `AgentBaseGraph` — direct framework inheritance |
| Category | Cat 2 (two-layer nested pipeline) |
| Generation mode | deterministic — the agent invokes no language model |

**Three-layer separation**

- State: flat TypedDict composition (`src/schemas/state.py` — no Pydantic; msgpack-safe)
- Node: framework inheritance (`execute(self, state: dict) -> dict`, partial-dict returns)
- Graph: composition (`register_nodes()` fills the backbone slots; the inner `BaseGraph` owns the
  domain topology)

## Architecture Overview

### Cat 2 two-layer nested pattern

```
Outer backbone (AgentBaseGraph — fixed, add_edges() never overridden):
  START → initialize → pre_process → main → {route} → post_process → finalize → END
                                         ↓ (retry, max_retry)
                                      pre_process

  pre_process  = ValidateInputNode           (input validation + caller-data contract)
  main         = FacilityInspectionGraphNode (GraphNode wrapping DomainWorkflowGraph)
  post_process = SecurityGateOutputNode      (output boundary + audit)

Inner DomainWorkflowGraph (BaseGraph — custom linear topology):
  START → load_baseline_parameters → parse_sensor_data → parse_field_notes
        → detect_anomalies → check_mandatory_items → assess_severity
        → generate_anomaly_alert → END
```

### The outer→inner handoff

The framework invokes an inner graph as `subgraph.invoke(user_input, session_id=..., ctx=...)`.
Nothing else from the outer state crosses that call — not the caller's `input_context`, not the
equipment type the outer validator resolved, not the validated caller overrides. Without a bridge
every report would be scored against the generic fallback baseline and every caller parameter
would be silently discarded.

`src/graph/context_bridge.py` closes the gap using the two sanctioned subclass hooks:

| Hook | Runs | Does |
|---|---|---|
| `FacilityInspectionGraphNode.extract_input(state)` | before `subgraph.invoke()` | stashes the handoff keys |
| `DomainWorkflowGraph._extra_initial_state()` | inside `subgraph.invoke()` | seeds them into the inner state |

A `ContextVar` carries the handoff, so concurrent invocations in one process cannot see each
other's context.

### Configuration routing

Runtime parameters live in `config/config.yaml` (the platform registry loads it and passes it as
`Graph(config=...)`; `src/api/server.py` reads the same file so the standalone deployment matches).
`config/agent.yaml` is the static manifest and carries no runtime block.

A node's contract is `execute(self, state) -> dict` — it never receives a per-invocation config
argument, so a node that reads one is reading a value that is always absent. Declared settings
therefore reach the domain nodes by constructor injection:
`FacilityInspectionGraphNode._parent_config()` reads and validates the file, hands it to
`DomainWorkflowGraph`, and `register_nodes()` passes it to the node that needs it. Every forwarded
number is checked for type, finiteness and range at that point.

### Node configuration

| Node | Class | Slot / graph | Responsibility | TrustLevel |
|------|-------|--------------|----------------|------------|
| initialize | InitializeNode (framework default) | outer backbone | session init, trust gate | — |
| pre_process | ValidateInputNode | outer backbone | input validation, instruction-override refusal, caller-data contract, equipment type resolution | VERIFIED_EXTERNAL |
| main | FacilityInspectionGraphNode | outer backbone | GraphNode: wraps DomainWorkflowGraph, bridges the handoff | — |
| load_baseline_parameters | LoadBaselineParametersNode | inner graph | tolerance thresholds per equipment type + caller overrides | ANONYMOUS |
| parse_sensor_data | ParseSensorDataNode | inner graph | extract readings, normalize units, detect out-of-range | ANONYMOUS |
| parse_field_notes | ParseFieldNotesNode | inner graph | keyword-based observation extraction from field notes | ANONYMOUS |
| detect_anomalies | DetectAnomaliesNode | inner graph | unify sensor + field-note anomalies; cross-reference corroboration | ANONYMOUS |
| check_mandatory_items | CheckMandatoryItemsNode | inner graph | verify the mandatory inspection checklist (電気事業法 / GX推進法) | ANONYMOUS |
| assess_severity | AssessSeverityNode | inner graph | classify findings critical/warning/info; critical is non-suppressible | ANONYMOUS |
| generate_anomaly_alert | GenerateAnomalyAlertNode | inner graph | build the structured alert under the rendering bounds | ANONYMOUS |
| post_process | SecurityGateOutputNode | outer backbone | output boundary: credential screen, rendering schema, audit | ANONYMOUS |
| finalize | FinalizeNode (framework default) | outer backbone | response_metadata, total_time_ms | — |

`src/nodes/pre_process_node.py` and `src/nodes/post_process_node.py` are the generic reference
nodes the sample graphs under `src/examples/` are built from. They are not wired into this
agent's backbone.

The output boundary declares `ANONYMOUS` deliberately: it screens **all** output regardless of who
called. Caller trust is enforced at the entry gate (`ValidateInputNode`, `VERIFIED_EXTERNAL`).

### State definition (`src/schemas/state.py`)

| Field | Type | Producer | Consumer |
|-------|------|----------|---------|
| validated_input | Optional[str] | ValidateInputNode | ParseSensorDataNode, ParseFieldNotesNode, CheckMandatoryItemsNode |
| equipment_type | Optional[str] | ValidateInputNode | LoadBaselineParametersNode and all inner nodes |
| inspection_settings | Optional[Dict] | ValidateInputNode | LoadBaselineParametersNode, CheckMandatoryItemsNode, AssessSeverityNode |
| baseline_parameters | Optional[Dict] | LoadBaselineParametersNode | ParseSensorDataNode |
| sensor_readings | Optional[List] | ParseSensorDataNode | (available for tests) |
| sensor_anomalies | Optional[List] | ParseSensorDataNode | DetectAnomaliesNode, GenerateAnomalyAlertNode |
| field_note_observations | Optional[List] | ParseFieldNotesNode | DetectAnomaliesNode |
| detected_anomalies | Optional[List] | DetectAnomaliesNode | AssessSeverityNode |
| missing_mandatory_items | Optional[List] | CheckMandatoryItemsNode | AssessSeverityNode, GenerateAnomalyAlertNode |
| mandatory_check_passed | bool | CheckMandatoryItemsNode | GenerateAnomalyAlertNode |
| severity_assessments | Optional[List] | AssessSeverityNode | GenerateAnomalyAlertNode |
| has_critical | bool | AssessSeverityNode, re-derived by SecurityGateOutputNode | GenerateAnomalyAlertNode, caller |
| anomaly_alert | Optional[Dict] | GenerateAnomalyAlertNode, re-enforced by SecurityGateOutputNode | caller |
| result | Optional[str] | GenerateAnomalyAlertNode (JSON), republished by SecurityGateOutputNode | SecurityGateOutputNode |
| formatted_output | Optional[str] | SecurityGateOutputNode | FinalizeNode |
| out_of_scope | bool | ValidateInputNode | routing / caller |
| error_log | List[str] | all nodes (append) | all nodes (read) |
| status | Optional[str] | all nodes | backbone routing |
| trace_id | Optional[str] | InitializeNode (inherited) | emit_trace_event calls |
| correlation_id | Optional[str] | InitializeNode (inherited) | merge_output |

**State constraints (mandatory)**

- Flat TypedDict only (primitives + JSON-serializable types)
- No JWT, API keys or credentials in State (checkpoint database leakage)
- InvocationContext travels via `config["configurable"]` only, never in State
- No Pydantic models, dataclasses or arbitrary Python objects (msgpack-incompatible)

## Invocation Contract

### Input

| Field | Type | Notes |
|---|---|---|
| `input` | str | the inspection report text, 10–50,000 characters |
| `input_context` | dict | optional per-run parameters, defined in `src/nodes/caller_context.py` |

`input_context` fields, each validated before use:

| Field | Type | Accepted |
|---|---|---|
| `equipment_type` | str | one of `substation`, `transmission_line`, `generation`, `refinery`, `unknown` |
| `critical_deviation_pct` | number | finite, `0 < x <= 1000` |
| `warning_deviation_pct` | number | finite, `0 < x <= 1000`, not above `critical_deviation_pct` |
| `baseline_overrides` | dict | ≤32 sensors; keys match `[a-z0-9_]{1,32}`; each of `min`/`warning`/`max` finite within ±1,000,000 and ordered `min <= warning <= max` |
| `mandatory_item_codes` | list[str] | ≤64 entries; each matching `[A-Z0-9]{1,8}(-[A-Z0-9]{1,8}){0,2}` |

Any other key, or any value outside these bounds, refuses the whole request. Absent fields are
fine — the run uses the built-in baselines and the declared thresholds.

### Output

| Field | Type | Notes |
|---|---|---|
| `output` | str (JSON) | the published anomaly alert |
| `status` | str | terminal AgentStatus value |
| `anomaly_alert` | dict | the same alert, parsed |
| `has_critical` | bool | derived at the output boundary from the findings actually rendered |
| `out_of_scope` | bool | the report carried no sensor-data indicator |
| `trace_id`, `correlation_id`, `node_history` | — | framework fields |

## Security Boundaries

### Entry (`ValidateInputNode`)

Owned by this template, and executed inside `execute()` — calling the node directly exercises the
same refusals, so the guarantees hold whether or not a platform gate runs in front of it:

- report is a string, 10–50,000 characters; control characters stripped
- instruction-override phrasing (text addressed to a model rather than recording an observation,
  English and Japanese forms) is refused outright — the request errors and nothing is carried
  forward. An ordinary note that merely contains a word like "instructions" is unaffected
- every `input_context` field validated per the table above; the request fails **closed** on the
  first rejection so a run never proceeds on half-applied overrides
- rejected values are never echoed — errors name the field

Caller-controlled numbers are the reason the finiteness check exists: `NaN` parses through
`float()` and arrives intact through raw JSON, and every comparison against it is False, so a
`NaN` deviation threshold would classify a facility in breach as within tolerance. Numbers fail
closed.

The **report text is a numeric channel too**, and gets the same treatment. A long enough run of
digits parses to `float("inf")`, and an infinite reading flows through the deviation arithmetic
into the alert, where it serializes as the bare token `Infinity` — which Python's `json` accepts
but a strict parser rejects, so the published alert would break every strict consumer.
`ParseSensorDataNode` therefore discards any reading that is not finite and within
±1,000,000,000,000 rather than scoring it, and `AssessSeverityNode` re-establishes that each
resolved threshold is a real number before comparing against it, so no route into the classifier
— including one that builds the graph itself — can reach a comparison against `NaN`.

### Output boundary (`SecurityGateOutputNode`)

Two independent layers, each with its own audit event.

1. **No secret material leaves the agent.** The rendered alert is screened with the framework's
   credential detector (Stripe/OpenAI keys, JWTs, AWS access key ids, Bearer tokens, database
   connection strings) plus this template's own patterns for credential assignments and private
   key blocks. A hit blocks the whole output and replaces it with a fixed notice.

2. **Findings, not the inspection record.** The alert reports what was found; it is not a channel
   for handing the submitted report back. `src/nodes/output_schema.py` publishes the bounds: each
   free-text excerpt is truncated to 240 characters, and at most 50 findings are rendered, ordered
   critical → warning → info. The bounds are stated in the alert itself under `rendering_schema`.
   They are not caller-configurable — widening them is what the invariant exists to prevent.

   Critical findings are non-suppressible (電気事業法 保安規程 / GX推進法). That holds against the
   finding cap (the ordering means the cap can only drop informational findings), against the
   caller's parameters, and against the alert's own summary: the boundary recomputes the severity
   counts and the critical flag from what it is actually about to publish.

**Layer order.** The credential screen runs on the alert as received, *before* any bounding, and
again on the final rendering. A pattern scan is order-sensitive in a way that field-level
redaction is not — truncating a free-text field first could cut a secret in half and leave the
remainder unrecognisable to every pattern — so the scan never runs only after a transform.

**Identifier integrity.** The bounding is field-scoped: it rewrites the designated free-text
excerpt fields and nothing else. Equipment references, checklist item codes, alert ids and sensor
readings ship byte-identical, and the test suite pins that both ways for the identifier shapes
this domain uses (`TR-001`, `SKF-6205`, `ENE-FAC-20260712-001`, `SUB-01`, `GX-01`). This template
renders no monetary aggregates, so the currency-rounding rendering grid used by financial
templates does not apply here; the two invariants above are what this boundary enforces.

### Audit

`emit_trace_event(event, payload, state)` fires in every domain node. Payloads carry counts, flags
and identifiers only — never raw sensor values, report text or facility topology.

| Node | Event | Payload keys |
|------|-------|--------------|
| ValidateInputNode | inspection_report_validated | equipment_type, report_length, has_sensor_data, out_of_scope, caller_override_count |
| ValidateInputNode | inspection_report_refused | reason, report_length |
| ValidateInputNode | caller_context_rejected | rejected_field_count |
| LoadBaselineParametersNode | baseline_parameters_loaded | equipment_type, sensor_count, override_count, source |
| ParseSensorDataNode | sensor_data_parsed | equipment_type, readings_count, anomalies_count, critical_count |
| ParseFieldNotesNode | field_notes_parsed | equipment_type, observations_count, critical_hints, warning_hints |
| DetectAnomaliesNode | anomalies_detected | equipment_type, sensor_anomaly_count, field_note_anomaly_count, total_detected, corroborated_count |
| CheckMandatoryItemsNode | mandatory_items_checked | equipment_type, total_items, missing_count, mandatory_check_passed |
| AssessSeverityNode | severity_assessed | equipment_type, critical_threshold_pct, warning_threshold_pct, total_assessments, critical/warning/info counts, has_critical |
| GenerateAnomalyAlertNode | anomaly_alert_generated | alert_id, equipment_type, anomaly_count, has_critical, severity_summary, mandatory_check_passed |
| SecurityGateOutputNode | output_gate_passed / output_gate_blocked / output_schema_enforced / output_gate_empty | alert_id, counts, outcome |

### Framework gate usage

- Input gate (`_extra_security_gate_input`): not overridden. The framework's default PII masking
  and injection policy apply to `user_input` / `validated_input`; the template's own refusals live
  in `ValidateInputNode.execute()` so they do not depend on that default being active.
- Output gate: `_screen_output()` is a **module-level function** in
  `security_gate_output_node.py`, never an instance method. The framework wraps instance gate
  methods, and a wrapped hook returns `None` on the clean path, which the graph then passes as the
  next node's state.

## Equipment Types Supported

| Canonical name | Caller selector | Detection keywords | Baseline sensors |
|---|---|---|---|
| 変電設備 | `substation` | 変電設備, substation | temperature_c, voltage_kv, current_a, oil_level_pct, humidity_pct |
| 送電線 | `transmission_line` | 送電線, transmission | temperature_c, tension_kn, sag_m, insulation_mohm |
| 発電設備 | `generation` | 発電設備, generation | temperature_c, vibration_mms, rpm, pressure_kpa, oil_pressure_kpa |
| 石油精製設備 | `refinery` | 石油精製設備, refinery, petrochemical | temperature_c, pressure_kpa, flow_rate_m3h, h2s_ppm, vibration_mms |
| unknown | `unknown` | (fallback) | temperature_c |

Thresholds are adjustable per run through `input_context.baseline_overrides`.

## Mandatory Inspection Items

Per 電気事業法 保安規程 and GX推進法 2026, the built-in checklist carries `SUB-*` / `TL-*` /
`GEN-*` / `REF-*` codes per equipment type plus `GX-01` (emission record, all types) and `GX-02`
(efficiency record, 発電設備). A missing regulatory item classifies as critical.

A caller may narrow or extend the checklist by listing item **codes** in
`input_context.mandatory_item_codes`. The rendered description for a code always comes from the
built-in catalogue, so no caller free text reaches the alert through this field; an uncatalogued
code renders as the code itself.

## Import Isolation

- [x] The template imports no platform SDK package
- [x] Import targets: `framework.*` and `shared.*` only
- [x] `emit_trace_event` imported as a free function: `from shared.utils.audit_logger import emit_trace_event`

## Design Decision Record

| Decision | Option A | Option B | Chosen | Rationale |
|----------|----------|----------|--------|-----------|
| Base class | AgentBaseGraph | AutonomousBaseGraph | AgentBaseGraph | multi-step deterministic pipeline, not an autonomous loop |
| Composition | flat Cat-1 slots | Cat-2 nested GraphNode | Cat-2 nested | 7 domain nodes exceed the 5 backbone slots; keeps the outer backbone untouched |
| Output screen | instance method | module-level function | module-level | a wrapped instance gate returns None on the clean path and breaks the graph |
| State serialization | `Optional[str]` + to_json/from_json | consistent `Optional[Dict/List]` | consistent Dict/List | msgpack serializes dicts and lists natively |
| Severity thresholds | fixed | declared + caller-overridable | declared + overridable | operating envelopes differ per facility; both routes are validated before use |
| Domain config route | per-invocation config argument | constructor injection | constructor injection | nodes never receive a config argument, so the former is always empty |
| Caller checklist input | full item objects | codes only | codes only | descriptions come from the catalogue, so no caller free text can reach the alert |

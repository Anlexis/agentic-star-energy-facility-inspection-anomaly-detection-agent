# Test Specification — ENE-C2-011

| Field | Value |
|---|---|
| Template ID | ENE-C2-011 |
| Agent | FacilityInspectionAnomalyDetectionAgent |
| Category | Cat 2 (nested) |

## Test Architecture

```
tests/
  unit/
    test_agent.py                              — per-node behaviour
    test_caller_contract_and_output_schema.py  — the caller-data contract and the output bounds
    test_framework_compliance_tc06_tc07.py     — framework gate finality
  proof_of_boundary/
    test_pb_invoke_order.py                    — PB-6 per-node call order, PB-6b full-graph order
    test_invoke_e2e.py                         — end-to-end behaviour through POST /invoke
    test_server_boot.py                        — the entry-point auth boundary
    test_import_isolation.py                   — PB-4 import isolation
    test_state_safety.py                       — PB-2/PB-5 state field safety
    test_pb7_hitl_interrupt_propagation.py     — PB-7 (skip stub: no cross-boundary HITL here)
```

### Conventions

- `emit_trace_event` is patched at the node module (e.g.
  `src.nodes.validate_input_node.emit_trace_event`), never via a `sys.modules` stub — the real
  `shared` package is installed in CI.
- The HTTP tests drive the app through its real ASGI interface rather than a test client, so they
  depend on nothing beyond the framework's own requirements and can never silently skip.
- No test file stubs all of its test functions.

## Unit Tests

### TC-V — ValidateInputNode (entry gate)

| TC | Input | Expected |
|----|-------|----------|
| TC-V-001 | valid 変電設備 report with sensor data | SUCCESS, `out_of_scope=False`, report stripped |
| TC-V-002 | 変電設備 keyword in the header | `equipment_type=変電設備` |
| TC-V-003 | empty string | ERROR, error_log populated |
| TC-V-004 | under 10 characters | ERROR |
| TC-V-005 | over 50,000 characters | ERROR naming the size limit |
| TC-V-006 | no sensor-data indicator | SUCCESS, `out_of_scope=True` |
| TC-V-007 | control characters `\x00\x01\x1f` | SUCCESS, control characters stripped |
| TC-V-008 | unknown equipment type with sensor data | SUCCESS, `equipment_type=unknown` |

### TC-S — AssessSeverityNode

| TC | Input | Expected |
|----|-------|----------|
| TC-S-001 | no anomalies, no missing items | `has_critical=False` |
| TC-S-002 | deviation 25% | critical |
| TC-S-003 | deviation 8.5% | warning |
| TC-S-004 | deviation 2.0% | info |
| TC-S-005 | `source="both"` (corroborated) | critical, non-suppressible |
| TC-S-006 | missing GX推進法 item | critical, rationale states non-suppressible |
| TC-S-007 | `severity_hint="critical"` with low deviation | critical (hint wins) |

### TC-G — SecurityGateOutputNode (output boundary)

| TC | Input | Expected |
|----|-------|----------|
| TC-G-001 | clean alert | published, carrying `rendering_schema` |
| TC-G-002 | API-key shape in the alert | ERROR, whole output blocked, secret absent |
| TC-G-003 | JWT in the alert | ERROR |
| TC-G-004 | nothing to publish | SUCCESS, no error |
| TC-G-005 | Bearer token in the alert | ERROR |
| TC-G-006 | the screen's shape | a module-level function; neither gate method overridden |

### TC-B — LoadBaselineParametersNode

| TC | Input | Expected |
|----|-------|----------|
| TC-B-001 | `equipment_type=変電設備` | the substation sensor set |
| TC-B-002 | `equipment_type=unknown` | the fallback set |
| TC-B-003 | all four known types | a baseline set for each |

### TC-A — GenerateAnomalyAlertNode

| TC | Input | Expected |
|----|-------|----------|
| TC-A-001 | no anomalies | alert dict with alert_id and equipment_type |
| TC-A-002 | any input | `state["result"]` is valid JSON |
| TC-A-003 | `has_critical=True` | carried into the alert |

### TC-F — ParseFieldNotesNode (equipment reference extraction)

| TC | Input | Expected |
|----|-------|----------|
| TC-F-001 | `TR-001`, `CB-23`, `SKF-6205`, `SUB-01`, `STU-1234`, `ENE-FAC-20260712-001`, `TR001` | each captured whole, never a prefix |
| TC-F-002 | asset named in prose (変圧器 / transformer 3) | captured as written |
| TC-F-003 | note naming no asset | falls back to the equipment type |
| TC-F-004 | uppercase prose with no digit (`OK-NG`) | not read as an equipment code |

### TC-C — the caller-data contract (`test_caller_contract_and_output_schema.py`)

| Area | Coverage |
|---|---|
| Numerics | a parametrized matrix per numeric field — `NaN`, `±Infinity`, their string forms, numeric strings, bools, lists, dicts, and out-of-range magnitudes — each rejected, with the settings left empty |
| Fail-closed | a rejection carries nothing forward: no partially applied settings, no validated report |
| Ordering | `warning_deviation_pct` above `critical_deviation_pct`, and `min > max` bands, both refused |
| Inert strings | equipment selector and item codes reject injection payloads, over-length values and non-strings; a valid selector is still accepted and normalised |
| No echo | a rejected value never appears in an error message |
| Caps | sensor-override and item-code collections capped |
| Unsupported keys | refused rather than ignored, so a typo cannot silently leave a run on defaults |
| Absent context | accepted — the run uses the built-in baselines |
| Instruction override | refused by `ValidateInputNode.execute()` called directly, in English and Japanese forms; ordinary notes containing the same words are unaffected |

### TC-O — the output rendering schema (same file)

| Area | Coverage |
|---|---|
| Excerpt bound | long excerpts truncated and marked; short ones byte-identical |
| Finding cap | the cap applies, critical findings are never dropped |
| Non-suppressible critical | an alert claiming `has_critical=False` over a critical finding is corrected at the boundary |
| Published schema | the alert states the bounds it was rendered under |
| Identifier integrity | `TR-001`, `CB-23`, `SUB-01`, `GX-01`, `SKF-6205`, `STU-1234`, `ENE-FAC-20260712-001`, `90d`, `STAR 2026`, `JPY 1,000`, `JPY 1,234` and a section heading following a three-letter code all ship byte-identical; numeric fields are not rewritten |
| Credential screen | nine credential shapes each block the whole output; the secret appears in neither the output nor the error log; ordinary facility text is not flagged |
| Layer order | a secret positioned past the excerpt bound is still caught — the screen runs before the bounding as well as after |
| Report numerics | an over-long digit run (which parses to infinity) is discarded rather than scored, a plausible reading is still scored, and every published deviation is finite |
| Threshold fallback | a malformed declared threshold falls back to the module default at every route, and a breach is still classified critical afterwards |

## Boundary Tests

### PB-6 / PB-6b — invoke order (`test_pb_invoke_order.py`)

Every concrete node under `src/nodes/` must run
`trust gate → node_start → input gate → execute() → output gate → node_complete`, and
`FacilityInspectionAnomalyDetectionAgent.invoke()` must visit
`InitializeNode → ValidateInputNode → FacilityInspectionGraphNode → SecurityGateOutputNode → FinalizeNode`
and return SUCCESS for a valid report.

### End-to-end through `POST /invoke` (`test_invoke_e2e.py`)

Runs the real compiled agent behind the real ASGI app with Bearer auth.

| Area | Coverage |
|---|---|
| Real outcome | a breach report yields findings derived from its own readings (temperature and voltage deviations, the 95.0 ℃ value, recommendations) — never a baseline stub |
| Clean path | an in-tolerance report reports no deviation for that sensor |
| Out of scope | a non-inspection document returns `out_of_scope=True` rather than a guess |
| Severity coverage | critical and warning are both reachable |
| Context bridge | the equipment selector, a baseline override and the severity thresholds each change the outcome — proving `input_context` reaches the inner graph, which the framework does not forward |
| Caller checklist | `mandatory_item_codes` narrows what is checked |
| Rejection | the non-finite matrix per numeric field, injection-shaped selectors and codes, unsupported keys and inverted bands all return an error and publish nothing |
| Instruction override | refused end to end |
| Output bounds | identifiers and item codes byte-identical; structural tokens unchanged; excerpt bound and finding cap hold on the shipped bytes; credential material never present anywhere in the response |

### Entry-point auth boundary (`test_server_boot.py`)

| Condition | Expected |
|---|---|
| `INVOKE_AUTH_TOKEN` set, no or wrong Bearer | 401, generic body, graph never runs, expected token never disclosed |
| correct Bearer | runs at VERIFIED_EXTERNAL |
| `INVOKE_AUTH_TOKEN` unset | runs, caller stays ANONYMOUS |
| trust set by middleware | preserved, never demoted |
| oversized `input_context` | 413 before the graph runs |
| valid `input_context` | forwarded to the graph |

Importing `src.api.server` is itself the boot check: it builds the app, constructs the agent,
compiles the graph and provisions secrets at import time.

### PB-4 — import isolation (`test_import_isolation.py`)

No platform-SDK import anywhere under `src/`.

### PB-2 / PB-5 — state safety (`test_state_safety.py`)

No credential-shaped field name and no prohibited type annotation in the `State` TypedDict.

### PB-7 — HITL interrupt propagation (`test_pb7_hitl_interrupt_propagation.py`)

Skip stub. `FacilityInspectionGraphNode.propagate_hitl = False` and the inner pipeline has no
`interrupt()` checkpoint, so there is no cross-boundary propagation behaviour to assert. The
module detects the condition at import time and skips with a stated reason.

## Running the Tests

```bash
python -m pytest tests/ -v          # everything
python -m pytest tests/unit/ -v
python -m pytest tests/proof_of_boundary/ -v
```

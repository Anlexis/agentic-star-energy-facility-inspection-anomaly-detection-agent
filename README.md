# Energy Facility Inspection Anomaly Detection Agent

AI agent for detecting anomalies in energy facility inspection reports, built with Agentic Star.

> **Category**: Cat 2 (domain-specific pipeline — energy facility inspection anomaly detection)
> **Industry**: Energy
> **Template ID**: ENE-C2-011

## Overview

Energy facilities produce inspection reports continuously — a substation, a transmission line or
a refinery unit each generate hundreds a year, mixing instrument readings with an inspector's
written notes. Reading them for the signal that matters is slow, and whether a reading counts as
"out of tolerance" tends to depend on who is reading it.

This agent takes one inspection report as text and returns a structured anomaly alert. It pulls
the sensor readings out of the report, scores them against tolerance baselines for the equipment
type, extracts the anomaly-relevant observations from the field notes, cross-references the two
so that a reading corroborated by an inspector's note is escalated, checks the report against the
mandatory inspection checklist for that equipment type, and classifies every finding as critical,
warning or informational with the reason it was classified that way. The result is a JSON alert
with a severity summary, the individual findings, the missing checklist items and recommended
next actions.

It is deterministic: the same report produces the same alert, and every classification traces
back to a threshold you can see and change. Tolerance baselines, severity thresholds and the
mandatory checklist are all adjustable per request, so one deployment can serve facilities with
different operating envelopes.

This is an agent template built with the **AGENTIC STAR** development platform and the
**AgentCore Framework**. It is intended to be taken as a starting point: fork it, adapt it to
your own data and policies, and run it inside your own AGENTIC STAR deployment.

## Requirements

**This template does not run standalone.** It requires:

| Requirement | Notes |
|---|---|
| **AGENTIC STAR platform** | The agent connects to the platform at start-up. Without it, start-up fails immediately (see *Behaviour without the platform* below). Deployment guides and API documentation: [AGENTIC STAR Developers](https://developers.fd.agenticstar.tm.softbank.jp/) |
| **AgentCore Framework** (`agenticstar-agentcore`) | Installed from PyPI as a dependency. |
| Python | >=3.11 |

```bash
pip install -e .
```

### Behaviour without the platform

The framework is designed to run **only** on AGENTIC STAR. There is no fallback or degraded
mode. If the platform is unreachable or the SDK version does not match, the agent fails at graph
compile / start-up preflight rather than starting in a partially working state. This is
intentional — a half-running agent is worse than one that refuses to start.

## Quick Start

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
python -m pytest tests/ -v
```

Tests run without a platform connection. Running the agent itself does not.

## Project Structure

```
src/graph/    outer backbone graph, inner domain pipeline, the context bridge between them
src/nodes/    the pipeline nodes, the caller-data contract and the output schema
src/schemas/  the state definition shared by both graphs
tests/        unit, integration and boundary tests
config/       agent.yaml (static manifest) and config.yaml (runtime parameters)
docs/         design and test documentation
```

`docs/02_design.md` describes the architecture, the state fields and the security boundaries;
`docs/03_test_spec.md` lists what the test suite covers.

## Customising

1. Adjust `config/config.yaml` for your own environment — the severity thresholds live there.
2. Replace the built-in tolerance baselines and mandatory checklists in
   `src/nodes/load_baseline_parameters_node.py` and `src/nodes/check_mandatory_items_node.py`
   with the ones your facilities run against, or override them per request through
   `input_context` (the accepted fields are defined in `src/nodes/caller_context.py`).
3. Extend the sensor-name, unit and keyword tables in `src/nodes/parse_sensor_data_node.py` and
   `src/nodes/parse_field_notes_node.py` to match how your reports are written.
4. Re-run the test suite.

## License

MIT — see [LICENSE](LICENSE).

## Status of this repository

This template is published **as is**, by its individual author, under the MIT license. It carries
**no warranty and no support commitment**, and no organisation stands behind its behaviour or
fitness for any purpose. Issues and pull requests may or may not receive a response; that is at
the sole discretion of the repository owner.


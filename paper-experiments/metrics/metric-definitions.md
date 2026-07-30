# Metric Definitions

This file defines the metrics used by LAPIS paper tables. Values should be
computed from reproducible YASA/LAPIS reports, not copied from design examples.

## Detection Metrics

| Metric | Definition | Counting Rule |
|---|---|---|
| Detected CVEs | Number of benchmark CVEs reported by the tool | Count one per vulnerable case if final status is `reported` |
| Recall | Detected vulnerable CVEs / total vulnerable CVEs | Exclude safe cases from denominator; report no-gap positive controls separately in notes if needed |
| Precision | True positive findings / all reported findings | Requires manual or oracle validation |
| F1 | Harmonic mean of precision and recall | Compute only when both precision and recall are available |
| Path Recovery | Cases with a reviewable source-to-sink path | Count when the final report contains a coherent YASA trace or `ordered_source_to_sink_chain` |
| False Positive | Reported flow judged non-vulnerable | Count after manual/oracle validation |

## Contract Metrics

| Metric | Definition | Counting Rule |
|---|---|---|
| CCEC Generated | Candidate call-edge contracts generated | Count candidate edges in CCEC JSON |
| CCEC Consumed | CCEC edges observed by LAPIS-Tool | Count `materializedMatched` or checker matches |
| CTPC Generated | Propagation contracts generated | Count propagation edges, summaries, upgrades, and kill conditions |
| CTPC Consumed | CTPC facts used by LAPIS-Tool | Count diagnostics in `lapis-ctpc-diagnostics.jsonl` |
| Triple Pass | Three-way validation success | Must-flow, must-not-flow, and must-kill all pass |
| Invalid Contracts Accepted | Contracts accepted after validation but rejected by manual/oracle audit | Used in Table 3 to measure validation quality |

## LLM Backend Metrics

| Metric | Definition | Counting Rule |
|---|---|---|
| Contract Accuracy | Accepted/generated contract ratio | Count structurally valid CCEC plus validated CTPC outputs over generated contract JSON files |
| Triple Pass | Three-way validation success rate | Must-flow, must-not-flow, and must-kill all pass |
| Path Recovery | Cases with reviewable source-to-sink paths after backend-generated contracts | Count using final YASA/LAPIS re-scan reports |
| Cost | Provider token cost or normalized relative cost | Record provider-specific cost in appendix |

## Runtime and LLM Metrics

| Metric | Definition | Counting Rule |
|---|---|---|
| LLM Calls | Number of model calls used for repair | Count CCEC, CTPC, and validation calls separately |
| Token Cost | Prompt + completion tokens or provider cost | Record provider-specific units in appendix |
| Latency | Wall-clock time per LLM call or full pipeline | Record seconds |
| Timeout | Failed run due to timeout | Record timeout threshold and stage |

## Trace Status

The following statuses are emitted by `LAPIS-Core/src/lapis/yasa_runner.py`:

| Status | Meaning |
|---|---|
| `no_finding_trace` | No finding trace was produced |
| `reported_trace` | YASA reported a finding trace |
| `actual_taint_trace` | A real source-to-boundary taint trace is available |
| `ccec_callgraph_closed_taint_open` | CCEC closed callgraph reachability but taint facts remain open |
| `ctpc_fact_closed` | CTPC facts closed the trace |

For paper tables, use `Path Recovery = yes` only when the final report
contains a coherent `ordered_source_to_sink_chain` that follows the intended
parameter/data propagation order.

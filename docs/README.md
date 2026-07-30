# LAPIS Documentation

This directory keeps project-level LAPIS research documents separate from
module READMEs and experiment outputs.

## Methodology

- [Overall Repair Workflow](methodology/overall-repair-workflow.md)
  describes the implemented evidence gate, gap diagnosis, LLM-backed
  CCEC/CTPC generation, YASA consumption, and end-to-end workflow.
- [Call Edge Repair Plan](methodology/call-edge-repair-plan.md)
  documents the implemented CCEC path for connectivity gaps, including
  materialized call-edge consumption in `LAPIS-Tool`.
- [Dataflow Repair Flow](methodology/dataflow-repair-flow.md)
  documents the implemented CTPC path for propagation gaps, including
  fact diagnostics and ordered trace reconstruction.

## Dataset

- [CVE Dataset Case Matrix](datasets/cve-dataset-case-matrix.md)
  classifies the benchmark cases into connectivity, propagation, mixed, and
  control groups.

## Reports

- [Mixed Case Verification Report](reports/mixed-case-verification-report.md)
  records the current mixed-case closure results for python-multipart and
  pyLoad.

## Experiment Design

- [LAPIS Experiment Design](experiment/LAPIS_Experiment_Design.md)
  records the paper-level RQ design and example table layout. Its numeric
  tables are placeholders until the final benchmark collection is complete.

## Current Implementation Snapshot

The current project is no longer only a repair proposal. The repository now
contains an implemented closed-loop workflow:

```text
baseline YASA scan
-> Evidence Pack / Evidence Gate
-> Gap Diagnosis
-> LLM-generated CCEC and/or CTPC
-> structural / three-way validation
-> LAPIS-modified YASA rerun with --ccec-file / --ctpc-file
-> finding trace + ordered source-to-sink chain for review
```

Implemented code locations:

```text
LAPIS-Core/src/lapis/cli.py
  CLI commands and terminal output for scan summaries, contract status, traces.

LAPIS-Core/src/lapis/yasa_runner.py
  YASA runner wrapper, contract consumption summaries, trace quality,
  reconstructed CCEC evidence, and ordered source-to-sink chain rendering.

LAPIS-Tool/src/engine/analyzer/python/common/python-analyzer.ts
  materialized CCEC call-edge matching and diagnostics.

LAPIS-Tool/src/checker/taint/python/lapis-ccec.ts
  virtual/boundary CCEC sink handling and diagnostics.

LAPIS-Tool/src/checker/taint/python/lapis-ctpc.ts
  CTPC fact tracking, propagation, suppression, virtual sink handling, and
  diagnostics.
```

Latest closed-loop experiment artifacts live under `LAPIS-Experiments/reports/`.
The checked-in latest contracts are LLM-generated through the `llm-generate-*`
commands, not manually copied oracle chains.

## Paper Experiment Tables

Paper-facing metric definitions and table templates are stored separately under
[`paper-experiments/`](../paper-experiments/README.md). The tables there use
`TBD` placeholders until the final CVE benchmark and real-world evaluation data
are collected. Treat tables in `docs/experiment/LAPIS_Experiment_Design.md` as
design examples only.

Outdated or superseded draft reports are intentionally not kept here. Current
experiment artifacts live under `LAPIS-Experiments/reports/`.

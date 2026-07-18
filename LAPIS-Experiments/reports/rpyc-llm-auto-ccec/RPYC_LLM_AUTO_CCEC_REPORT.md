# RPyC LLM Auto CCEC Experiment

## Goal

Make the CCEC prompt/evidence builder expose the correct oracle-blind local static evidence so that gpt-5 generates the RPyC missing-call-edge contract automatically, instead of selecting unrelated dangling edges such as `safe_import -> __import__`.

## Evidence Builder Change

- Auto-discovers `getattr(obj, "__array__")` followed by the callback boundary `array_callback()`.
- Correlates that attribute with factory registration metadata containing `("__array__", "array protocol")`.
- Correlates the same attribute with `_make_method` branch evidence.
- Requires the generated branch body to contain a configured final sink fsig such as `pickle.loads`.
- Emits `suggested_virtual_edges` and prompt constraints that force LLM output to stay on evidence-backed edges.

## Generated Artifacts

- gpt-5 generated candidates: `ccec/candidate_edges.llm.json`
- gpt-5 structural validation: `ccec/llm_validation_report.json`
- Three-way validation contract: `ccec/ccec_validation_contract.json`
- Three-way validation report: `ccec/ccec_link_validation_report.json`
- Local semantic samples: `ccec-validation/`
- Local sample validation report: `ccec/ccec_local_validation_report.json`
- Current final-sink baseline: `runs/baseline-final-sink/baseline-final-sink_full_cve_report.json`
- Current final-sink LLM run: `runs/llm-auto-final-sink/llm-auto-final-sink_full_cve_report.json`

## Validation Results

Current final-sink baseline:

- YASA result: `no_finding`
- Findings: `0`
- Sources: `1`
- Sinks: `0`

gpt-5 CCEC output:

- Candidate edges: `2`
- Generated edge 1: `array_callback()` -> `rpyc.core.netref._make_method.<generated __array__>`
- Generated edge 2: `rpyc.core.netref._make_method.<generated __array__>` -> `pickle.loads`
- Structural validation: `accepted`
- Final-sink-only YASA result: `finding`
- Final-sink-only findings: `1`

Three-way CCEC validation:

- Classification: `hard`
- must-link: `passed`
- must-not-link: `passed`
- must-kill: `passed`
- Link contract validation: `accepted`
- Local semantic sample validation: `accepted`
- Edge coverage:
  - `array-boundary-to-generated-method`: `covered`
  - `array-generated-method-to-pickle-loads`: `covered`

## Conclusion

The automated LLM CCEC loop is feasible for the RPyC case. The prompt/evidence builder gives gpt-5 oracle-blind local static evidence and constrains it to evidence-backed virtual edges. The resulting LLM-generated CCEC contract turns the current single-final-sink baseline from `no_finding` into one final `finding`, with structural, three-way, local semantic, and full-CVE validation coverage.

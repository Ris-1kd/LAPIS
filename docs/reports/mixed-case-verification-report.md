# Mixed Case Verification Report

## Summary

Mixed-case flow is now wired at the LAPIS-Core workflow level:

1. Evidence Gate
2. Gap Diagnosis: `mixed_case`
3. CCEC candidate edges and repaired call-chain
4. CTPC Evidence Pack after CCEC
5. CTPC top-k repair plan and prompt generation

The python-multipart mixed example now reaches YASA finding-level closure with both CCEC and CTPC enabled. CTPC is consumed through generic contract events and fact kinds rather than a CVE-specific hard-coded path.

## Verified Dataset

### CVE-2026-24486 python-multipart

This is the clean mixed-case verification target.

Baseline evidence:

- source hit: true in the case evidence pack
- sink hit: true in the case evidence pack
- finding: 0
- gap type: `mixed_case`

Generated CTPC Evidence Pack:

- `LAPIS/LAPIS-Experiments/cases/mixed_case/cve-2026-24486-python-multipart/evidence/evidence_pack.json`

Generated CTPC Repair Plan:

- `LAPIS/LAPIS-Experiments/cases/mixed_case/cve-2026-24486-python-multipart/ctpc/ctpc_repair_plan.json`

The plan classifies this case as:

- mode: `hard`
- llm_required: true
- top-k propagation candidates: 4
- strategy: `ranked_candidates_to_llm_ctpc`

Top-k CTPC candidates:

1. `filename -> FormParser.file_name`
   - kind: `constructor_keyword_capture`
2. `FormParser.file_name -> File.__init__.file_name`
   - kind: `closure_capture_to_constructor_arg`
3. `File.__init__.file_name -> path`
   - kind: `path_join_keep_filename`
4. `path -> open(path)`
   - kind: `filesystem_sink_argument`

YASA verification:

- baseline check:
  - `findingCount = 0`
  - `markedSourceCount = 0`
  - `matchedSinkCount = 0`
- CCEC-only check:
  - `findingCount = 0`
  - `markedSourceCount = 2`
  - `matchedSinkCount = 12`
- CCEC + CTPC file-path check:
  - `findingCount = 2`
  - `markedSourceCount = 2`
  - `matchedSinkCount = 12`
  - run report: `LAPIS/LAPIS-Experiments/cases/mixed_case/cve-2026-24486-python-multipart/repaired-runs/ccec-ctpc-file-path/ccec-ctpc-file-path_full_cve_report.json`

Interpretation:

CCEC improves the analysis context enough for YASA to observe source and sink, but CCEC alone still does not produce a finding. After enabling the CTPC file-path contract, the mixed chain closes and YASA reports findings.

The final sink is represented as a CTPC/CCEC virtual final sink: the physical observed boundary is `parser.write(...)`, and the repaired evidence chain points to `open(path, "w+b")`.

Implemented CTPC generic consumption:

- generic fact store keyed by CTPC fact names
- tainted identifier seeding for `TaintSource` variables
- contract-driven `assignment` and `function_call` propagation
- contract-driven `sink` / `risk_upgrades`
- virtual final sink metadata from CTPC patterns, for example `virtual_final_sink: "open(path)"`

Consumed python-multipart propagation family:

- `constructor_keyword_capture`
- `path_join_keep_filename`
- `filesystem_sink_argument`
- virtual boundary-to-final-sink upgrade

### CVE-2025-55156 pyLoad

This case has mixed-case metadata and now also produces a CTPC repair plan:

- `LAPIS/LAPIS-Experiments/cases/mixed_case/cve-2025-55156-pyload/ctpc/ctpc_repair_plan.json`

Top-k CTPC candidates:

1. `url -> data[*][3]`
   - kind: `tuple_list_element`
2. `data[*][3] -> statuses`
   - kind: `generator_tuple_index_join`
3. `statuses -> SQL f-string`
   - kind: `fstring_sql_interpolation`

However, the current configured baseline summary reports `findingCount = 1`, so this case is not a clean no-finding benchmark for final mixed closure. It can still be used as a structural mixed-flow example.

## Current Status

Implemented:

- mixed-case CTPC Evidence Pack generation
- mixed-case CTPC top-k repair planning
- mixed-case CTPC prompt generation
- robust dataset-file resolution for ambiguous anchors such as `multipart.py`
- validation run showing CCEC-only is insufficient for python-multipart
- generic LAPIS-Tool CTPC consumer support for non-SQL fact kinds
- python-multipart file-path CTPC contract
- final CCEC + CTPC YASA run producing `findingCount > 0`

Not yet implemented:

- LLM-generated three-way CTPC validation samples for python-multipart
- stricter must-not / must-kill validation for file-path sanitizer cases
- broader generic expression matching for tuple destructuring and object-field propagation

## Next Implementation Step

To harden the mixed full chain, add CTPC validation samples for `FILE_PATH` propagation:

1. `must-flow`: tainted filename reaches virtual `open(path)`
2. `must-not-flow`: tainted body bytes without tainted filename does not report
3. `must-kill`: filename normalized by basename/path sanitizer is suppressed

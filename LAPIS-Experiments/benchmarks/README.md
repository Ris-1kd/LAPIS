# LAPIS Benchmarks

`benchmarks/` stores the raw analyzer inputs. Keep this directory separate from
`cases/`, which stores LAPIS-generated evidence, contracts, validation reports,
and repaired analyzer runs.

## Layout

```text
benchmarks/
  connectivity_gap/
    <case_id>/
      source/
      poc/
      rules/
      manifest.json
      README.md

  propagation_gap/
    <case_id>/
      source/
      poc/
      rules/
      manifest.json
      README.md

  mixed_case/
    <case_id>/
      source/
      poc/
      rules/
      manifest.json
      README.md
```

## Directory Meaning

```text
source/
  The analyzed project source code.

poc/
  Safe PoC or driver code used as the analysis entrypoint.

rules/
  YASA rule config files for source, sink, and entrypoint definitions.

manifest.json
  Machine-readable benchmark metadata.

README.md
  Human-readable case notes and reproduction commands.
```

## Gap Types

```text
connectivity_gap
  Call graph is incomplete. Repair branch: CCEC.

propagation_gap
  Call graph is basically reachable, but taint/value/access-path propagation is
  missing. Repair branch: CTPC.

mixed_case
  Both call graph connectivity and data propagation are missing. Repair order:
  CCEC first, then CTPC if the taint path is still broken.
```

## Included Cases

| Gap type | Case | Repair branch | Notes |
| --- | --- | --- | --- |
| `connectivity_gap` | `cve-2024-27758-rpyc` | CCEC | LLM materializes the generated `__array__` function edge; YASA reports a complete trace without CTPC. |
| `connectivity_gap` | `cve-2023-24816-ipython` | CCEC | LLM materializes a rebound `_set_term_title` edge; YASA reports a complete trace without CTPC. |
| `propagation_gap` | `cve-2024-36039-pymysql` | CTPC | Candidates must be inferred from baseline facts. |
| `mixed_case` | `cve-2026-24486-python-multipart` | CCEC then CTPC | Candidates must be inferred from baseline facts. |

## Upload Checklist

For each benchmark case, upload:

```text
source/        project source snapshot
poc/           safe PoC / driver
rules/         YASA rule config
manifest.json  metadata required to run baseline scans
README.md      brief blind-run explanation and run commands
```

Do not place LAPIS generated outputs here. Generated files belong under
`cases/<gap_type>/<case_id>/`.

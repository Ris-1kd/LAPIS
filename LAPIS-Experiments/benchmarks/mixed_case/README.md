# Mixed Case Benchmarks

Place raw input datasets here when both call graph connectivity and data
propagation are incomplete.

Expected repair branch:

```text
CCEC -> CTPC
```

Each case should follow:

```text
<case_id>/
  source/
  poc/
  rules/
  manifest.json
  README.md
```

Copy `_TEMPLATE_CASE/` and rename it to the concrete case id, for example:

```text
cve-2026-24486-python-multipart/
```


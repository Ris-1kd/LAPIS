# Propagation Gap Benchmarks

Place raw input datasets here when the call graph is basically reachable but
taint/value/access-path propagation is incomplete.

Expected repair branch:

```text
CTPC
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
cve-2024-36039-pymysql/
```


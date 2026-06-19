# Mixed Case Benchmark Template

Replace this directory name with the concrete case id.

Required files:

```text
source/        analyzed project source
poc/           safe PoC / driver
rules/         YASA rule config
manifest.json  machine-readable metadata
README.md      human-readable notes
```

Mixed cases should first require CCEC to advance call connectivity, then CTPC to
repair remaining taint/value/access-path propagation.


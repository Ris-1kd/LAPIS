# LAPIS

LAPIS is the workspace for the new access-path propagation gap research line.

## Layout

```text
LAPIS-Core/
  Reusable tool implementation for locating access-path propagation gaps,
  building evidence packs, ranking candidate edges, and validating contracts.

LAPIS-Experiments/
  Experiment assets: case configs, YASA rules, baseline outputs, generated
  evidence packs, validation cases, and reports.

LAPIS-Tool/
  LAPIS-modified YASA tool tree. This is where CTPC loading, guarded
  access-path propagation, and YASA-in-the-loop validation hooks will be added.
```

`YASA-Engine-upstream` remains the untouched baseline. LAPIS-specific YASA
changes should be made in `LAPIS-Tool`, not in the upstream folder.

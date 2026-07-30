# YASA Baseline Tool

Table 2 compares the original YASA baseline with full LAPIS. The original YASA
tool is an external baseline dependency, not part of the LAPIS implementation.

## Repository Policy

Do not commit the full original YASA repository into `LAPIS-Project`.

Reasons:

- `LAPIS-Project/LAPIS-Tool` already contains the LAPIS-modified YASA tool used
  for contract consumption.
- The original YASA repository is an upstream baseline, not LAPIS-owned code.
- Keeping it ignored avoids mixing baseline implementation, local binaries, and
  LAPIS research artifacts in the remote repository.
- The local upstream checkout contains `uast4py-linux-amd64`, which is an
  environment dependency and should not be committed as project source.

## Local Baseline Checkout

Current local baseline path inside the LAPIS workspace:

```text
external-tools/YASA-Engine-upstream
```

This path is intentionally ignored by `.gitignore`.

Current upstream remote:

```text
https://github.com/antgroup/YASA-Engine.git
```

Observed local commit:

```text
89ffcfd9f863c1bacae4588894ff73358e0ad76f
89ffcfd sync: update version
```

## Reproduction Convention

For paper experiments, record the original YASA baseline as:

```text
tool: YASA upstream
repo: https://github.com/antgroup/YASA-Engine.git
commit: 89ffcfd9f863c1bacae4588894ff73358e0ad76f
uast_sdk_path: external-tools/YASA-Engine-upstream/uast4py-linux-amd64
```

The LAPIS-enhanced runs should use:

```text
tool: LAPIS-Tool
path: LAPIS-Tool
contracts: --ccec-file and/or --ctpc-file
```

If a clean reproducibility setup is needed, clone the upstream YASA repository
into `external-tools/YASA-Engine-upstream` and provide its
`uast4py-linux-amd64` path to `run-yasa-case`.

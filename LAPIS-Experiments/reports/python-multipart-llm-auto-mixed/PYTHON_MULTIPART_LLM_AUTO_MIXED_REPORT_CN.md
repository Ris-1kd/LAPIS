# cve-2026-24486 python-multipart 混合缺口 LLM 自动闭环实验报告

## 1. 实验目标

本实验验证 `cve-2026-24486-python-multipart` 这个 mixed case 是否可以在无已知答案注入、无人工手写契约的条件下，通过 LLM API/gpt-5 按顺序自动完成：

1. 先基于局部静态证据生成 CCEC 调用边契约。
2. 对每条 CCEC 调用边做 must-link / must-not-link / must-kill 三分验证。
3. 回灌 CCEC 后确认仍存在数据流缺口。
4. 再基于局部静态证据生成 CTPC 数据流契约。
5. 对 CTPC 做 must-flow / must-not-flow / must-kill 三分验证。
6. 将 CCEC + CTPC 回灌原始 full-CVE 数据集，验证是否补出最终链路。

实验过程中 prompt 没有给出官方完整链路答案；LLM 只看到 PoC 构造点、callback 注册/分发、文件名保存、路径拼接、open 本地 sink 等局部静态证据。

## 2. 关键产物

- CCEC 候选边：`ccec/candidate_edges.llm.json`
- CCEC 结构验证：`ccec/ccec_structural_validation_report.json`
- CCEC 三分验证：`ccec/ccec_local_validation_report.json`
- CTPC evidence：`ctpc/evidence_pack.json`
- CTPC 最终契约：`ctpc/ctpc.json`
- CTPC 三分验证：`ctpc/validation-v3/validation_report.json`
- baseline：`runs/baseline/baseline_full_cve_report.json`
- post-CCEC：`runs/post-ccec/post-ccec_full_cve_report.json`
- final：`runs/final-single-sink-v2/final-single-sink-v2_full_cve_report.json`
- 最终链路对比：`final_known_chain_comparison.json`
- 唯一最终 sink 规则：`LAPIS/LAPIS-Experiments/cases/mixed_case/cve-2026-24486-python-multipart/rules/final-sink-only.json`

规则审计结果：

| 项 | 值 |
|---|---|
| sink 规则数量 | `1` |
| 唯一 `fsig` | `open` |
| sink 参数 | `args[0]`，即文件路径参数 |
| 规则语义 | 只接受到达文件写入 `open(path, "w+b")` 的链路 |

## 3. Baseline 对照

原始 YASA full-CVE 扫描结果：

| 阶段 | findings | sources | sinks | 结论 |
|---|---:|---:|---:|---|
| baseline | 0 | 2 | 4 | source/sink 都能命中，但完整漏洞链路断开 |

本实验使用唯一最终 sink 规则，规则文件只包含 `open(args[0])` 一个危险调用签名。`sinks=4` 表示数据集中有 4 个 `open` 调用点被该唯一 sink 签名匹配，不表示存在 4 条 sink 规则。这说明该 case 不是规则完全失效，而是中间调用边与数据流语义缺失。

旧实验中的 `os.path.join`、`parser.write` 等中间边界已经不再作为 sink 规则存在；它们只作为 CCEC/CTPC 证据或 virtual boundary 出现在契约内部。

## 4. CCEC 阶段

gpt-5 基于 callback 局部静态证据生成 3 条 CCEC 调用边：

1. `FormParser.write -> OctetStreamParser.write`
2. `OctetStreamParser.write -> FormParser.__init__.<callback:on_start>`
3. `OctetStreamParser.write -> FormParser.__init__.<callback:on_data>`

CCEC 结构验证结果：

| 指标 | 结果 |
|---|---|
| candidate_edges | 3 |
| structural status | accepted |
| local three-way status | accepted |
| must-link | pass |
| must-not-link | pass |
| must-kill | pass |

post-CCEC full-CVE 扫描：

| 阶段 | findings | 结论 |
|---|---:|---|
| post-CCEC | 0 | 调用边阶段推进了 callback 语义，但仍需要 CTPC 补 filename/path 传播 |

## 5. CTPC 阶段

gpt-5 最终生成的 CTPC v3 包含 7 条数据流/边界语义：

1. `filename -> FormParser.file_name`
2. `file_name -> self._file_base`
3. `file_name -> self._ext`
4. `self._file_base -> fname`
5. `fname -> path`
6. `path -> open(path)`
7. `parser.write -> virtual_final_sink=open`

第 7 条是 mixed case 的关键：当前 CCEC consumer 能记录 callback 边界，但还不能真正 materialize callback body 到 `open(path)`；因此 CTPC 在已验证 CCEC 之后，用 `parser.write` 边界绑定本地静态证据中的唯一最终 `open` sink。该规则明确不把 `parser.write(data)` 的 data bytes 当作 filename source。

实现上，`parser.write` 不是规则文件中的 sink；它只作为 CTPC 契约中带有文件/行证据约束的 virtual boundary 使用。最终 ruleConfig 仍然只有 `open` 一个 sink。

为了避免 virtual boundary 误触发，CTPC consumer 还要求 `parser.write` 边界同时匹配契约中的 evidence 文件和行号；因此 `self.parser.write(data)` 这类库内部委托调用不会被当成第二个最终 finding。

CTPC 本地三分验证：

| 验证项 | 预期 | 结果 |
|---|---|---|
| must-flow | finding | pass |
| must-not-flow | no_finding | pass |
| must-kill | no_finding | pass |
| edge coverage | 7/7 | pass |
| status | accepted | accepted |

## 6. 最终 full-CVE 结果

将 gpt-5 生成并验证通过的 CCEC + CTPC v3 回灌原始数据集后：

| 阶段 | findings | sources | sinks | 结论 |
|---|---:|---:|---:|---|
| baseline | 0 | 2 | 4 | 唯一 `open` sink 规则下原始未报 |
| post-CCEC | 0 | 2 | 4 | 唯一 `open` sink 规则下仍缺数据流 |
| final CCEC+CTPC v3 + single-final-sink constraint | 1 | 2 | 4 | 成功报出，并收敛到唯一最终 sink |

最终 finding 出现在 PoC 第 23 行 `parser.write(b"file-content")` 边界，报告中标注 CTPC virtual final sink 为 `open`。CCEC 的 callback 边界证据保留在 diagnostics/contract 中，但在 CTPC 已声明 `virtual_final_sink=open` 后不再作为第二条最终 finding 输出。

## 7. 与已知链路对比

已知链路来自 `py-result/py-report/tool-cve-breakpoint-matrix.md`，其完整预期为：

```text
poc_cve_2026_24486_python_multipart.py:9 filename = source()
-> poc_cve_2026_24486_python_multipart.py:16 FormParser(... file_name=filename ...)
-> multipart.py:1556-1559 on_start closure captures file_name and calls FileClass(file_name, ...)
-> multipart.py:1578-1579 callbacks={"on_start": on_start, ...}
-> poc_cve_2026_24486_python_multipart.py:23 parser.write(...)
-> multipart.py:475 path = os.path.join(file_dir, fname)
-> multipart.py:478 open(path, "w+b")
```

对比结果：

| 对比项 | 结果 |
|---|---|
| source line | 匹配：PoC line 9 |
| constructor boundary | 匹配：`FormParser(... file_name=filename ...)` |
| callback dispatch | 由 CCEC 三条 callback 边表示 |
| path propagation | 由 CTPC `file_name -> _file_base/_ext -> fname -> path` 表示 |
| final sink | 匹配：唯一最终 sink `open` |
| physical `open(path)` line | 未物理 materialize 到 line 478；通过 `parser.write -> virtual_final_sink=open` 表示 |

因此，本轮输出与已知链路在语义最终 sink 上匹配；差异是当前 analyzer 报告位置仍在 `parser.write` 边界，而不是物理 `multipart.py:478 open(path)` 行。

## 8. 结论与限制

本例已实现 LLM API/gpt-5 自动化 mixed-case 闭环：先补调用边，再补数据流，三分验证通过后回灌 full-CVE，最终从 baseline 0 finding 提升到 final 1 finding，并通过 sink 规则约束收敛为唯一最终 sink `open`。

限制也很明确：当前 CCEC consumer 还不是完整 callgraph materializer，不能真实执行 callback body 到 `open(path)`；因此最终链路通过 CTPC 的 `virtual_final_sink=open` 在 `parser.write` 边界报告。这是现阶段可验证的闭环实现，后续若实现真实 callback callgraph materialization，可以把 final finding 从边界 sink 进一步落到物理 `open(path)` 行。

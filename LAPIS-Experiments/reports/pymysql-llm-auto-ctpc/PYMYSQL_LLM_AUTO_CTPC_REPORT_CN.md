# PyMySQL LLM 自动 CTPC 闭环实验报告

## 1. 实验目标

本实验验证 CVE-2024-36039 / PyMySQL 的缺失数据流修复流程：

```text
baseline 无 finding
  -> 从静态证据构造 Evidence Pack
  -> 调用 gpt-5 生成 CTPC
  -> 本地三分验证
  -> YASA 三分验证
  -> 三分验证通过后接受 CTPC
  -> 回灌静态分析器
  -> 扫描完整 CVE 链路
```

CTPC 修的是数据流/访问路径传播，不是调用图边。对应报告目录：

- `LAPIS/LAPIS-Experiments/reports/pymysql-llm-auto-ctpc/`

## 2. 实验规则

本实验使用单一最终 sink 规则：

```text
self._query(query)
```

规则文件：

- `LAPIS/LAPIS-Experiments/cases/propagation_gap/cve-2024-36039-pymysql/rules/final-sink-only.json`

规则中只有一个最终危险调用签名：

```json
{
  "fsig": "self._query",
  "args": ["0"],
  "attribute": "CVE-2024-36039-pymysql-query-send"
}
```

因此本实验不是多 sink 放宽匹配，而是要求污点最终到达 PyMySQL 的实际查询发送点：

```text
pymysql/cursors.py:153
result = self._query(query)
```

规则审计结果：

| 项 | 值 |
| --- | --- |
| sink 规则数量 | `1` |
| 唯一 `fsig` | `self._query` |
| sink 参数 | `args[0]`，即 `query` |
| 规则语义 | 只接受到达 PyMySQL 查询发送点的链路 |

## 3. 原始 baseline 结果

case 自带 baseline 扫描摘要：

- `LAPIS/LAPIS-Experiments/cases/propagation_gap/cve-2024-36039-pymysql/baseline/scan_summary.json`

原始结果：

| 指标 | 数值 |
| --- | ---: |
| markedSourceCount | 1 |
| matchedSinkCount | 2 |
| findingCount | 0 |
| entryPointCount | 1 |
| fileCount | 20 |
| lineCount | 4367 |
| totalTimeMs | 6258 |

解释：

```text
source 能被识别
sink 能被识别
但 source -> sink 的完整 taint path 没有闭合
```

这里 `matchedSinkCount=2` 表示唯一 sink 签名 `self._query` 在数据集中匹配到 2 个调用点，不表示规则中存在 2 条 sink。整个实验规则始终只有 `self._query(query)` 一个最终 sink。

所以该 case 是 propagation gap / 缺失数据流，不是 connectivity gap。

### 3.1 baseline 与 LLM-CTPC 回灌结果对比

| 实验阶段 | source | sink | finding | 结果解释 |
| --- | ---: | ---: | ---: | --- |
| baseline 原始扫描 | 1 | 2 | 0 | source/sink 均命中，但数据流链路断开 |
| LLM-CTPC 回灌扫描 | 1 | 2 | 1 | CTPC 补齐访问路径传播后，完整 CVE 链路闭合 |

完整回灌结果来自：

- `LAPIS/LAPIS-Experiments/reports/pymysql-llm-auto-ctpc/runs/llm-auto-ctpc/llm-auto-ctpc_full_cve_report.json`

对比结论：

```text
baseline:    source=1, sink=2, finding=0
LLM-CTPC:    source=1, sink=2, finding=1
delta:       finding +1
```

这说明原始失败不是因为入口、source 或最终 sink 没被识别，而是中间访问路径传播缺失。

对比中 `sink=2` 仍然是同一个最终 sink 规则的两个匹配 callsite；实验没有加入中间语句或 helper 调用作为 sink。

## 4. 原始中间断开的传播语句

原始链路中关键代码如下。

source：

```text
dataset/poc/poc_cve_2024_36039_pymysql.py:30
key = cve_2024_36039_source()
```

第一个断点：污点变量作为 dict key 使用。

```text
dataset/poc/poc_cve_2024_36039_pymysql.py:31
args = {key: "safe-value"}
```

这里缺的是：

```text
key
  -> args.keys()[*]
```

第二个断点：`_escape_args` 返回的新 dict 保留原始 key。

```text
dataset/pymysql/cursors.py:104
return {key: conn.literal(val) for (key, val) in args.items()}
```

这里缺的是：

```text
args.keys()[*]
  -> _escape_args(...).keys()[*]
```

第三个断点：百分号 mapping 格式化时，mapping key 影响格式化后的 query 结构。

```text
dataset/pymysql/cursors.py:129
query = query % self._escape_args(args, conn)
```

这里缺的是：

```text
self._escape_args(args, conn).keys()[*]
  -> query
```

最终 sink：

```text
dataset/pymysql/cursors.py:153
result = self._query(query)
```

因此原始断开的核心传播语句是 3 个：

| 序号 | 位置 | 缺失语义 |
| --- | --- | --- |
| 1 | `poc_cve_2024_36039_pymysql.py:31` | dict key 传播到 `args.keys()[*]` |
| 2 | `cursors.py:104` | dict comprehension / `_escape_args` 保留 mapping keys |
| 3 | `cursors.py:129` | percent mapping key 传播到格式化后的 `query` |

## 5. Evidence Pack

Evidence Pack：

- `LAPIS/LAPIS-Experiments/reports/pymysql-llm-auto-ctpc/evidence/evidence_pack.json`

生成结果：

```text
baseline source_hit=True
baseline sink_hit=True
baseline findings=0
access_path_gap_candidate=True
top_k_edges=4
```

top-k 静态候选包括：

| kind | evidence |
| --- | --- |
| `dict_literal_key` | `args = {key: "safe-value"}` |
| `percent_mapping_key` | `query = query % self._escape_args(args, conn)` |
| `dict_comprehension_key_preserved` | `return {key: conn.literal(val) for (key, val) in args.items()}` |
| `return_fact_from_argument` | `_escape_args` 返回值保留参数 key 事实 |

Evidence Pack 只包含静态局部证据和 baseline 客观结果，不包含隐藏答案或手工 oracle。LLM 看到的是：

```text
1. baseline 已经观察到 source/sink，但 finding=0
2. source 前向切片看到 key 被放入 dict key
3. sink 后向切片看到 query 进入 self._query
4. analysis_scope 中的局部函数证据显示 _escape_args / mogrify 的关键语义
5. top-k candidate propagation obligations
```

本次为了让 LLM 能看到正确局部静态证据，Evidence Builder 增强了 PyMySQL 相关抽取：

| 证据类型 | 抽取位置 | 用途 |
| --- | --- | --- |
| `dict_literal` | PoC driver | 发现 `key -> args.keys()[*]` |
| `dict_comprehension` | `_escape_args` | 发现返回 dict 保留原始 key |
| `percent_operation` | `mogrify` | 发现 mapping key 影响格式化后的 query |
| `function_call` | `execute/mogrify/_escape_args` | 支持生成函数摘要 |

## 6. LLM API 生成的 CTPC

LLM API 使用 gpt-5 生成 CTPC：

- `LAPIS/LAPIS-Experiments/reports/pymysql-llm-auto-ctpc/ctpc/ctpc.llm.json`
- `LAPIS/LAPIS-Experiments/reports/pymysql-llm-auto-ctpc/ctpc/ctpc.json`

最终接受的 CTPC 包含：

| 类型 | 数量 |
| --- | ---: |
| `propagation_edges` | 3 |
| `function_summaries` | 1 |
| `kill_conditions` | 0 |

LLM 补充的 3 条核心数据流传播边：

| edge_id | pattern | 含义 |
| --- | --- | --- |
| `e1_dict_literal_key_to_mapping_keys` | `dict_literal_key` | `key -> args.keys()[*]` |
| `e2_dict_comprehension_preserve_keys` | `dict_comprehension_key_preserved` | dict comprehension 保留 key |
| `e3_percent_mapping_key_into_query` | `percent_mapping_key` | mapping key 影响格式化后的 `query` |

同时 LLM 生成 1 条函数摘要：

| summary_id | pattern | 含义 |
| --- | --- | --- |
| `fs1_escape_args_keys_preserved` | `return_fact_from_argument` | `_escape_args(args, conn)` 的返回值保留 `args` 的 key 事实 |

### 6.1 CTPC 接受条件

LLM 输出不是直接回灌。它必须先满足以下 gate：

```text
1. schema_version == ctpc.v2
2. pattern.kind 必须属于 YASA 解释器支持集合
3. propagation_edges 必须有 evidence file/line/code
4. 本地三分验证必须 accepted
5. YASA 三分验证必须 accepted
```

当前接受的 pattern 集合：

| 类型 | 支持 pattern |
| --- | --- |
| propagation edge | `dict_literal_key` |
| propagation edge | `dict_comprehension_key_preserved` |
| propagation edge | `percent_mapping_key` |
| function summary | `return_fact_from_argument` |

普通赋值、函数调用到最终 sink 的常规传播不由 CTPC 编造，而由原始静态分析器处理。CTPC 只补访问路径语义缺口。

## 7. 三分验证

### 7.1 本地结构三分验证

验证报告：

- `LAPIS/LAPIS-Experiments/reports/pymysql-llm-auto-ctpc/validation/reports/validation_report.json`

结果：

```text
status=accepted
must-flow: finding, passed
must-not-flow: no_finding, passed
must-kill: no_finding, passed
edge coverage: 3/3 covered
```

三类局部语义片段：

| 类型 | 文件 | 目的 |
| --- | --- | --- |
| must-flow | `validation/must-flow/case.py` | tainted key 经 dict key、dict comprehension、percent mapping 到 sink |
| must-not-flow | `validation/must-not-flow/case.py` | source 存在但不进入 mapping key，不能误报 |
| must-kill | `validation/must-kill/case.py` | key 白名单 guard 拦截后不能报 |

本地结构验证还检查 3 条 LLM propagation edge 的 coverage：

| edge_id | pattern | coverage |
| --- | --- | --- |
| `e1_dict_literal_key_to_mapping_keys` | `dict_literal_key` | covered |
| `e2_dict_comprehension_preserve_keys` | `dict_comprehension_key_preserved` | covered |
| `e3_percent_mapping_key_into_query` | `percent_mapping_key` | covered |

因此这里不是只验证最终 finding，而是确认 LLM 补出的每一类数据流语义都被局部样例覆盖。

### 7.2 YASA 三分验证

验证报告：

- `LAPIS/LAPIS-Experiments/reports/pymysql-llm-auto-ctpc/validation/yasa-runs/llm-ctpc-enhanced_yasa_validation_report.json`

结果：

```text
status=accepted
must-flow expected=finding predicted=finding passed=True
must-not-flow expected=no_finding predicted=no_finding passed=True
must-kill expected=no_finding predicted=no_finding passed=True
```

这一步很关键：只有本地结构验证和真实 YASA 三分验证都通过后，CTPC 才被接受并进入 full-CVE 回灌。

### 7.3 三分样例设计细节

must-flow 正例：

```python
key = source()
args = {key: "safe-value"}
escaped = {key: quote(val) for (key, val) in args.items()}
query = query % escaped
sink(query)
```

预期：`finding`。该样例覆盖 3 条 CTPC propagation edge。

must-not-flow 负例：

```python
unrelated = source()
args = {"name": "safe-value"}
escaped = {key: quote(val) for (key, val) in args.items()}
query = query % escaped
sink(query)
return unrelated
```

预期：`no_finding`。该样例保证 source 存在，但 source 不进入 mapping key，也不进入 mapping value，防止 CTPC 无条件泛化。

must-kill 抑制例：

```python
key = source()
if key not in {"name", "email"}:
    return
args = {key: "safe-value"}
escaped = {key: quote(val) for (key, val) in args.items()}
query = query % escaped
sink(query)
```

预期：`no_finding`。该样例测试白名单 guard 下的安全路径不应报。

## 8. Full-CVE 回灌结果

回灌 CTPC 后完整扫描报告：

- `LAPIS/LAPIS-Experiments/reports/pymysql-llm-auto-ctpc/runs/llm-auto-ctpc/llm-auto-ctpc_full_cve_report.json`

结果：

```text
status=reported
result=finding
findingCount=1
markedSourceCount=1
matchedSinkCount=2
```

`matchedSinkCount=2` 仍然来自唯一 `self._query` sink 规则：它表示该 fsig 在 full-CVE 数据集中匹配到 2 个调用点，不表示规则中存在 2 个 sink。

CTPC diagnostics：

- `LAPIS/LAPIS-Experiments/reports/pymysql-llm-auto-ctpc/runs/llm-auto-ctpc/llm-auto-ctpc/lapis-ctpc-diagnostics.jsonl`

关键诊断：

```text
action=force
reason=ctpc access-path propagation reached sql_injection value query
sink=self._query
line=153
```

说明 CTPC 风险事实已经到达最终 sink 的参数 `query`。

### 8.1 完整链路解释

回灌后 YASA 输出的 finding 落点：

```text
File: /pymysql/cursors.py
Line 153: self._query(query)
SINK RULE: self._query
SINK Attribute: CVE-2024-36039-pymysql-query-send
```

关键 CTPC 诊断：

```text
LAPIS CTPC: ctpc access-path propagation reached sql_injection value query;
final sink self._query
```

对应闭合后的语义链路：

```text
cve_2024_36039_source()
  -> key
  -> args = {key: "safe-value"}
  -> args.keys()[*]
  -> _escape_args(args, conn)
  -> returned mapping keys
  -> query = query % self._escape_args(args, conn)
  -> query
  -> self._query(query)
```

这里的最终 sink 仍然是单一最终 sink `self._query(query)`。

## 9. 自动化实现细节

本实验涉及的自动化阶段和产物如下：

| 阶段 | 命令/模块 | 产物 |
| --- | --- | --- |
| Evidence 构造 | `python3 -m lapis build-evidence` | `evidence/evidence_pack.json` |
| CTPC 计划 | `python3 -m lapis plan-ctpc-repair` | `ctpc/plan.json` |
| CTPC prompt | `python3 -m lapis build-ctpc-prompt` | `ctpc/ctpc_prompt.md` |
| LLM 生成 CTPC | `python3 -m lapis llm-generate-ctpc` | `ctpc/ctpc.llm.json` |
| CTPC 物化 | `python3 -m lapis materialize-ctpc` | `ctpc/ctpc.json` |
| 局部样例物化 | `python3 -m lapis materialize-validation` | `validation/*/case.py` |
| 本地三分验证 | `python3 -m lapis validate-ctpc` | `validation/reports/validation_report.json` |
| YASA 验证规则 | `python3 -m lapis build-validation-rules` | `validation/yasa-rules/*.json` |
| YASA 三分验证 | `python3 -m lapis run-yasa-validation` | `validation/yasa-runs/llm-ctpc-enhanced_yasa_validation_report.json` |
| full-CVE 回灌 | `python3 -m lapis run-yasa-case --ctpc-file ...` | `runs/llm-auto-ctpc/llm-auto-ctpc_full_cve_report.json` |

### 9.1 本次实现改动

为了完成闭环，本次实现做了三类必要改动：

| 文件 | 改动 |
| --- | --- |
| `LAPIS/LAPIS-Core/src/lapis/cli.py` | 增强 PyMySQL CTPC evidence builder，提取 `_escape_args`、`mogrify`、dict comprehension、percent formatting 等局部静态证据 |
| `LAPIS/LAPIS-Core/src/lapis/prompt.py` | 收紧 CTPC prompt，限制 LLM 只能输出 YASA 解释器支持的 pattern |
| `LAPIS/LAPIS-Tool/src/checker/taint/python/lapis-ctpc.ts` | 当 CTPC 风险事实到达原始最终 sink 实参时，允许结合原始 sink 规则 force finding |

这些改动不把答案写死到 PyMySQL case；它们把流程变成：

```text
证据足够具体
  -> LLM 生成结构化 CTPC
  -> gate 检查 pattern 与三分语义
  -> YASA 解释器按 CTPC 事实驱动 finding
```

## 10. 与 baseline 的最终对比

| 指标 | baseline | LLM-CTPC 回灌 | 变化 |
| --- | ---: | ---: | ---: |
| findingCount | 0 | 1 | +1 |
| markedSourceCount | 1 | 1 | 0 |
| matchedSinkCount | 2 | 2 | 0 |
| entryPointCount | 1 | 1 | 0 |
| fileCount | 20 | 20 | 0 |
| lineCount | 4367 | 4367 | 0 |

实验含义：

```text
source/sink/entrypoint 数量没有靠放宽规则改变；
finding 的出现来自 CTPC 补齐缺失访问路径传播。
```

回灌后的完整扫描用时：

```text
totalTimeMs=5679
parseMs=5166
symbolInterpretMs=56
```

原始 baseline 用时：

```text
totalTimeMs=6258
parseMs=5714
symbolInterpretMs=51
```

运行时间差异主要来自普通扫描波动，不作为本实验核心指标。核心指标是：

```text
baseline finding=0
LLM-CTPC finding=1
三分验证 accepted
```

## 11. 是否完整

对当前 final-sink-only 实验，闭环是完整的：

```text
LLM 生成 CTPC
  -> 本地三分验证 accepted
  -> YASA 三分验证 accepted
  -> 回灌 full-CVE
  -> 单一最终 sink self._query(query) 产生 finding
```

需要注意的边界：

1. 本实验验证的是 PyMySQL 这个 propagation gap case。
2. 当前 CTPC 的核心补充是 3 条 propagation edge + 1 条 function summary。
3. `kill_conditions` 为空，但 must-kill 仍在局部样例和 YASA 样例中通过；它验证的是 guarded safe pattern 不应产生最终 finding。
4. 本实验没有使用多 sink 放宽结果；最终 finding 落在 `self._query(query)`。

因此结论是：

```text
PyMySQL CTPC 实验已经通过 gpt-5 LLM API 完成自动契约生成、
三分验证、静态分析器回灌和 full-CVE finding 闭环。
```

## 12. 产物索引

| 产物 | 路径 |
| --- | --- |
| 中文报告 | `LAPIS/LAPIS-Experiments/reports/pymysql-llm-auto-ctpc/PYMYSQL_LLM_AUTO_CTPC_REPORT_CN.md` |
| Evidence Pack | `LAPIS/LAPIS-Experiments/reports/pymysql-llm-auto-ctpc/evidence/evidence_pack.json` |
| CTPC plan | `LAPIS/LAPIS-Experiments/reports/pymysql-llm-auto-ctpc/ctpc/plan.json` |
| CTPC prompt | `LAPIS/LAPIS-Experiments/reports/pymysql-llm-auto-ctpc/ctpc/ctpc_prompt.md` |
| LLM 原始 CTPC | `LAPIS/LAPIS-Experiments/reports/pymysql-llm-auto-ctpc/ctpc/ctpc.llm.json` |
| 接受的 CTPC | `LAPIS/LAPIS-Experiments/reports/pymysql-llm-auto-ctpc/ctpc/ctpc.json` |
| 本地三分验证报告 | `LAPIS/LAPIS-Experiments/reports/pymysql-llm-auto-ctpc/validation/reports/validation_report.json` |
| YASA 三分验证报告 | `LAPIS/LAPIS-Experiments/reports/pymysql-llm-auto-ctpc/validation/yasa-runs/llm-ctpc-enhanced_yasa_validation_report.json` |
| full-CVE 回灌报告 | `LAPIS/LAPIS-Experiments/reports/pymysql-llm-auto-ctpc/runs/llm-auto-ctpc/llm-auto-ctpc_full_cve_report.json` |
| CTPC diagnostics | `LAPIS/LAPIS-Experiments/reports/pymysql-llm-auto-ctpc/runs/llm-auto-ctpc/llm-auto-ctpc/lapis-ctpc-diagnostics.jsonl` |

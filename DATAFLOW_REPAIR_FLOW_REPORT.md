# 数据流断链修复流程报告

## 1. 定位

本报告只描述 **Call Graph 基本完整，但数据流 / taint propagation 不完整** 的修复流程。

对应产物是：

```text
CTPC: Conditional Taint Propagation Contract
```

它和缺失调用边修复分开：

```text
调用边修复：
  分析进不去真实 callee，需要补 callsite -> callee。

数据流修复：
  分析已经能到相关代码区域，但 access-path / value-flow / taint fact 没有传播过去。
```

## 2. 目标

数据流修复要回答：

```text
某个 source fact 为什么没有传播到 sink-relevant value？
缺的是哪一种 access-path propagation？
能否用结构化契约描述这个传播义务？
该契约是否能通过正例、反例、kill 例验证？
```

最终目标不是让 LLM 直接声称有漏洞，而是生成可验证的传播契约：

```text
Evidence Pack -> CTPC -> validation samples -> validation report -> accepted/rejected/inconclusive
```

## 3. 总体流程

```text
1. 跑 YASA baseline
   获取 source/sink 命中、finding/no-finding、trace、UAST、局部源码。

2. 定位数据流断点
   找 source forward frontier 和 sink backward dependency 的会聚区域。

3. 构造 Evidence Pack
   提取 access path、赋值、容器、函数调用、返回值、格式化、guard 等静态证据。

4. 生成候选传播义务
   规则或 LLM 基于 Evidence Pack 提出 propagation edge / function summary / kill condition。

5. 生成 CTPC
   将候选传播义务 materialize 成结构化 CTPC。

6. 生成 validation artifacts
   根据 CTPC 生成 must-flow、must-not-flow、must-kill 三类样例。

7. 运行 validation
   先结构模拟验证；可选再运行 YASA baseline/enhanced 双运行验证。

8. 输出 validation_report
   给出 accepted / rejected / inconclusive，并输出 edge coverage 和 feedback。

9. 接受并回灌
   accepted CTPC 可进入契约库或作为增强规则输入，之后重新跑原始 case。
```

## 4. 断点定位

数据流断点通常满足：

```text
source 已被标记
sink 已被规则匹配
控制/调用上下文大体可达
但 taint trace 没有从某个 access path 传播到 sink 参数
```

定位需要两侧信息：

```text
Source forward frontier:
  source taint 已经传播到哪里，停在哪个变量、字段、容器或返回值。

Sink backward dependency:
  sink 参数依赖哪些变量、字段、容器元素、格式化结果或函数返回值。
```

若 forward frontier 和 backward dependency 在某个局部结构附近会聚，则进入 Evidence Pack 构造。

## 5. Evidence Pack

Evidence Pack 是 CTPC 的输入，不是契约本体。

它应该记录：

```text
source evidence
sink evidence
frontier variable / access path
backward dependency variable / access path
local AST/UAST snippet
assignment / call / return / operator structure
container shape
function summary hint
safe evidence / kill guard
missing propagation hypothesis
```

示例结构：

```json
{
  "case_id": "cve-2024-36039-pymysql",
  "breakpoint": {
    "kind": "missing_access_path_propagation",
    "source_frontier": "args.keys()[*]",
    "sink_dependency": "final_query",
    "location": "cursors.py:109"
  },
  "source_evidence": {
    "symbol": "key",
    "expr": "key = source()"
  },
  "local_structure": [
    {
      "kind": "dict_literal",
      "expr": "args = {key: \"safe-value\"}"
    },
    {
      "kind": "dict_comprehension",
      "expr": "escaped = {key: conn.literal(val) for (key, val) in args.items()}"
    },
    {
      "kind": "percent_format",
      "expr": "final_query = query % escaped"
    }
  ],
  "safe_evidence": [
    {
      "kind": "value_only_parameterization",
      "expr": "args = {\"name\": val}"
    }
  ]
}
```

## 6. 候选传播义务

Evidence Pack 后生成的是候选传播义务，而不是 validation sample。

候选传播义务包括：

```text
propagation edge:
  局部结构内 fact A -> fact B。

function summary:
  函数调用中 argument fact -> return fact。

risk upgrade:
  某类 fact 被特定 operator 消费后升级为风险 fact。

kill condition:
  某个 guard / sanitizer / safe pattern 抑制风险。
```

例如：

```text
dict literal key:
  tainted_symbol($key) -> mapping_key($lhs.keys()[*])

dict comprehension:
  mapping_key($map.keys()[*]) -> mapping_key($lhs.keys()[*])

percent formatting:
  mapping_key($rhs.keys()[*]) -> sql_structure_value($result)

function summary:
  mapping_key($arg0.keys()[*]) -> mapping_key($return.keys()[*])
```

## 7. CTPC 本体

CTPC 本体描述候选传播契约，不包含具体 must-flow / must-not-flow / must-kill 样例。

LAPIS 当前结构化版本为：

```text
ctpc.v2
```

核心字段：

```json
{
  "schema_version": "ctpc.v2",
  "contract_name": "pymysql_dict_key_percent_format",
  "gap_type": [],
  "applies_to": {},
  "fact_types": [],
  "propagation_edges": [],
  "function_summaries": [],
  "risk_upgrades": [],
  "kill_conditions": [],
  "validation_expectations": {
    "must_flow": "finding",
    "must_not_flow": "no_finding",
    "must_kill": "no_finding"
  }
}
```

字段含义：

| 字段 | 作用 |
|---|---|
| `fact_types` | 定义新的传播事实形状，如 mapping key、SQL structure value |
| `propagation_edges` | 描述局部 AST 结构中的 fact 传播 |
| `function_summaries` | 描述跨函数 argument -> return 的传播 |
| `risk_upgrades` | 描述 fact 如何升级成风险 fact |
| `kill_conditions` | 描述何种 guard/safe pattern 会 suppress 风险 |
| `validation_expectations` | 描述三分样例的预期结果，不是样例本体 |

## 8. 三分验证样例

验证器根据 Evidence Pack + CTPC 生成三类样例目录：

```text
validation/must-flow
validation/must-not-flow
validation/must-kill
```

三者不写进 CTPC 本体。

### 8.1 must-flow

正例。契约应该让数据流打通。

预期：

```text
finding
```

用途：

```text
证明 CTPC 能解释原始断点中的缺失 propagation。
```

### 8.2 must-not-flow

反例。相似结构下不应该误报。

预期：

```text
no_finding
```

用途：

```text
防止契约过宽，例如把普通 value taint 错当成 SQL structure risk。
```

### 8.3 must-kill

kill 例。guard / whitelist / sanitizer 生效后应抑制风险。

预期：

```text
no_finding
```

用途：

```text
证明 kill_conditions 真正限制了传播，而不是装饰性字段。
```

## 9. Validation Report

验证结果单独输出：

```json
{
  "ctpc": "ctpc.v2.json",
  "validation_dir": "validation",
  "status": "accepted",
  "sample_results": [
    {
      "sample": "must-flow",
      "expected": "finding",
      "predicted": "finding",
      "passed": true
    },
    {
      "sample": "must-not-flow",
      "expected": "no_finding",
      "predicted": "no_finding",
      "passed": true
    },
    {
      "sample": "must-kill",
      "expected": "no_finding",
      "predicted": "no_finding",
      "passed": true
    }
  ],
  "edge_coverage": [],
  "feedback": []
}
```

判定：

```text
accepted:
  must-flow 通过
  must-not-flow 通过
  must-kill 通过
  关键 propagation_edges / function_summaries 被样例覆盖

rejected:
  must-flow 不通
  或 must-not-flow / must-kill 出现误报
  或契约过宽/过窄

inconclusive:
  样例不足
  edge coverage 不足
  runner 无法裁决
```

## 10. YASA 复验

LAPIS 的验证分两层：

```text
Local structural validation:
  用结构模拟器检查 CTPC 是否解释三分样例。

YASA-in-the-loop validation:
  对 must-flow / must-not-flow / must-kill 分别跑 YASA，
  比较 baseline/enhanced 的 finding/no-finding。
```

README 中已有对应命令：

```text
validate-ctpc
run-yasa-validation
run-yasa-case
```

最终仍需在原始 CVE case 上复验：

```text
accepted CTPC
  -> enhanced analysis
  -> original source-to-sink chain 是否恢复
```

## 11. 停止条件

数据流修复循环需要停止条件：

```text
成功停止:
  原始 source-to-sink chain 被恢复。

无会聚区域:
  source frontier 和 sink backward dependency 找不到局部会聚。

无候选义务:
  Evidence Pack 无法生成 propagation obligation。

三分验证失败:
  must-flow / must-not-flow / must-kill 任一关键样例失败。

样例不足:
  无法生成有区分度的反例或 kill 例。

预算耗尽:
  每个 case 的 CTPC 生成和验证轮数达到上限。
```

## 12. 产物目录

建议保持 LAPIS 当前目录风格：

```text
case/
  evidence/
    evidence_pack.json
  ctpc/
    ctpc.json
    ctpc.v2.json
  validation/
    must-flow/
    must-not-flow/
    must-kill/
    yasa-rules/
    reports/
      validation_report.json
  validation/yasa-runs/
    ...
  full-cve-runs/
    ...
```

## 13. 与调用边修复的边界

```text
如果断点是 symbolic/dangling callee，优先进入调用边 CCEC 分支。

如果 CG 已经能到相关函数，但 access-path 没传播，进入数据流 CTPC 分支。

如果二者同时存在，先补调用边，让分析进入真实 callee；
再重新跑 baseline，检查是否还存在数据流断链。
```

## 14. 一句话总结

```text
CTPC 流程不是直接让 LLM 修漏洞，
而是让 Evidence Pack 生成结构化传播契约，
再用 must-flow / must-not-flow / must-kill 三分验证决定是否接受。
```

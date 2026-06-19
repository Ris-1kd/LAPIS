# 静态污点断链整体修复流程

## 0. 目标

本流程面向 YASA/LAPIS 分析中 **未报 finding 的候选 case**，判断它是否可能是有证据支持的漏报，并进一步区分：

```text
Connectivity Gap:
  Call Graph 不完整，需要补调用边。

Propagation Gap:
  Call Graph 基本完整，但 access-path / value-flow / taint propagation 不完整。

Mixed Case:
  调用边和数据流传播都存在缺口。
```

重要边界：

```text
系统不把所有 no-finding 都当成漏报。
系统不为了产生 finding 强行补边或补传播。
系统只能筛出 evidence-supported candidate FN。
```

在真实未知项目里，系统通常不能百分百证明“真正 FN”。它输出的是：

```text
evidence-supported candidate false negative
```

只有在 CVE benchmark 中，借助 PoC、patch、advisory 或人工 oracle，才可以标注为真实 FN。

## Step 1：Evidence Gate

Evidence Gate 是证据门控。它位于所有修复之前，用来判断：

```text
这个 no-finding case 该不该进入断链诊断与修复？
```

### 1.1 输入

```text
未报 finding 的候选 case
YASA baseline 结果
source/sink rules
callgraph.json
UAST / AST
trace / diagnostics / source-sink hit 信息
```

### 1.2 门控检查

Evidence Gate 至少检查：

```text
1. source 是否命中？
2. sink 是否命中？
3. source 和 sink 是否存在调用上下文关联？
4. source forward frontier 到达了哪里？
5. sink backward dependency 依赖哪些变量、字段、容器、字符串？
6. 是否存在 symbolic/dangling callee？
7. 是否存在局部结构连接证据？
8. 是否存在 sanitizer、参数化查询、trusted overwrite、安全覆盖等反证？
9. 候选补边是否会导致图爆炸？
```

### 1.3 关键证据

Evidence Gate 不是深度修复器，只做第一层过滤。它关注的是：

```text
endpoint evidence:
  source hit, sink hit

context evidence:
  call context, entrypoint, reachable module/function region

frontier evidence:
  source taint/value-flow 已经传播到哪里

backward evidence:
  sink 参数依赖哪些局部变量、字段、容器或返回值

symbolic evidence:
  CG 中是否存在 symbolic/dangling callee

local structure evidence:
  assignment、call、return、container、format、registry、decorator 等局部连接结构

negative evidence:
  sanitizer、参数化查询、trusted overwrite、safe guard、impossible branch

explosion risk:
  补边候选是否过多，是否会产生过宽 CG
```

### 1.4 输出类别

Evidence Gate 输出五类：

| 类别 | 含义 | 后续动作 |
|---|---|---|
| A. candidate_fn | 有证据支持的候选漏报 | 进入 Step 2 断链类型诊断 |
| B. true_negative | 无结构连接证据，不像漏报 | 不修 |
| C. safe_killed | 被 sanitizer / 参数化安全 / trusted overwrite 阻断 | 不修 |
| D. infeasible | 调用上下文或路径不可达 | 不修 |
| E. deferred | 证据不足，暂缓 | 不修或等待更多证据 |

### 1.5 Evidence Gate 示例输出

```json
{
  "case_id": "example-case",
  "gate_status": "candidate_fn",
  "source_hit": true,
  "sink_hit": true,
  "call_context_related": true,
  "source_frontier": [
    {
      "location": "app.py:42",
      "kind": "symbolic_callee",
      "expr": "getattr(self, name)(req)"
    }
  ],
  "sink_backward_dependency": [
    {
      "sink": "os.system(cmd)",
      "depends_on": ["cmd", "handler_result"]
    }
  ],
  "symbolic_callee_present": true,
  "local_structure_evidence": ["name def-use", "receiver class methods"],
  "negative_evidence": [],
  "explosion_risk": "low",
  "decision_reason": "source/sink both hit, frontier stops at symbolic callee, and local receiver/name evidence exists"
}
```

## Step 2：断链类型诊断

通过 Evidence Gate 后，系统判断该 candidate FN 属于哪类欠传播。

具体 CVE benchmark 的三类样本矩阵见：[CVE_DATASET_CASE_MATRIX.md](/home/ubuntu/llm-yasa-repair/CVE_DATASET_CASE_MATRIX.md)。

### 2.1 三类断链

| 类型 | 名称 | 含义 | 修复分支 |
|---|---|---|---|
| 1 | Connectivity Gap | 调用连接性缺失，Call Graph 不完整 | CCEC 调用边修复 |
| 2 | Propagation Gap | CG 基本完整，但 taint/value/access-path 不通 | CTPC 数据流修复 |
| 3 | Mixed Case | 调用边和数据流传播同时缺失 | 先 CCEC，重跑，再 CTPC |

### 2.2 Connectivity Gap 判断

满足以下特征时，进入调用边修复：

```text
source frontier 到达某个 callsite
baseline CG 出现 symbolic/dangling callee
callee 无 funcDef 或只有表达式名
存在 resolved callee universe 可供选择
存在 receiver/name/key/import/registration/signature 证据
```

典型表现：

```python
getattr(obj, name)()
handlers[key](req)
registry[name].run(data)
callback(req)
dispatcher.dispatch(action, req)
```

### 2.3 Propagation Gap 判断

满足以下特征时，进入数据流修复：

```text
source 和 sink 位于可解释的调用上下文中
相关函数/调用边基本可达
没有主要 symbolic callee 阻断
source forward frontier 与 sink backward dependency 在局部结构附近会聚
缺的是 access-path / container / function summary / operator propagation
```

典型表现：

```python
args = {key: "safe-value"}
escaped = {key: escape(val) for (key, val) in args.items()}
query = query % escaped
sink(query)
```

### 2.4 Mixed Case 判断

同时满足两类特征时，标记为 Mixed Case：

```text
存在 symbolic/dangling callee 阻断
并且在可见局部结构中也存在 propagation gap 迹象
```

处理顺序固定：

```text
1. 先补调用边 CCEC
2. 将 accepted CCEC 应用到 repaired CG 或回灌分析器
3. 重跑 baseline/enhanced analysis
4. 如果 source-sink 仍然 taint 不通，再进入 CTPC 数据流修复
```

原因：

```text
如果分析还没有进入真实 callee，数据流证据通常不完整。
先恢复调用连接性，才能更可靠地判断是否仍缺传播语义。
```

### 2.5 诊断输出

```json
{
  "case_id": "example-case",
  "gate_status": "candidate_fn",
  "diagnosis": {
    "gap_type": "mixed_case",
    "primary_gap": "connectivity_gap",
    "secondary_gap": "possible_propagation_gap",
    "reason": [
      "source frontier stops at symbolic callee getattr(self, name)",
      "sink backward dependency points to handler result",
      "local dict/format propagation evidence may require CTPC after call edge repair"
    ]
  },
  "next_step": "run_ccec_first"
}
```

## Step 3A：Connectivity Gap 修复：CCEC

CCEC 分支修复缺失调用边。

### 3A.1 输入

```text
Evidence Gate 输出
Connectivity Gap 诊断
Call Edge Evidence Bundle
resolved callee universe
```

### 3A.2 证据文件与候选空间

规则层先抽取证据文件，不直接输出最终候选边。

证据包括：

```text
symbolic callsite
caller context
callsite AST shape
receiver expression
dynamic name/key expression
def-use / constant value
receiver possible type
class method set
candidate callee universe
signature compatibility
import/module alias
registration/callback evidence
sink relevance / frontier progress
negative evidence / explosion risk
```

### 3A.3 easy / middle / hard 分层

根据证据文件先做三分类：

| 分层 | 条件 | 生成策略 |
|---|---|---|
| easy | 证据唯一确定 callee，低风险 | 规则生成候选边和 CCEC，不调用 LLM |
| middle | 候选空间小，有轻微歧义 | 规则生成 Top-K，或 LLM rerank/explain |
| hard | 候选空间大，跨函数/跨模块，证据冲突 | LLM 在候选空间内提出/排序候选边 |

LLM 约束：

```text
只能使用 evidence file 和 callee universe
不能生成项目中不存在的 callee
不能直接决定 accepted
只能输出 candidate edge proposal / rank / reason / risk
```

### 3A.4 生成候选边与 CCEC

分层后才生成候选边：

```json
{
  "breakpoint_id": "bp-001",
  "difficulty": "middle",
  "generator": "llm_rerank",
  "candidate_edges": [
    {
      "candidate_id": "edge-001",
      "from_callsite": "app.py:42:method(req)",
      "to_callee": "app.py:12:Handler.do_exec",
      "pattern_kind": "getattr_result_call",
      "score": 0.91,
      "evidence": {},
      "risk": {}
    }
  ]
}
```

然后 materialize 为：

```text
ccec.v1.json
```

CCEC 本体包含：

```text
pattern
from callsite
to callee
guards
binding
evidence
risk
validation_expectations
```

### 3A.5 CCEC 三分验证

验证器根据 CCEC 生成：

```text
validation/must-link
validation/must-not-link
validation/must-kill
```

预期：

| 样例 | 预期 |
|---|---|
| must-link | edge_exists |
| must-not-link | edge_absent |
| must-kill | edge_absent |

输出：

```text
ccec_validation_report.json
```

接受条件：

```text
must-link 通过
must-not-link 通过
must-kill 通过
edge coverage 通过
repaired graph 中 source frontier 前进或更接近 sink
```

## Step 3B：Propagation Gap 修复：CTPC

CTPC 分支修复数据流传播缺口。

### 3B.1 输入

```text
Evidence Gate 输出
Propagation Gap 诊断
Dataflow Evidence Pack
source forward frontier
sink backward dependency
local convergence region
```

### 3B.2 Evidence Pack

Evidence Pack 记录：

```text
source evidence
sink evidence
frontier access path
backward dependency access path
assignment / call / return / operator
container shape
function summary hint
risk kind
safe evidence / kill guard
```

### 3B.3 候选传播义务

候选传播义务包括：

```text
propagation_edges
function_summaries
risk_upgrades
kill_conditions
```

### 3B.4 生成 CTPC

生成：

```text
ctpc.v2.json
```

CTPC 本体包含：

```text
fact_types
propagation_edges
function_summaries
risk_upgrades
kill_conditions
validation_expectations
```

### 3B.5 CTPC 三分验证

验证器根据 CTPC 生成：

```text
validation/must-flow
validation/must-not-flow
validation/must-kill
```

预期：

| 样例 | 预期 |
|---|---|
| must-flow | finding |
| must-not-flow | no_finding |
| must-kill | no_finding |

输出：

```text
ctpc_validation_report.json
```

接受条件：

```text
must-flow 通过
must-not-flow 通过
must-kill 通过
关键 propagation edge / function summary 被覆盖
```

## Step 4：Mixed Case 处理

Mixed Case 固定顺序：

```text
1. CCEC 修复调用边
2. 应用 accepted CCEC
3. 重跑 baseline/enhanced analysis
4. 再次执行 Evidence Gate 和断链类型诊断
5. 如果仍是 Propagation Gap，再进入 CTPC
6. 如果 source-sink 已打通，停止
```

伪代码：

```python
if gap_type == "mixed_case":
    ccec_report = repair_connectivity_gap(case)
    if not ccec_report.accepted:
        return ccec_report

    rerun = run_analyzer_with_accepted_ccec(case)
    gate = evidence_gate(rerun)
    diagnosis = diagnose_gap_type(gate, rerun)

    if diagnosis.gap_type == "propagation_gap":
        return repair_propagation_gap(case, rerun)
    if rerun.finding_reported:
        return "fixed"
    return "inconclusive"
```

## Step 5：回灌与复验

回灌分两种：

```text
External repaired graph:
  不改 YASA，引入 accepted CCEC/CTPC 后在外部 repaired graph 上验证。

YASA-in-the-loop:
  若契约可以表达为 YASA 规则/config/adapter，则重跑 YASA 做 finding/no-finding 复验。
```

最终报告应记录：

```text
baseline no-finding
Evidence Gate 决策
gap diagnosis
accepted CCEC / CTPC
validation reports
repaired graph progress
是否恢复 source-to-sink chain
是否需要人工 oracle
```

## Step 6：停止条件

整体循环停止条件：

```text
success:
  source-to-sink chain 被验证恢复。

not_candidate:
  Evidence Gate 输出 true_negative / safe_killed / infeasible。

deferred:
  Evidence Gate 输出 deferred。

connectivity_unrepairable:
  无 callee universe，或补边会导致图爆炸。

propagation_unrepairable:
  无局部会聚区域，或无法生成 CTPC。

validation_rejected:
  三分验证失败。

inconclusive:
  证据不足、样例不足、top candidates 无法区分。

budget_exhausted:
  迭代轮数或验证次数达到上限。
```

## 产物目录建议

```text
case/
  baseline/
    callgraph.json
    findings.json
    diagnostics.json
  gate/
    evidence_gate_report.json
  diagnosis/
    gap_diagnosis.json
  ccec/
    evidence_bundle.json
    ccec.v1.json
    validation/
      must-link/
      must-not-link/
      must-kill/
    ccec_validation_report.json
  ctpc/
    evidence_pack.json
    ctpc.v2.json
    validation/
      must-flow/
      must-not-flow/
      must-kill/
    ctpc_validation_report.json
  repaired/
    repaired_callgraph.json
    repaired_value_flow.json
    final_repair_report.json
```

## 总结

完整修复流程是：

```text
Evidence Gate:
  先判断该不该修，过滤 true negative / safe killed / infeasible。

Gap Diagnosis:
  再判断是 Connectivity Gap、Propagation Gap，还是 Mixed Case。

CCEC:
  对调用边缺失，先证据分层，再由规则或 LLM 生成候选边与 CCEC，并做三分验证。

CTPC:
  对数据流缺失，生成传播契约 CTPC，并做 must-flow / must-not-flow / must-kill 验证。

Mixed:
  先 CCEC，重跑；若 taint 仍断，再 CTPC。
```

# 缺失调用边修复方案

## 1. 定位

本方案只处理 **Call Graph 不完整导致的断链**：

```text
真实语义存在 caller callsite -> callee，
但 YASA baseline CG 中只出现 symbolic/dangling callee，
或调用边停在不可解析的占位节点。
```

它和“CG 基本完整但 taint 不传播”的数据流修复分开处理。调用边修复的核心产物是外部生成的候选边契约：

```text
CCEC: Conditional Call Edge Contract
```

当前工程中，YASA 不再只是完全黑盒。LAPIS 将验证后的 CCEC 作为
`--ccec-file` 传给修改版 `LAPIS-Tool`，由工具内部真实消费：

```text
LAPIS-Core:
  生成 / 验证 / 传入 CCEC，并汇总 contract consumption diagnostics。

LAPIS-Tool:
  在 Python analyzer 中匹配 CCEC callsite，把调用指向 materialized target；
  在 taint checker 中处理 CCEC boundary / virtual sink，并输出诊断。
```

关键实现：

```text
LAPIS-Tool/src/engine/analyzer/python/common/python-analyzer.ts
  materialized CCEC call edge matching
  lapis-ccec-materialized-diagnostics.jsonl

LAPIS-Tool/src/checker/taint/python/lapis-ccec.ts
  CCEC boundary / virtual sink consumption
  lapis-ccec-diagnostics.jsonl

LAPIS-Core/src/lapis/yasa_runner.py
  summarize_contract_consumption()
  render_reconstructed_ccec_chain_lines()
  render_ordered_source_to_sink_chain_lines()
```

## 2. 总体流程

```text
1. 跑 YASA baseline
   输入源码、规则、entrypoint，导出 callgraph.json、findings/trace、AST/UAST。

2. 定位 source forward frontier
   从 source 出发，在 CG/taint/value-flow 上找所有能到达但继续不下去的断点集合。

3. 识别 symbolic/dangling callee
   断点满足 callee 无 funcDef、只有表达式名、unknown function、或边停在 symbolic 节点。

4. 构造 Evidence Bundle
   抽取 CG、UAST、def-use、constant、class/type、import/module、signature 等静态证据。

5. 生成证据文件与候选空间
   规则层抽取 Evidence Bundle、resolved callee universe、receiver/name/signature 等事实。

6. easy / middle / hard 分层
   根据证据完整度、歧义度、候选空间大小和风险决定后续由规则还是大模型生成候选边/CCEC。

7. 候选边生成与 Top-K
   easy 由规则生成唯一候选边；middle 由规则生成 Top-K 或 LLM rerank；
   hard 由 LLM 在候选空间内提出/排序候选边。

8. LLM 生成 CCEC
   `llm-generate-ccec` 基于 case/gate/diagnosis 调用 LLM API，
   输出 `candidate_edges.llm.json`。

9. 结构验证 / 三分验证
   `validate-ccec-candidates` 检查候选边结构；
   对需要三分验证的 case，可生成 must-link / must-not-link / must-kill
   validation contract。

10. YASA 真实消费
   `run-yasa-case --ccec-file ...` 将 CCEC 交给 `LAPIS-Tool`。
   成功消费时报告中出现：

   ```text
   ccec_status=materialized_call_edge_consumed
   ccec_materialized_matches>0
   ```

11. 迭代或停止
   如果 CCEC 后仍是 `ccec_callgraph_closed_taint_open` 或 `needs_ctpc=true`，
   说明调用边已闭合但传播 fact 不完整，需要进入 CTPC。
   如果 `reported/finding` 且 ordered trace 完整，则闭环完成。
```

## 2.1 当前已验证 CCEC Case

| CVE | 项目 | 类型 | baseline | CCEC 后结果 | 是否需要 CTPC |
|---|---|---|---|---|---|
| CVE-2023-24816 | IPython | connectivity_gap | `finding=0` | `reported/finding=1` | 否 |
| CVE-2024-27758 | RPyC | connectivity_gap | `finding=0` | `reported/finding>0` | 否，最新闭环以 CCEC 为主 |
| CVE-2026-24486 | python-multipart | mixed_case | `finding=0` | CCEC 后仍 `finding=0` | 是 |
| CVE-2025-55156 | pyLoad | mixed_case | `finding=0` | CCEC 后仍 `finding=0` | 是 |

最新产物路径：

```text
LAPIS-Experiments/reports/ipython-ccec/ccec/candidate_edges.llm.json
LAPIS-Experiments/reports/rpyc-llm-auto-ccec/ccec/candidate_edges.llm.json
LAPIS-Experiments/reports/python-multipart-llm-auto-mixed-latest/ccec/candidate_edges.llm.json
LAPIS-Experiments/reports/pyload-llm-auto-mixed-latest/ccec/candidate_edges.llm.json
```

复扫命令形态：

```bash
PYTHONPATH=LAPIS-Core/src python3 -m lapis run-yasa-case \
  --tool-dir LAPIS-Tool \
  --case LAPIS-Experiments/cases/connectivity_gap/cve-2023-24816-ipython/case.json \
  --out-dir LAPIS-Experiments/reports/reproduce-ipython/final-ccec \
  --uast-sdk-path /path/to/YASA-Engine-upstream/uast4py-linux-amd64 \
  --label final-ccec \
  --timeout-seconds 180 \
  --ccec-file LAPIS-Experiments/reports/ipython-ccec/ccec/candidate_edges.llm.json
```

## 3. Source Forward Frontier

如果 source 出发有多条路径，frontier 不是单个“最远点”，而是集合：

```text
ForwardFrontier(source) = { bp1, bp2, bp3, ... }
```

每个 breakpoint 代表一条 source-reachable 路径当前走不下去的位置。

每条路径维护状态：

```json
{
  "current": "current CG node or callsite",
  "path_prefix": ["..."],
  "taint_state": {},
  "access_path_state": {},
  "call_context": [],
  "path_condition": [],
  "visited_budget": 0
}
```

处理规则：

```text
resolved callee 且可继续传播 -> 扩展路径
symbolic/dangling callee -> 加入 frontier set
unknown function / 缺调用边 -> 加入 frontier set
到达 sink -> 标记 success
循环/递归/重复状态 -> 按 budget 截断
```

每轮从 frontier set 里选择 top-M 个断点进行修复。优先级可以由以下因素决定：

```text
taint 是否到达 callsite
是否支配其它断点
候选数量是否少
证据是否强
是否靠近 sink backward slice
补边后预计能解锁多少后继节点
```

## 4. 为补调用边需要抽取的静态图信息

调用边修复不需要抽取所有污点相关图。核心目标是回答：

```text
这个 symbolic callsite 实际可能调用谁？
候选 callee 是否真实存在？
这条边在语法、类型、上下文上是否可行？
```

最小必要图信息：

| 图 / 信息 | 来源 | 作用 |
|---|---|---|
| Call Graph | `callgraph.json` | 定位 symbolic/dangling callee，获取 caller 和已有边 |
| AST/UAST Callsite 图 | UAST dump / parser / checker hook | 抽取调用形状、receiver、callee、args、literal |
| Function/Method Definition Index | UAST + CG resolved nodes | 提供真实候选 callee 集合 |
| Def-Use / Constant 图 | UAST assignment、identifier use、literal | 解析 `name = "foo"`、`key = "run"`、`f = handler` |
| Class/Type/Inheritance 图 | UAST class definition、constructor call、supers | 推断 receiver 类型和类方法集合 |
| Import/Module/Alias 图 | UAST import 节点、文件路径 | 解析 `module.func`、`from x import y` 的真实定义 |
| Argument Binding 图 | callsite args + function signature | 判断参数数量、keyword、`*args`、`**kwargs` 是否兼容 |

按动态模式扩展：

| 模式 | 重点证据 |
|---|---|
| `obj.method()` | receiver type + class method graph |
| `getattr(obj, name)()` | receiver type + `name` def-use/constant |
| `handlers[key]()` | dict/registry value graph + `key` def-use/constant |
| `f()` 变量函数 | variable-to-function def-use |
| `registry.register(k, f)` | registration/callback graph |
| decorator route | decorator graph + handler index |
| dynamic import | import string constant + module graph |

`source frontier` 和 `sink backward slice` 不是 CG 补边本身的硬需求，但用于让补边服务于漏洞链恢复：优先修 taint-relevant、sink-relevant 的断边。

## 5. Evidence Bundle

Evidence Bundle 是“尽可能完整”的多图诊断证据包。不同断点需要的证据子集不同，证据缺失本身也是诊断结果。

```json
{
  "breakpoint": {
    "id": "bp-001",
    "kind": "symbolic_callee",
    "caller": "Handler.dispatch",
    "symbolic_callee": "getattr(self, name)",
    "callsite": "method(req)",
    "location": "app.py:42"
  },
  "callsite_shape": {
    "kind": "getattr_call",
    "receiver": "self",
    "name_expr": "name",
    "args": ["req"]
  },
  "cg_evidence": {
    "incoming_edges": [],
    "nearby_resolved_nodes": []
  },
  "def_use_evidence": {
    "name": {
      "possible_values": ["do_exec"],
      "definitions": ["name = 'do_exec'"]
    }
  },
  "receiver_evidence": {
    "possible_types": ["Handler"],
    "class_methods": ["dispatch", "do_exec", "render"]
  },
  "module_evidence": {
    "imports": [],
    "aliases": []
  },
  "signature_evidence": {
    "actual_args": ["req"],
    "candidate_params": ["self", "req"],
    "compatible": true
  },
  "sink_relevance": {
    "candidate_contains_sink": false,
    "distance_to_sink_function": 2
  },
  "missing_evidence": [],
  "diagnosis": {
    "kind": "missing_call_edge",
    "repairability": "repairable",
    "confidence": "medium"
  }
}
```

证据分级：

```text
strong:
  CG + AST + def-use/type + signature + sink relevance 都支持

medium:
  CG + AST + def-use 或 type 支持，sink relevance 较弱

weak:
  只有名字相似或 lexical proximity

unrepairable:
  没有 resolved candidate，或只能靠 LLM 猜测
```

## 6. 证据文件与候选空间

规则层首先抽取证据文件，而不是直接产出最终候选边。证据文件描述：

```text
breakpoint 在哪里
callsite 形状是什么
receiver/name/key/signature 有哪些静态事实
项目中有哪些 resolved callee universe
哪些函数/方法在类型、模块、注册表上可能相关
哪些证据缺失或冲突
```

证据文件中可以包含“候选空间”，但这不是最终 candidate edge：

```json
{
  "breakpoint_id": "bp-001",
  "breakpoint": {
    "caller": "Handler.dispatch",
    "symbolic_callee": "getattr(self, name)",
    "callsite": "app.py:42:method(req)"
  },
  "callsite_shape": {
    "kind": "getattr_result_call",
    "receiver": "self",
    "name_expr": "name",
    "args": ["req"]
  },
  "evidence": {
    "name_values": ["do_exec"],
    "receiver_types": ["Handler"],
    "signature_observation": {
      "actual_arg_count": 1
    }
  },
  "callee_universe": [
    {
      "callee_id": "fn-001",
      "qualified_name": "Handler.do_exec",
      "location": "app.py:12",
      "params": ["self", "req"]
    },
    {
      "callee_id": "fn-002",
      "qualified_name": "Handler.render",
      "location": "app.py:18",
      "params": ["self", "req"]
    }
  ],
  "missing_evidence": [],
  "risk_evidence": {
    "dynamic_name": false,
    "receiver_type_ambiguous": false,
    "callee_universe_size": 2
  }
}
```

证据抽取规则示例：

| 动态调用模式 | 候选生成规则 |
|---|---|
| `getattr(obj, "foo")()` | 抽取 receiver 可能类型、字面量属性名、类方法集合 |
| `getattr(obj, name)()` | 抽取 name 的 def-use/constant、receiver 类型、类方法集合 |
| `obj.method()` symbolic | 抽取 receiver type、method name、类方法集合 |
| `handlers[key]()` | 抽取 dict/registry 内容、key def-use/constant |
| `f()` | 抽取变量到函数值的 def-use |
| decorator route | 抽取 decorator 参数、handler index |
| callback/register | 抽取注册点 key/value 函数映射 |

## 7. easy / middle / hard 分层与候选生成策略

证据文件生成后，先做 easy / middle / hard 分层。分层决定候选边由规则生成、规则生成后让 LLM rerank，还是由 LLM 在候选空间中提出/排序。

```text
easy:
  证据足以让规则唯一确定候选边。

middle:
  证据能限定一个小候选空间，但需要排序或消歧。

hard:
  证据不足以规则化生成确定候选，需要 LLM 结合证据在候选空间内提出或排序候选。
```

### 7.1 easy

判定条件：

```text
候选空间经过规则过滤后只剩 1 个 callee
receiver/name/key/signature 至少两类独立证据支持
无明显反证
CG explosion risk low
```

处理：

```text
规则生成 candidate edge
规则直接 materialize CCEC
不调用 LLM
仍然进入 validator
```

### 7.2 middle

判定条件：

```text
候选空间较小，例如 2~5 个
证据基本充分，但 top-1/top-2 分差不足
或某一类证据缺失
```

处理：

```text
方案 A：规则生成 ranked candidate edges，validator 按 top-K 逐一验证
方案 B：LLM 只做 rerank/explain，再由 materializer 生成 CCEC
```

### 7.3 hard

判定条件：

```text
候选空间较大
receiver 类型不确定
name/key 来自复杂表达式或跨函数传播
callback / dispatcher / dynamic import 跨模块
证据冲突或缺口较多
```

处理：

```text
LLM 基于 Evidence Bundle + callee_universe 提出候选边或排序候选边
LLM 不允许生成 callee_universe 外的函数
LLM 不直接输出 accepted，只输出 candidate edge proposal / rank / reason / risk
结构化 materializer 再把候选边转成 CCEC
```

候选边对象在 easy/middle/hard 策略之后产生：

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
      "guards": ["receiver_type", "name_value", "callee_exists", "signature_compatible"],
      "evidence": {
        "def_use": ["name def-use resolves to 'do_exec'"],
        "receiver": ["self has possible type Handler"],
        "callee": ["Handler defines do_exec(self, req)"]
      },
      "risk": {"ambiguity": "low", "cg_explosion": "low"}
    }
  ]
}
```

## 8. Top-K 排序

每个候选边计算分数：

```text
Score(edge) =
  w1 * name_match
+ w2 * receiver_type_match
+ w3 * argument_compatibility
+ w4 * def_use_strength
+ w5 * import_module_consistency
+ w6 * lexical_proximity
+ w7 * sink_relevance
- w8 * ambiguity_penalty
- w9 * explosion_penalty
```

排序分两层：

```text
breakpoint priority
  x
candidate edge score
```

建议策略：

```text
每轮选择 top-M 个 frontier breakpoint
每个 breakpoint 只验证 top-K 条候选边
只接受能让 frontier 前进或到达 sink-relevant 区域的边
```

### 8.1 分层与候选生成输出

候选阶段应输出分层结果，供后续统计和消融：

```json
{
  "breakpoint_id": "bp-001",
  "difficulty": "middle",
  "llm_policy": "rerank_only",
  "candidate_count": 3,
  "top1_score": 0.82,
  "top2_score": 0.79,
  "evidence_strength": "medium",
  "risk": {
    "ambiguity": "medium",
    "cg_explosion": "low"
  }
}
```

分层是论文评估的重要指标：

```text
easy 占比：规则修复能力
middle 占比：规则 + 验证器能否替代 LLM
hard 占比：真正需要 LLM 的断点规模
LLM accepted/refuted/inconclusive 比例：控幻觉指标
```

## 9. CCEC 生成

按照 `repair.md` 的顺序，CCEC 位于 easy / middle / hard 分类之后：

```text
Evidence Bundle
  -> generate_candidate_call_edges
  -> rank_call_edges / Top-K
  -> classify_easy_middle_hard
  -> build CCEC
  -> validator
```

不同分层对应不同 CCEC 生成策略：

| 分层 | CCEC 生成策略 |
|---|---|
| easy | `build_ccec_from_rule(ranked.top1, evidence_bundle)` |
| middle | 规则按 top-K 逐一尝试，或 LLM rerank 后对 top candidate 生成 CCEC |
| hard | LLM 在候选集合内消歧/解释，随后由规则 materializer 生成 CCEC |

LLM 的边界：

```text
LLM 可以排序、解释、指出风险、建议 guard。
LLM 不得生成候选集合外的新 callee。
LLM 不直接决定 accepted。
最终 CCEC 必须由结构化 materializer 生成，并交给 validator。
```

候选边契约 CCEC 只描述“调用边本体 + 条件 + 证据 + 期望”，不直接包含 must-link / must-not-link / must-kill 的具体样例。

参考 LAPIS CTPC 的分层：

```text
ctpc.v2.json              -> 候选数据流传播契约
validation/must-flow      -> 验证器生成的正例样例
validation/must-not-flow  -> 验证器生成的反例样例
validation/must-kill      -> 验证器生成的 kill 样例
validation_report.json    -> 验证结果
```

调用边修复对应为：

```text
ccec.v1.json              -> 候选调用边契约
validation/must-link      -> 验证器生成的正例样例
validation/must-not-link  -> 验证器生成的反例样例
validation/must-kill      -> 验证器生成的 kill 样例
validation_report.json    -> 验证结果
```

CCEC 示例：

```json
{
  "schema_version": "ccec.v1",
  "contract_name": "getattr_name_to_method_call",
  "gap_type": ["missing_call_edge"],
  "applies_to": {
    "language": "python",
    "breakpoint_kind": "symbolic_callee"
  },
  "breakpoint": {
    "breakpoint_id": "bp-001",
    "caller": "Handler.dispatch",
    "symbolic_callee": "getattr(self, name)",
    "callsite": "app.py:42:method(req)"
  },
  "call_edge_contracts": [
    {
      "edge_id": "getattr_name_to_handler_method",
      "source_candidate_id": "edge-001",
      "event": "function_call",
      "pattern": {
        "kind": "getattr_result_call",
        "receiver": "$receiver",
        "name_expr": "$name",
        "callsite": "$callsite"
      },
      "from": {
        "callsite": "$callsite"
      },
      "to": {
        "callee": "$receiver_type.$name"
      },
      "guards": [
        {
          "kind": "receiver_type_resolved",
          "receiver": "$receiver"
        },
        {
          "kind": "name_value_resolved",
          "expr": "$name"
        },
        {
          "kind": "callee_exists"
        },
        {
          "kind": "signature_compatible"
        }
      ],
      "binding": {
        "receiver": {
          "actual": "$receiver",
          "formal": "self"
        },
        "actual_to_formal": [
          {
            "actual": "$arg0",
            "formal": "$param1"
          }
        ]
      },
      "evidence": {
        "def_use": ["name def-use resolves to 'do_exec'"],
        "receiver": ["self has possible type Handler"],
        "callee": ["Handler defines do_exec(self, req)"],
        "signature": ["callsite has one actual argument and receiver is bound"]
      },
      "risk": {
        "ambiguity": "low",
        "cg_explosion": "low"
      }
    }
  ],
  "validation_expectations": {
    "must_link": "edge_exists",
    "must_not_link": "edge_absent",
    "must_kill": "edge_absent"
  }
}
```

## 10. CCEC 验证设计

### 10.1 分层原则

CCEC 本体和验证样例分开保存：

```text
ccec.v1.json:
  候选调用边契约。包含 pattern、from、to、guards、binding、evidence、risk、
  validation_expectations。

validation/must-link:
  验证器根据 CCEC + Evidence Bundle 生成的正例样例。

validation/must-not-link:
  验证器根据 CCEC + Evidence Bundle 生成的反例样例。

validation/must-kill:
  验证器根据 CCEC + Evidence Bundle 生成的 guard 破坏样例。

validation_report.json:
  验证器运行后的裁决结果。包含 sample_results、edge_coverage、feedback。
```

这和 LAPIS 数据流 CTPC 的实现保持一致：候选契约不直接携带三分样例，三分样例和验证结果属于 validator 产物。

### 10.2 must-link 样例

满足 guard 时，补边应该出现。这个样例由验证器生成，不写进 CCEC 本体。

```text
name == "do_exec"
receiver type == Handler
callsite method(req)
=> callsite -> Handler.do_exec
```

通过条件：

```text
callee 真实存在
参数兼容
guard 有静态证据支持
补边后 source frontier 前进
```

### 10.3 must-not-link 样例

相似调用形状下，不应该错误连到该 callee。

```text
name == "render"
method = getattr(self, name)
method(req)
=> 不允许 callsite -> Handler.do_exec
```

它防止契约过宽，例如：

```text
getattr(self, anything) -> Handler.do_exec
```

### 10.4 must-kill 样例

破坏 guard 后，该补边必须失效。

```text
receiver type == OtherHandler
name == "do_exec"
=> 不允许 callsite -> Handler.do_exec
```

must-kill 用来验证 guard 是必要条件，而不是装饰性解释。它也是验证器产物，不写进 CCEC 本体。

### 10.5 validation_report.json

验证结果单独输出：

```json
{
  "ccec": "ccec.v1.json",
  "validation_dir": "validation",
  "status": "accepted",
  "sample_results": [
    {
      "sample": "must-link",
      "expected": "edge_exists",
      "predicted": "edge_exists",
      "passed": true,
      "features": {
        "receiver_type_hit": true,
        "name_value_hit": true,
        "callee_exists": true,
        "signature_compatible": true
      },
      "evidence": [
        {
          "kind": "name_value",
          "expr": "name = 'do_exec'"
        },
        {
          "kind": "edge_observed_in_repaired_graph",
          "edge": "app.py:42:method(req) -> app.py:12:Handler.do_exec"
        }
      ]
    },
    {
      "sample": "must-not-link",
      "expected": "edge_absent",
      "predicted": "edge_absent",
      "passed": true
    },
    {
      "sample": "must-kill",
      "expected": "edge_absent",
      "predicted": "edge_absent",
      "passed": true
    }
  ],
  "edge_coverage": [
    {
      "edge_id": "getattr_name_to_handler_method",
      "covered": true,
      "reason": "must-link sample exercises receiver/name/signature guards"
    }
  ],
  "graph_progress": {
    "frontier_advanced": true,
    "new_resolved_nodes": ["Handler.do_exec"],
    "sink_distance_delta": -1
  },
  "feedback": []
}
```

### 10.6 判定规则

```text
accepted:
  must-link 通过
  must-not-link 通过
  must-kill 通过
  CCEC edge coverage 通过
  repaired graph 中 frontier 前进或更靠近 sink

rejected:
  callee 不存在
  参数明显不兼容
  guard 被反证
  must-not-link/must-kill 失败
  补边导致 CG 爆炸

inconclusive:
  结构上可能
  但 def-use/type/import/sink evidence 不足
  或 top-1/top-2 分差太小
```

验证分层：

```text
V1 Structural verification:
  callee exists, loc exists, signature compatible

V2 Guard verification:
  name/key/receiver/import/registration evidence supports edge

V3 Graph-progress verification:
  repaired CG makes frontier advance or reaches new resolved function

V4 Taint-goal verification:
  repaired path gets closer to sink or reaches sink
```

接受条件：

```text
accepted = V1 + V2 + validation samples pass + (V3 or V4)
```

## 11. 回灌和复验

优先在外部 repaired graph 上验证：

```text
baseline CG + verified CCEC edges -> repaired CG
```

验证目标：

```text
source frontier 是否前进
是否进入新的 resolved function
是否进入 sink-relevant function
source-sink 是否可达
```

如果某些契约可以表达为 YASA 现有 rule/config，则回灌 YASA 重跑自证。不能表达时，不修改 YASA 引擎，只保留外部 repaired graph 结果。

## 12. 停止条件

必须有停止条件，防止无限补边。

```text
成功停止:
  source 到 sink 在 repaired graph 上连通，并通过 taint/path 验证

无候选停止:
  当前 frontier breakpoint 没有任何 resolved callee candidate

无进展停止:
  验证 top-K 后，frontier 没有前进

证据不足停止:
  只有名字相似，没有 def-use/type/import/registration 等独立证据

低置信停止:
  top-1 低于阈值，或 top-1/top-2 分差太小且无法验证

爆炸风险停止:
  候选过多，或补边后 CG 扩张超过阈值

预算停止:
  每个 source-sink pair 最多 N 轮，每个断点最多验证 top-K

重复断点停止:
  连续两轮卡在同一个 frontier，且没有 accepted edge
```

## 13. Repairable 判定

不是所有 source-sink 都能补全。只有满足以下条件才进入 repair：

```text
source 已命中
sink 已命中
source frontier 存在 symbolic/dangling callee
存在至少一个真实 resolved callee candidate
至少两类独立静态证据支持候选边
没有强反证
```

否则标记为：

```text
unrepairable_under_observed_graphs
```

含义不是证明漏洞不存在，而是在当前 YASA 产物和已抽取静态图信息下，不能可靠补全。此时不允许 LLM 凭空生成边。

## 14. 推荐 MVP

第一版只实现：

```text
1. 读取 YASA callgraph.json
2. 识别 resolved / symbolic / dangling 节点
3. 从 UAST 抽 callsite、assignment、literal、class/method、import
4. 构建 function/method definition index
5. 构建轻量 def-use + constant propagation
6. 支持 obj.method、getattr(obj, name)、handlers[key] 三类候选生成
7. Top-K 排序
8. easy/middle/hard 分层，easy 不调用 LLM，middle 可选 rerank，hard 调用 LLM 消歧
9. 输出 ccec.v1.json 候选调用边契约
10. 生成 validation/must-link、must-not-link、must-kill
11. 输出 validation_report.json
12. 输出 repaired graph 和 repair report
```

暂不改 YASA 引擎。只有当需要工程化复验时，再考虑增加“读取 verified CCEC 并注入分析”的可选适配层。

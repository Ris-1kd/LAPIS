# RPyC LLM 自动生成 CCEC 闭环实验报告

## 1. 实验目标

本实验验证：在不向 LLM 泄露 benchmark 隐藏答案的前提下，是否可以让 LLM API 基于 oracle-blind 静态分析证据，自动生成 CCEC 缺失调用边契约，并使原本 `no_finding` 的 CVE 样例变为 `finding`。

目标 CVE 样例为：

- Case：`cve-2024-27758-rpyc`
- 项目：RPyC
- 漏洞类型：unsafe deserialization
- 修复分支：CCEC / 缺失调用边
- 最终 sink：`pickle.loads`
- 唯一最终 sink 规则：`LAPIS/LAPIS-Experiments/cases/connectivity_gap/cve-2024-27758-rpyc/rules/final-sink-only.json`

规则审计结果：

| 项 | 值 |
| --- | --- |
| sink 规则数量 | `1` |
| 唯一 `fsig` | `pickle.loads` |
| sink 参数 | `args[0]` |
| 规则语义 | 只接受到达 `pickle.loads(...)` 的反序列化链路 |

## 2. 对照组：未补充 CCEC 边的 baseline

本报告只保留当前 LLM API 闭环实验使用的单最终 sink baseline：规则中只包含最终 sink `pickle.loads`。

报告文件：

- `LAPIS/LAPIS-Experiments/reports/rpyc-llm-auto-ccec/runs/baseline-final-sink/baseline-final-sink_full_cve_report.json`

关键结果：

| 指标 | 值 |
| --- | --- |
| `result` | `no_finding` |
| `status` | `not_reported` |
| `findingCount` | `0` |
| `markedSourceCount` | `1` |
| `matchedSinkCount` | `0` |
| `entryPointCount` | `1` |
| `fileCount` | `30` |
| `lineCount` | `6497` |
| `totalTimeMs` | `8760` |

解释：

单最终 sink baseline 下，YASA 无法从入口函数连到 `pickle.loads`，结果是 `no_finding`。这说明需要补充的是调用图连接，而不是增加更多 sink 规则。

这里 `matchedSinkCount=0` 不表示规则中没有 sink，而是表示原始调用图没有物理到达 `pickle.loads` callsite。规则文件本身始终只有 `pickle.loads` 一个最终 sink。

## 3. Oracle-blind 约束

本实验的 CCEC 生成阶段没有把隐藏答案或 benchmark oracle 传给 LLM。

Prompt 中显式隐藏或排除：

- manual source/sink annotations
- manual breakpoint annotations
- manual repair-order annotations
- manual source-to-sink chain summaries
- benchmark hidden oracle 中的最终链路

LLM 可见的信息来自 evidence builder 自动提取的局部静态证据，以及规则文件中的 sink fsig。也就是说，LLM 不是直接读取标准答案，而是在静态证据约束下生成 CCEC 契约。

## 4. 静态证据提取流程

修改后的 evidence builder 会自动扫描数据集 AST，寻找动态方法调用模式：

1. 在本地代码中发现动态属性获取：

   `poc/poc_cve_2024_27758_rpyc.py:20`

   ```python
   array_callback = getattr(obj, "__array__")
   ```

2. 发现真正的边界调用点：

   `poc/poc_cve_2024_27758_rpyc.py:21`

   ```python
   return array_callback()
   ```

3. 发现 factory 注册了同名动态方法：

   `poc/poc_cve_2024_27758_rpyc.py:26`

   ```python
   class_factory(("remote.module.EvilArray", 1, 0), [("__array__", "array protocol")])
   ```

4. 在库代码中发现 `_make_method` 对同名方法的 materialization 分支：

   `rpyc/core/netref.py:251`

   ```python
   elif name == "__array__":
   ```

5. 在生成的 `__array__` 方法内部发现最终 sink：

   `rpyc/core/netref.py:255`

   ```python
   return pickle.loads(syncreq(self, consts.HANDLE_PICKLE, -1))
   ```

证据构建器据此生成 `suggested_virtual_edges`，并要求 LLM 只能基于这些证据生成 CCEC，不能再选择无关 dangling edge。

## 5. LLM 自动生成的 CCEC 契约

LLM 输出文件：

- `LAPIS/LAPIS-Experiments/reports/rpyc-llm-auto-ccec/ccec/candidate_edges.llm.json`

结构验证报告：

- `LAPIS/LAPIS-Experiments/reports/rpyc-llm-auto-ccec/ccec/llm_validation_report.json`

结构验证结果：

| 指标 | 值 |
| --- | --- |
| `status` | `accepted` |
| CCEC 边数 | `2` |

LLM 生成的两条 CCEC 边为：

### 5.1 边 1：动态 callback 到 materialized factory method

```text
array_callback()
  -> rpyc.core.netref._make_method.<generated __array__>
```

关键字段：

- `callee_kind`: `materialized_factory_method`
- `boundary_callsite`: `array_callback()`
- `confidence`: `0.91`

作用：

这条边补齐了 YASA 原始调用图无法解析的动态调用边界：`array_callback()` 实际上来自 `getattr(obj, "__array__")`，而该 `__array__` 是由 `class_factory/_make_method` 动态生成的。

### 5.2 边 2：generated `__array__` 到最终 sink

```text
rpyc.core.netref._make_method.<generated __array__>
  -> pickle.loads
```

关键字段：

- `callee_kind`: `builtin_sink`
- `callsite`: `pickle.loads(syncreq(self, consts.HANDLE_PICKLE, -1))`
- `confidence`: `0.94`

作用：

这条边把 materialized `__array__` 方法连接到最终反序列化 sink `pickle.loads`。

## 6. 补充 CCEC 后的实验结果

### 6.1 单最终 sink 规则 + LLM CCEC

报告文件：

- `LAPIS/LAPIS-Experiments/reports/rpyc-llm-auto-ccec/runs/llm-auto-final-sink/llm-auto-final-sink_full_cve_report.json`

关键结果：

| 指标 | 值 |
| --- | --- |
| `result` | `finding` |
| `status` | `reported` |
| `findingCount` | `1` |
| `markedSourceCount` | `1` |
| `matchedSinkCount` | `0` |
| `entryPointCount` | `1` |
| `fileCount` | `30` |
| `lineCount` | `6497` |
| `totalTimeMs` | `9211` |

说明：

`matchedSinkCount=0` 是正常现象，因为最终 sink 是通过 CCEC virtual boundary 触发的，不是 baseline callgraph 直接匹配到的具体 sink callsite。SARIF/输出中已经显示：

```text
SINK RULE: pickle.loads
SINK Attribute: LAPIS CCEC virtual sink: pickle.loads
Line 21: array_callback()
```

这说明在只有最终 sink `pickle.loads` 的严格规则下，LLM 生成的 CCEC 已经足以使样例从 `no_finding` 变为 `finding`。

本实验没有保留 `_make_method`、`array_callback` 或其他中间边界作为 sink 规则；这些只存在于 CCEC 契约和 trace 证据中，最终报告仍收敛到唯一语义 sink `pickle.loads`。

## 7. 前后对比

| 实验配置 | CCEC | `result` | `findingCount` | `markedSourceCount` | `matchedSinkCount` |
| --- | --- | --- | ---: | ---: | ---: |
| 单最终 sink baseline | 无 | `no_finding` | 0 | 1 | 0 |
| 单最终 sink + LLM CCEC | 有 | `finding` | 1 | 1 | 0 |

结论：

未补边时，source 已经被标记，但完整 CVE 链路无法形成；补充 LLM 自动生成的 CCEC 后，单最终 sink 规则成功报告唯一 finding。因此该 CCEC 契约确实补上了关键缺失调用边。

## 8. 完整 CVE 链路解释

补边后的完整链路可以描述为：

1. `cve_2024_27758_source()` 产生 payload。
2. driver 调用 `class_factory`，并传入 `("__array__", "array protocol")` 方法元数据。
3. `numpy_like_array_coercion` 执行：

   ```python
   array_callback = getattr(obj, "__array__")
   ```

4. 程序调用：

   ```python
   array_callback()
   ```

5. CCEC 将该动态 callback 边界补充为：

   ```text
   array_callback()
     -> rpyc.core.netref._make_method.<generated __array__>
   ```

6. generated `__array__` 内部到达：

   ```python
   pickle.loads(syncreq(self, consts.HANDLE_PICKLE, -1))
   ```

7. YASA 报告 `finding`。

## 9. 为什么之前 LLM 会失败

之前的 prompt/evidence 过弱，LLM 看到的是 baseline callgraph 中大量 dangling/callgraph 边，其中包括无关的：

```text
safe_import -> __import__
```

这条边虽然是一个可见的 dangling edge，但与本 CVE 的 `__array__ -> pickle.loads` 漏洞链路无关，因此补上它不会让实验从 `no_finding` 变成 `finding`。

当前修复后，prompt/evidence builder 直接暴露与本 CVE 相关的局部静态证据，并加入约束：

- 如果 `suggested_virtual_edges` 非空，LLM 必须输出这些 evidence-backed edges；
- 不允许选择无关 dangling callgraph edge；
- virtual/materialized 边必须保留 `boundary_callsite`，以便 YASA CCEC consumer 能在 `array_callback()` 处触发。

## 10. 最终结论

本例已经完成完整闭环：

```text
原始 baseline no_finding
  -> oracle-blind 静态 evidence builder 提取局部证据
  -> gpt-5 API 自动生成 CCEC 契约
  -> CCEC 结构验证 accepted
  -> YASA 使用 LLM CCEC 重跑原始 CVE 数据集
  -> result=finding
```

因此可以确认：

1. 该实验不是把已知答案直接喂给 LLM。
2. LLM 是根据静态分析证据生成 CCEC 契约。
3. 生成的 CCEC 契约可以补齐 RPyC 样例的关键缺失调用边。
4. 补边后可以实现完整 CVE 链路，并使原始 `no_finding` 样例变为 `finding`。

## 11. 验证完整性审计

从“能否打通 CVE 链路”的角度看，本实验已经完成闭环；从“完整 CCEC 验证协议”的角度看，目前也已经补齐三分验证，包括 must-link、must-not-link、must-kill 三类局部语义片段。

### 11.1 已完成的验证层级

| 验证项 | 状态 | 对应产物 |
| --- | --- | --- |
| easy / middle / hard 分类 | 已完成 | `ccec/plan.json` |
| CCEC 模式 | `hard` | `mode=hard` |
| LLM 是否需要参与 | 是 | `llm_required=true` |
| 结构验证 | 已完成 | `ccec/llm_validation_report.json` |
| 结构验证结果 | `accepted` | 两条边均通过字段/证据/置信度检查 |
| final-sink-only CVE 重跑 | 已完成 | `runs/llm-auto-final-sink/..._full_cve_report.json` |
| CCEC consumer 触发诊断 | 已完成 | `lapis-ccec-diagnostics.jsonl` |
| 三分验证 contract | 已完成 | `ccec/ccec_validation_contract.json` |
| 三分验证 contract 检查 | 已完成，`accepted` | `ccec/ccec_link_validation_report.json` |
| 局部语义片段物化 | 已完成 | `ccec-validation/` |
| 局部语义片段验证 | 已完成，`accepted` | `ccec/ccec_local_validation_report.json` |

分类结果来自 `ccec/plan.json`：

```json
{
  "mode": "hard",
  "llm_required": true,
  "generation_strategy": "baseline_static_evidence_then_llm_synthesis",
  "evidence_kind": "dynamic_getattr_factory_method_evidence"
}
```

因此该例不是 easy case。它属于 hard CCEC，因为目标边不是一个普通静态函数调用，而是：

```text
getattr("__array__")
  -> factory materialized method
  -> generated __array__
  -> pickle.loads
```

### 11.2 三分验证结果

`ccec/plan.json` 中规划的三分验证已经落地：

```text
llm_generate_must_link_must_not_link_must_kill
validate_ccec_link_contract
validate_ccec_local
```

注意：本例中 LLM 自动补充了两条 CCEC 边，因此三分验证不能只做一组样例，而必须对每条边分别验证 must-link、must-not-link、must-kill。当前实现已经改为逐边生成验证样例：

```text
2 条 CCEC 边 × 3 类验证 = 6 个局部语义片段
```

三分验证 contract：

- `LAPIS/LAPIS-Experiments/reports/rpyc-llm-auto-ccec/ccec/ccec_validation_contract.json`

contract 级验证报告：

- `LAPIS/LAPIS-Experiments/reports/rpyc-llm-auto-ccec/ccec/ccec_link_validation_report.json`

局部语义片段目录：

- `LAPIS/LAPIS-Experiments/reports/rpyc-llm-auto-ccec/ccec-validation/`

local sample 验证报告：

- `LAPIS/LAPIS-Experiments/reports/rpyc-llm-auto-ccec/ccec/ccec_local_validation_report.json`

结果：

| CCEC 边 | must-link | must-not-link | must-kill | edge coverage |
| --- | --- | --- | --- | --- |
| `array-boundary-to-generated-method` | passed | passed | passed | covered |
| `array-generated-method-to-pickle-loads` | passed | passed | passed | covered |

整体状态：

| 验证层级 | 期望 | 状态 |
| --- | --- | --- |
| contract / JSON 契约 | 每条边都有三分验证定义 | `accepted` |
| local sample / 局部语义片段 | 每条边都有可解析 Python 样例 | `accepted` |
| must-link | guard 满足时目标边必须出现 | passed |
| must-not-link | 无关模式不应误补边 | passed |
| must-kill | guard 被破坏时必须抑制边 | passed |

### 11.3 每条边的三分验证样例

三分验证的目标不是再次复现完整 CVE，而是用最小局部语义片段分别验证 CCEC contract 的三个性质：

1. 正例中 guard 满足时，必须补上目标边。
2. 相似但无关的代码形态中，不应误补目标边。
3. 关键 guard 被破坏时，应抑制目标边。

#### 边 1：`array-boundary-to-generated-method`

该边连接：

```text
array_callback()
  -> rpyc.core.netref._make_method.<generated __array__>
```

它补齐的是动态属性访问和 factory 生成方法之间的缺失调用边。

| 验证类型 | 样例文件 | 预期 | 设计 |
| --- | --- | --- | --- |
| must-link | `ccec-validation/must-link/array-boundary-to-generated-method-must-link/case.py` | `edge_present` | `("__array__", "array protocol")` + `array_callback()` |
| must-not-link | `ccec-validation/must-not-link/array-boundary-to-generated-method-must-not-link/case.py` | `edge_absent` | 把方法元数据换成 `("__str__", "string protocol")` |
| must-kill | `ccec-validation/must-kill/array-boundary-to-generated-method-must-kill/case.py` | `edge_suppressed` | 保留 `__array__`，但把边界调用点换成 `other_callback()` |

正例局部语义片段的核心形态：

```python
def sample():
    obj = class_factory([("__array__", "array protocol")])()
    array_callback = getattr(obj, "__array__")
    return array_callback()
```

该样例满足 CCEC 的两个关键 guard：方法元数据包含 `__array__`，边界调用点是 `array_callback()`。因此预期补边存在。

负例和 kill 例分别验证：

- 当方法元数据不是 `__array__` 时，不应把无关 callback 错补成 generated `__array__`。
- 当 callsite 不是 `array_callback()` 时，即使元数据包含 `__array__`，也应抑制该边。

#### 边 2：`array-generated-method-to-pickle-loads`

该边连接：

```text
rpyc.core.netref._make_method.<generated __array__>
  -> pickle.loads
```

它补齐的是 factory 生成的 `__array__` 方法内部到最终危险 sink `pickle.loads` 的缺失调用边。

| 验证类型 | 样例文件 | 预期 | 设计 |
| --- | --- | --- | --- |
| must-link | `ccec-validation/must-link/array-generated-method-to-pickle-loads-must-link/case.py` | `edge_present` | generated `__array__` 中调用 `pickle.loads(...)` |
| must-not-link | `ccec-validation/must-not-link/array-generated-method-to-pickle-loads-must-not-link/case.py` | `edge_absent` | 改为调用 `json.loads(...)`，不应指向 pickle sink |
| must-kill | `ccec-validation/must-kill/array-generated-method-to-pickle-loads-must-kill/case.py` | `edge_suppressed` | 保留 `pickle.loads(...)`，但函数名换成 `generated_str()` |

正例局部语义片段的核心形态：

```python
def generated_array(payload):
    return pickle.loads(payload)
```

该样例满足 CCEC 的核心 guard：当前生成方法语义是 `__array__`，并且内部 sink 是 `pickle.loads`。因此预期补边存在。

负例和 kill 例分别验证：

- 当内部调用是 `json.loads` 时，不能把它误判为 pickle sink。
- 当调用 `pickle.loads` 的生成方法不是 `__array__` 语义时，应抑制该边，避免把任意 generated method 都连到最终 sink。

### 11.4 三分验证结果汇总

contract 级报告：

- `LAPIS/LAPIS-Experiments/reports/rpyc-llm-auto-ccec/ccec/ccec_link_validation_report.json`

结果：

```text
status=accepted
must_link=True
must_not_link=True
must_kill=True
array-boundary-to-generated-method: covered=true
array-generated-method-to-pickle-loads: covered=true
```

local sample 级报告：

- `LAPIS/LAPIS-Experiments/reports/rpyc-llm-auto-ccec/ccec/ccec_local_validation_report.json`

结果：

```text
status=accepted
must-link=True
must-not-link=True
must-kill=True
```

local sample 报告中每一类都有两个 case：

| 类别 | case 数 | 状态 |
| --- | ---: | --- |
| must-link | 2 | all passed |
| must-not-link | 2 | all passed |
| must-kill | 2 | all passed |

这说明三分验证不仅生成了 JSON contract，也为两条 LLM CCEC 边分别生成了可解析的局部 Python 语义片段，并且每个片段都通过了 expected、syntax、target coverage、negative/kill condition 等检查。

### 11.5 当前结论的边界

当前可以严格确认：

1. LLM 生成的 CCEC 结构合法。
2. LLM 生成的两条 CCEC 均完成逐边三分验证。
3. LLM 生成的 CCEC 能在 final-sink-only 规则下把原始 CVE 样例从 `no_finding` 变成 `finding`。
4. 该样例的分类是 hard，不是 easy。
5. 已完成 contract 级验证、local sample 级验证、CVE 级闭环验证。

因此，更准确的表述是：

```text
当前实验已经完成 LLM 自动 CCEC 生成、hard 分类、结构验证、
逐边三分验证、局部语义片段验证、CVE 级闭环验证。
```

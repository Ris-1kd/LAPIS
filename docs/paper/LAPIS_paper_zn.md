# LAPIS: LLM-Assisted Propagation Inference for Static Taint Analysis

> **中文释义：面向静态污点分析的大模型辅助传播推断**  
> **文档定位：SANER 2027 投稿论文中文完整报告与写作底稿**  
> **当前状态：方法与原型已有闭环证据；大规模数据集、消融、多模型和真实项目实验尚待完成。本文用 `TBD` 明示未完成结果，不以计划值冒充实验结论。**

---

## 0. 论文定位与审稿人摘要

### 0.1 一句话贡献

LAPIS 不让大语言模型直接判定漏洞，而是让其在静态证据约束下生成可执行、可验证的调用边与污点传播契约，从而修复静态污点分析中的欠传播并恢复缺失的 source-to-sink 路径。

### 0.2 研究边界

本文聚焦 **under-propagation（欠传播）**，即程序中存在真实的调用或值传播关系，但静态分析器未建模该关系，导致污点路径提前终止。本文不主张解决：

- source/sink 规则完全缺失；
- 所有形式的路径不可行性；
- 通用程序验证或动态漏洞利用确认；
- 依靠 LLM 直接阅读代码并输出漏洞标签。

### 0.3 当前可支持与不可支持的结论

当前仓库包含 6 个 Python CVE/对照案例：2 个 connectivity gap、1 个 propagation gap、2 个 mixed gap 和 1 个 no-gap control。已有闭环报告表明，5 个欠传播案例均可在契约注入后恢复报告，对照案例无需修复。这些结果只能支持“方法可行性”，不能支持统计意义上的普适有效性。计划中的约 100 个 CVE、多模型比较和 20–50 个真实项目均属于待完成评估。

### 0.4 最可能的审稿质疑

1. **新颖性不足**：契约是否只是 LLM 生成规则的重新命名？
2. **Oracle 泄漏**：是否利用 CVE 补丁、完整漏洞链或人工答案生成契约？
3. **验证循环论证**：用同一个分析器验证为同一个分析器生成的规则，是否只是在强行产生 finding？
4. **样本过少**：6 个案例不足以支撑广泛结论。
5. **比较不公平**：不同方法是否使用同样的 source/sink、程序版本和预算？
6. **精度风险**：补边与强制传播是否导致图爆炸或系统性误报？

论文必须围绕这些质疑提供设计和证据，而不是只描述系统流水线。

---

## 1. 拟投稿信息

- **目标会议**：SANER 2027 Research Track（最终页数、双盲、artifact 和生成式 AI 政策须以当届 CFP 为准）。
- **英文标题**：*LAPIS: LLM-Assisted Propagation Inference for Static Taint Analysis*
- **中文标题**：*LAPIS：面向静态污点分析的大模型辅助传播推断*
- **关键词**：Static Taint Analysis; Under-propagation; Large Language Models; Call Graph Repair; Taint Propagation Contracts; Vulnerability Detection
- **建议论文类型**：技术研究论文，而非工具演示论文。
- **建议核心叙事**：Evidence → Diagnose → Synthesize → Validate → Re-analyze。

### 1.1 备选标题

若实验最终更突出漏洞路径恢复，可用：

> **LAPIS: Evidence-Guided LLM Inference of Missing Propagation for Static Taint Analysis**

首选标题更短且严格展开 LAPIS；备选标题信息量更大，但缩写对应不够整齐。

---

## 2. 摘要（投稿版草稿）

静态污点分析通过追踪不可信输入到安全敏感操作的数据流来发现漏洞。然而，动态分派、回调、容器操作、字段映射和框架封装等语言与库语义经常未被分析器完整建模，使污点在到达真实汇点之前停止传播。已有方法通常依赖人工编写模型，扩展成本高；直接使用大语言模型检测漏洞则难以保证结果可执行、可复现且不受幻觉影响。

本文提出 LAPIS，一种面向静态污点分析欠传播问题的证据驱动修复框架。LAPIS 首先联合调用图、污点前沿、汇点反向依赖、局部程序结构和负向安全证据，筛选有证据支持的候选漏报并诊断断链类型。随后，它让 LLM 生成两类受限契约：用于恢复缺失调用关系的 Call-Edge Contract（CCEC），以及用于描述缺失访问路径和值传播语义的 Taint-Propagation Contract（CTPC）。候选契约必须通过结构检查以及 must-flow、must-not-flow 和 must-kill 三类局部验证，才会被注入分析器并触发重新分析。该设计将 LLM 限定为语义候选生成器，而将最终漏洞报告交由静态分析闭环决定。

我们计划在一个包含连接缺口、传播缺口、混合缺口及安全对照的真实 Python CVE 基准上评估 LAPIS，并与原始 YASA、非 LLM 启发式修复及若干 LLM 增强变体比较。评估将回答路径恢复效果、组件贡献、跨模型稳健性、成本以及真实项目适用性。当前 6 个案例的原型闭环已验证 CCEC/CTPC 可被分析器真实消费，并在 5 个欠传播案例中恢复报告，同时保持 1 个已报告对照案例不进入修复。完整论文只在大规模实验完成后填入总体 Recall、Precision、F1 和成本结论。

> **摘要定稿要求**：最终摘要控制在会议字数限制内；删除“计划”和“当前”措辞，换成最终数据；至少报告样本规模、相对提升、误报/精度和运行成本各一个量化结果。

---

## 3. 引言

### 3.1 背景与问题

静态污点分析通常将漏洞检测建模为从 source 到 sink 的可达性：

```text
source --P1--> v1 --P2--> ... --Pn--> sink
```

其中每个传播步骤由调用图、控制流图、数据流规则或库摘要支持。如果任意真实关系 `Pi` 未被建模，分析器看到的路径便会断裂：

```text
source ---> frontier    missing relation    sink
                         ─────── × ───────>
```

欠传播在动态语言中尤其突出。反射与动态分派会遗漏调用边；字典键、生成器、闭包、字符串格式化和框架回调会遗漏值传播。结果并非 source 或 sink 不存在，而是两者之间缺少分析器可执行的语义连接。

### 3.2 现有方案的不足

人工建模库摘要或传播规则准确但昂贵，并且难以及时覆盖快速演化的生态。保守地补充所有可能调用边会放大调用图并引入误报。LLM 能理解局部语义，却可能虚构 callee、忽略 sanitizer 或生成无法由分析器消费的自然语言解释。因此关键问题不是“LLM 能否发现漏洞”，而是：

> 能否把 LLM 的语义能力限制在一个由静态证据驱动、由机器可执行契约承载、由正反例验证约束的修复闭环中？

### 3.3 三项研究挑战

**C1：诊断。** `no finding` 既可能是真漏报，也可能是安全阻断、不可达路径或无关 source/sink。系统必须先判断是否值得修复，并定位断链属于调用连接、数据传播还是二者兼有。

**C2：表达。** 缺失语义必须以足够精确、可检查且可被现有分析器执行的形式表达，而不是自由文本或无界规则。

**C3：可信性。** 候选契约不能只证明“可以制造一条漏洞路径”；它还必须在相似但安全的输入上不传播，并在 sanitizer、guard 或安全覆盖存在时停止传播。

### 3.4 LAPIS 概览

LAPIS 采用五阶段闭环：

```text
Program + baseline artifacts
          |
          v
  (1) Evidence Gate ------> true negative / safe-killed / infeasible / deferred
          |
          v
  (2) Gap Diagnosis ------> connectivity / propagation / mixed
          |
          v
  (3) Contract Synthesis -> CCEC and/or CTPC
          |
          v
  (4) Local Validation ---> reject / revise / accept
          |
          v
  (5) Contract Injection + Static Re-analysis
```

对 mixed case，LAPIS 强制采用 CCEC → 重分析 → 再诊断 → CTPC 的阶段顺序。原因是调用图未恢复时，过早推断传播契约会缺少 callee 内部证据并提高误修概率。

### 3.5 贡献声明（建议最终版本）

本文作出以下贡献：

1. **问题刻画与证据化诊断。** 系统化定义静态污点分析的三类欠传播缺口，并提出融合端点、前沿、反向依赖、调用和负向证据的 gate-and-diagnose 流程。
2. **双契约修复抽象。** 提出 CCEC 与 CTPC，将调用连接修复和访问路径/值传播修复统一为可执行、可审计、可撤销的分析契约。
3. **验证驱动的 LLM 集成。** 设计结构检查与 must-flow/must-not-flow/must-kill 局部验证，使 LLM 只生成候选语义，避免将其输出直接等同于漏洞结论。
4. **可复现实证研究。** 构建带隐藏 oracle 的真实 CVE 欠传播基准，比较基线、消融和多模型配置，并发布案例元数据、契约、验证样例与重分析产物。此项贡献须在最终实验和 artifact 整理完成后才能保留。

---

## 4. 背景、定义与动机示例

### 4.1 静态污点分析模型

令程序的分析图为 `G = (V, E_c ∪ E_d)`，其中 `E_c` 为调用边，`E_d` 为数据/污点传播边；source 集合为 `S`，sink 集合为 `K`。若存在路径 `s ↝ k`（`s ∈ S, k ∈ K`），且路径未被合法 kill 语义阻断，则分析器报告 finding。

对于真实程序语义图 `G*`，静态分析图通常只是近似。本文关注存在 `e ∈ E(G*)` 但 `e ∉ E(G)`，并因此令真实 source-to-sink 路径在 `G` 中不可达的情形。

### 4.2 欠传播分类

| 类型 | 缺失关系 | 常见语言结构 | 修复契约 |
|---|---|---|---|
| Connectivity gap | `E_c` 中缺少真实调用边 | 动态分派、函数重绑定、callback、registry、reflection | CCEC |
| Propagation gap | `E_d` 中缺少真实值/访问路径传播 | container、field、closure、generator、formatting | CTPC |
| Mixed gap | `E_c` 与 `E_d` 均缺失 | callback 后继续经容器或字段传播 | 先 CCEC，重分析后 CTPC |

分类是对“当前分析状态”的诊断，不是项目的永久标签。一个初始 connectivity gap 在补边后可能暴露第二个 propagation gap，此时才被确认为 mixed gap。

### 4.3 运行示例：PyMySQL 传播缺口

以 CVE-2024-36039 的最小驱动为例，不可信字典键进入查询参数，经 `dict.items()`、字典推导和 `%` 格式化后到达查询执行逻辑。baseline 能识别 source 与 sink，也能到达相关调用上下文，但污点在字典键和格式化语义处停止。

```text
tainted key
  -> args[key]
  -> for key, value in args.items()
  -> escaped_args[key]
  -> query % escaped_args
  -> _query(query)
```

该案例不需要凭空补调用边，而需要一个明确描述 `args.**keys` 如何传播到格式化结果的 CTPC。验证还必须包含：普通值不应被无条件标污，以及参数化/安全构造存在时传播应被 kill。

### 4.4 为什么使用契约

契约位于自由文本解释和分析器源代码补丁之间：

- 比自然语言更可执行、可复现；
- 比修改分析器核心更局部、可撤销；
- 可记录证据、guard、作用域和置信度；
- 可在注入完整项目之前进行隔离验证；
- 便于比较不同 LLM 对相同 schema 的生成质量。

---

## 5. LAPIS 设计

### 5.1 设计原则

1. **Oracle-blind synthesis**：候选生成阶段不得读取 CVE patch、advisory 中的完整路径、人工断点或历史正确契约。
2. **Least repair**：只补足由局部证据支持的最小关系，不进行全局宽泛传播。
3. **Analyzer-in-the-loop**：候选必须由真实分析器消费并重扫；文本上“看起来正确”不算成功。
4. **Negative evidence first-class**：sanitizer、参数化查询、trusted overwrite 和不可达 guard 与正向证据同等重要。
5. **Traceable decision**：从证据、候选、验证到最终 finding 均保留机器可读产物。

### 5.2 输入与输出

输入包括：程序源码、source/sink 规则、baseline SARIF/trace、调用图、UAST/AST 和分析诊断。输出包括：gate 决策、缺口类型、候选/接受契约、局部验证结果、重扫 finding 与有序 source-to-sink trace。

### 5.3 Evidence Gate

Evidence Gate 防止将所有 `no finding` 当作漏报。证据包包含：

| 证据视角 | 内容 | 目的 |
|---|---|---|
| Endpoint | source/sink 命中及位置 | 确认路径端点存在 |
| Forward frontier | source 最远传播位置 | 定位可能断点 |
| Backward dependency | sink 参数依赖变量、字段、容器 | 从汇点反推连接需求 |
| Call context | caller/callee、receiver、symbolic target | 判断连接性缺口 |
| Local structure | assignment、return、closure、container、format | 判断传播缺口 |
| Negative evidence | sanitizer、safe API、guard、overwrite | 避免错误修复 |
| Explosion risk | 候选数、fan-out、作用域 | 控制图扩张 |

Gate 输出：`candidate_fn`、`true_negative`、`safe_killed`、`infeasible`、`deferred` 或 `already_reported`。只有 `candidate_fn` 进入修复。

建议在论文中给出 gate 评分或明确决策规则。如果当前实现是规则组合而非学习模型，应如实称为 evidence-based decision procedure，避免使用未经证明的“自动证明漏报”。

### 5.4 Gap Diagnosis

诊断器比较 source frontier、symbolic/dangling callee、已解析 callee universe 与 sink backward slice：

- frontier 停在未解析调用点且存在局部 target 证据 → connectivity gap；
- 调用上下文基本闭合但值在 field/container/format 等处停止 → propagation gap；
- 初始阶段只发现连接问题 → 先标 connectivity；补 CCEC 后仍存在传播断点 → mixed；
- 证据不足或候选爆炸风险高 → deferred。

### 5.5 CCEC：Call-Edge Contract

CCEC 表达受作用域和 guard 限制的调用关系。建议最小 schema：

```json
{
  "contract_id": "ccec-001",
  "callsite": {"file": "module.py", "line": 42, "expression": "handlers[key](req)"},
  "caller": "dispatch",
  "callee": "handle_request",
  "binding": {"actual_to_formal": {"req": "request"}},
  "guard": "key == 'request'",
  "scope": "module_or_class",
  "evidence_refs": ["receiver-type", "registry-write", "signature-match"]
}
```

CCEC 必须验证：callsite 与 callee 可定位、实参与形参兼容、guard 可解释、候选不超出允许作用域，以及边被调用图构建和后续 taint checker 实际消费。

候选策略可以按难度分层：唯一静态 target 直接生成；多个 target 由规则先产生 top-k 再让 LLM 排序；动态 factory/registry 场景允许 LLM 合成 virtual 或 materialized edge，但仍需证据引用。

### 5.6 CTPC：Taint-Propagation Contract

CTPC 描述局部值或访问路径之间的传播与 kill 条件。建议最小 schema：

```json
{
  "contract_id": "ctpc-001",
  "scope": {"function": "Cursor.execute", "file": "cursors.py"},
  "from": {"base": "args", "path": "**keys"},
  "to": {"base": "query", "path": "value"},
  "transform": "dict_items_comprehension_then_percent_format",
  "guard": "mapping_format_query",
  "kill": ["parameterized_query", "trusted_overwrite"],
  "evidence_refs": ["sink-backward-1", "local-def-use-3"]
}
```

CTPC 不应是“source 到 sink 的整条捷径”。它必须对应一个局部、可复用的缺失语义步骤，并限定函数、调用点、数据类型或访问路径范围。否则即使恢复了已知 CVE，也无法区分真正修复与 benchmark overfitting。

### 5.7 LLM 的受限职责

LLM 接收裁剪后的 evidence pack、候选 universe、schema 和禁止事项，输出严格 JSON。它可以做候选排序、guard 补全和局部传播抽象；不得输出最终漏洞标签，不得访问隐藏 oracle，不得修改 source/sink 规则。温度、seed（若后端支持）、模型版本、prompt hash、token 数和原始响应都应记录。

### 5.8 三分局部验证

每个契约需要隔离验证：

| 验证类型 | 期望 | 检查目标 |
|---|---|---|
| Must-flow | 应产生目标边或 finding | 契约确实补足预期局部语义 |
| Must-not-flow | 不应产生边或 finding | 相似名称、字段、receiver 不被过度泛化 |
| Must-kill | 存在 sanitizer/guard 时停止 | 安全阻断不被契约绕过 |

局部测试不能复制完整 CVE source-to-sink oracle。验证通过仅说明契约的局部行为符合要求，最终有效性仍由独立的全程序重扫和隐藏 oracle 评估决定。

### 5.9 注入与重分析

接受的契约经 LAPIS-Tool 真实消费。系统记录 materialized call edge、checker match、CTPC fact、ordered trace 和 finding。成功标准不是 finding 数增加，而是：

1. 契约在预定位置被消费；
2. 最终 trace 连续且与隐藏 oracle 的关键端点/步骤一致；
3. 安全对照和负向变体不产生新增误报；
4. 新增边和传播事实受作用域限制。

### 5.10 终止与失败处理

- gate 为非 `candidate_fn`：停止；
- 候选为空或证据不足：标记 deferred；
- 验证失败：拒绝或有限次数修订，禁止无限 self-refinement；
- CCEC 后已恢复 finding：停止，不生成 CTPC；
- CCEC 后仍有可证传播断点：生成 CTPC；
- 达到调用预算、候选上限或图扩张阈值：停止并报告 unresolved。

---

## 6. 实现

当前原型由 LAPIS-Core 编排、LAPIS-Tool 执行静态分析。核心流程已经支持 baseline 扫描、证据构造、gap 诊断、LLM 生成 CCEC/CTPC、三分验证、契约注入、复扫和有序 trace 输出。

论文实现章节应量化报告：

- 修改/新增代码行数与语言；
- 支持的 Python 语义和契约数量；
- LLM prompt/schema 版本；
- 每阶段超时与最大候选数；
- YASA/LAPIS-Tool、UAST SDK、Python 与模型的确切版本；
- 硬件、并发和缓存策略；
- 契约注入接口如何影响调用图与 taint checker。

不要只列 CLI 命令。正文应解释关键工程决策，完整命令放 artifact 附录。

---

## 7. 评估设计

### 7.1 研究问题

- **RQ1 Effectiveness**：LAPIS 能否恢复 baseline 遗漏的真实漏洞路径，同时保持可接受精度？
- **RQ2 Diagnosis and Contract Quality**：LAPIS 能否正确筛选候选漏报、分类缺口并生成正确契约？
- **RQ3 Component Contribution**：Evidence Gate、CCEC、CTPC 和三分验证各自贡献多大？
- **RQ4 Robustness and Efficiency**：结果对 LLM 后端和随机性是否稳健，时间与金钱成本如何？
- **RQ5 Real-world Utility**：在未参与构建的开源项目中，LAPIS 能否发现可人工确认的新风险路径？

将原稿的“多模型”与“成本”合并为 RQ4，并新增契约级质量 RQ2，可避免只用最终 finding 掩盖错误诊断或偶然成功。

### 7.2 数据集构建

目标 benchmark 应包含真实漏洞与安全/负向案例。每个 CVE 固定 vulnerable commit、语言/依赖版本、source/sink 规则、PoC/driver 和 patch-derived hidden oracle。纳入标准：

1. 漏洞由公开 advisory/patch 支持；
2. 在统一 baseline 下 source 和 sink 至少可分别定位；
3. baseline 漏报可归因于一个或多个欠传播关系；
4. 项目可在固定环境中复现；
5. 候选生成前移除 oracle 信息。

排除 source/sink 规则完全错误、构建不可复现或漏洞本质不适合污点分析的案例。两名标注者独立标注 gap 类型与关键路径，报告 Cohen's kappa；分歧由第三人仲裁。

当前 6 个案例仅为 feasibility set：

| 类别 | 案例 | baseline | 当前闭环状态 |
|---|---|---|---|
| Connectivity | CVE-2023-24816 / IPython | 0 finding | CCEC 后 reported |
| Connectivity | CVE-2024-27758 / RPyC | 0 finding | CCEC 后 reported |
| Propagation | CVE-2024-36039 / PyMySQL | 0 finding | CTPC 后 reported |
| Mixed | CVE-2026-24486 / python-multipart | 0 finding | CCEC+CTPC 后 reported |
| Mixed | CVE-2025-55156 / pyLoad | 0 finding | CCEC+CTPC 后 reported |
| Control | CVE-2023-4033 / MLflow | already reported | no repair |

最终规模不要预先写死为“100”。应在收集完成后报告筛选流程图：检索数 → 去重 → 可构建 → 适合 taint → baseline 漏报 → 最终纳入。

### 7.3 数据切分与防泄漏

- 开发集用于 prompt/schema 调试；测试集在冻结实现后一次性运行；
- 同一项目、同一漏洞族或同一库语义不得跨开发/测试泄漏；
- patch、advisory、CVE 描述和人工完整链只供最终 oracle 评估；
- 删除历史 candidate contract、repaired run 和带答案的文件；
- 保存每次运行的输入文件清单和 hash，以证明 oracle-blind；
- 若 prompt 曾针对某测试案例人工调整，该案例必须移回开发集。

### 7.4 比较方法

建议至少包含：

1. **YASA**：原始分析器；
2. **YASA + Conservative Edges/Propagation**：不使用 LLM 的宽松静态启发式，检验“多补边即可”的替代解释；
3. **YASA + Heuristic Candidates**：使用同一 evidence 和 schema，但仅规则排序/选择；
4. **LLM-direct**：同等代码上下文与 token 预算下直接判定漏洞，用于说明契约闭环价值；
5. **LAPIS w/o Validation**：候选直接注入；
6. **Full LAPIS**。

若无法复现 CodeQL/Semgrep 等工具的等价规则，不应把它们列为数值 baseline。可在 related work 中讨论，或明确报告规则工程差异。

### 7.5 指标定义

令 `TP` 为与 hidden oracle 一致的漏洞路径报告，`FP` 为无 oracle 支持且经人工确认不成立的报告，`FN` 为未恢复的已知漏洞：

```text
Recall    = TP / (TP + FN)
Precision = TP / (TP + FP)
F1        = 2 * Precision * Recall / (Precision + Recall)
```

还需报告：

- **Complete Path Recovery (CPR)**：恢复连续 source-to-sink trace 的案例比例；
- **Gate Precision/Recall**：gate 对 candidate FN 与安全/不可达案例的分类质量；
- **Gap Classification Accuracy/Macro-F1**；
- **Contract Exact/Semantic Accuracy**：与人工契约或局部行为 oracle 一致；
- **Validation Rejection Yield**：被验证拒绝且人工确认错误的候选比例；
- **Graph Expansion**：新增调用边/传播事实及相对图规模；
- **Runtime**：baseline、evidence、LLM、validation、re-scan 分阶段时间；
- **LLM Cost**：输入/输出 token、调用数、美元成本；
- **Stability**：多次运行成功率与契约差异。

Precision 的分母必须是独立分析单元（项目/路径/告警），不能混用“CVE 数”和“finding 数”。未知真实项目告警应单列 `unknown`，不得当作 TP 或 FP。

### 7.6 RQ1：总体有效性

在冻结测试集上比较各方法的 Recall、Precision、F1 和 CPR，按 gap 类型与 CWE 分层。对配对二元结果使用 McNemar 检验；报告 bootstrap 95% 置信区间和效应量。除总体表外，给出未恢复案例的失败分类。

| Method | Detected CVEs | Recall | Precision | F1 | CPR | ΔEdges | Time |
|---|---:|---:|---:|---:|---:|---:|---:|
| YASA | TBD | TBD | TBD | TBD | TBD | 0 | TBD |
| Conservative repair | TBD | TBD | TBD | TBD | TBD | TBD | TBD |
| Heuristic candidates | TBD | TBD | TBD | TBD | TBD | TBD | TBD |
| LLM-direct | TBD | TBD | TBD | TBD | N/A | N/A | TBD |
| LAPIS | TBD | TBD | TBD | TBD | TBD | TBD | TBD |

### 7.7 RQ2：诊断与契约质量

分别评估 gate、gap classifier、CCEC 和 CTPC，避免最终 finding 掩盖中间错误。

| Stage | Metric | Overall | Connectivity | Propagation | Mixed |
|---|---|---:|---:|---:|---:|
| Evidence Gate | Precision / Recall | TBD | TBD | TBD | TBD |
| Gap Diagnosis | Macro-F1 | TBD | TBD | TBD | TBD |
| CCEC | Semantic accuracy | TBD | TBD | N/A | TBD |
| CTPC | Semantic accuracy | TBD | N/A | TBD | TBD |
| Validation | Bad-contract rejection | TBD | TBD | TBD | TBD |

### 7.8 RQ3：消融实验

所有配置使用相同测试案例、模型、token 预算和随机重复次数。

| Configuration | Recall | Precision | F1 | CPR | FP | LLM Calls |
|---|---:|---:|---:|---:|---:|---:|
| Full LAPIS | TBD | TBD | TBD | TBD | TBD | TBD |
| w/o Evidence Gate/context | TBD | TBD | TBD | TBD | TBD | TBD |
| w/o staged diagnosis | TBD | TBD | TBD | TBD | TBD | TBD |
| w/o CCEC | TBD | TBD | TBD | TBD | TBD | TBD |
| w/o CTPC | TBD | TBD | TBD | TBD | TBD | TBD |
| w/o three-way validation | TBD | TBD | TBD | TBD | TBD | TBD |

`w/o CCEC` 主要应影响 connectivity/mixed；`w/o CTPC` 主要应影响 propagation/mixed。若所有类别同幅变化，应检查实现或数据标注。

### 7.9 RQ4：模型稳健性与效率

选择至少一个闭源强模型和两个可复现/不同能力档模型。记录模型的确切版本与访问日期，不只写 GPT/Gemini/DeepSeek。每个 case/model 至少重复 3–5 次；temperature 固定，并额外报告 temperature=0 仍可能存在的服务端非确定性。

| Model/version | Contract Acc. | Triple-pass | CPR | Median calls | Tokens | Cost | Time |
|---|---:|---:|---:|---:|---:|---:|---:|
| Model A | TBD | TBD | TBD | TBD | TBD | TBD | TBD |
| Model B | TBD | TBD | TBD | TBD | TBD | TBD | TBD |
| Model C | TBD | TBD | TBD | TBD | TBD | TBD | TBD |

成本计算应公布单价日期、缓存命中、失败重试和 validation token；只报告成功调用会低估实际成本。

### 7.10 RQ5：真实项目评估

从未参与开发的活跃 Python 项目中按预注册标准采样。先运行 baseline，再对 LAPIS 新增告警进行双人审查。分类为 confirmed vulnerability、valid risky flow、sanitized/safe、false positive、unknown。只有 confirmed 与明确有效的 risky flow 可按预先定义计入 precision；unknown 单列。

| Project | KLOC | Baseline | LAPIS | New | Confirmed | Risky | Safe/FP | Unknown | Time |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| TBD | TBD | TBD | TBD | TBD | TBD | TBD | TBD | TBD | TBD |

未经维护者确认的发现应称为“candidate finding”或“valid risky flow”，不得称为新 CVE。任何披露须遵循负责任披露流程。

### 7.11 误差分析

至少人工分析所有 FN、所有 FP，并随机抽样 TP。建议编码：

- evidence 缺失或 gate 错误；
- gap 类型误判；
- callee universe 不完整；
- LLM 选择/生成错误；
- schema/validator 漏检；
- analyzer 不消费契约；
- 多阶段语义超出 CCEC/CTPC；
- source/sink 或 path-feasibility 问题；
- 超时/预算耗尽。

误差分析应导出设计边界，而不是只展示成功案例。

---

## 8. 预期结果写作模板

在实验完成前，不写“显著提升”“高精度”或具体百分比。最终每个 RQ 采用“答案—证据—解释—限制”四句结构：

> **RQ1 Answer.** LAPIS 在 N 个测试 CVE 中恢复 X 个，相比 YASA 增加 Δ 个；Recall 从 A 提升至 B，Precision 为 C（95% CI：[...]）。提升主要来自 connectivity/mixed 类别，而 Z 个案例因……仍未恢复。该结果说明……，但不外推到……。

图表建议：

1. Figure 1：一个贯穿全文的真实动机案例；
2. Figure 2：LAPIS 总体架构；
3. Figure 3：CCEC→重扫→CTPC 的 mixed-case 时序；
4. Table 1：数据集与筛选流程；
5. Table 2：总体检测效果；
6. Table 3：阶段级准确性；
7. Table 4：消融；
8. Table 5：模型/成本；
9. Table 6：真实项目结果。

正文优先呈现关键结果，完整逐案例表、prompt、schema 和失败日志放 artifact/appendix。

---

## 9. 讨论

### 9.1 为什么不是让 LLM 直接检测漏洞

直接分类难以提供分析器可消费的中间语义，也难以区分稳定程序事实与模型猜测。LAPIS 把 LLM 输出降格为候选契约：静态证据限定问题空间，schema 限定表达，局部正反验证过滤错误，最终重分析产生 finding。这一定位既保留 LLM 的语义推断能力，也保留静态分析的可追踪性。

### 9.2 契约的可迁移性

需区分 case-specific 与 semantic-family contract。前者只在一个 callsite 生效，风险低但复用弱；后者可覆盖同类 API/容器语义，但必须通过更多负向案例。论文应报告契约作用域分布与跨项目复用实验，不能默认单案例契约自然泛化。

### 9.3 失败安全性

错误契约可能造成误报或图扩张。LAPIS 应默认拒绝无法定位、guard 为空、作用域过宽、负向验证失败或扩张超过阈值的契约。契约注入应可撤销，报告中明确标注 contract-derived edges/facts，使审计者能区分原生与增强语义。

### 9.4 适用范围

当前实现和案例均面向 Python/YASA，因此结论只适用于该生态。CCEC/CTPC 抽象可能迁移到 JavaScript、Java 等语言，但需要相应前端、访问路径模型和验证规则；在实证验证前只能作为未来工作。

---

## 10. 有效性威胁

### 10.1 内部有效性

- 工具实现缺陷可能被误认为方法效果；使用单元测试、契约消费日志和人工 trace 复核缓解。
- CVE 信息可能泄漏到 prompt；通过文件 allowlist、hash、冻结测试集和 oracle 访问审计缓解。
- 人工标注存在主观性；双人独立标注、仲裁和一致性系数缓解。
- 模型服务非确定；固定配置、多次运行并保存原始响应缓解。

### 10.2 构念有效性

- finding 不等于真实漏洞；使用 hidden oracle、完整路径和人工确认，不仅统计告警数。
- 局部验证通过不等于全程序正确；同时评估安全对照、FP 和图扩张。
- CVE recall 不能代表真实项目 precision；分别报告两个场景，不混合分母。

### 10.3 外部有效性

- Python、YASA 和所选 CWE 限制泛化；按项目、CWE、gap 类型分层报告。
- 公开 CVE 可能偏向易复现案例；公开筛选漏斗和排除原因。
- 选定 LLM 可能快速过时；公布模型版本、prompt/schema，并强调框架而非模型排名。

### 10.4 结论有效性

- 小样本容易夸大提升；报告置信区间、配对检验和效应量。
- 多次比较增加偶然显著性；预先指定主要指标并做适当校正。
- 未知告警误计为 TP 会抬高 precision；unknown 必须单列。

---

## 11. 相关工作组织

最终英文稿需要逐项查证并引用原始论文，禁止仅罗列工具名。建议分四组：

1. **静态污点分析与工业查询系统**：讨论 CodeQL、FlowDroid、Semgrep/YASA 等的图模型、摘要和扩展机制；
2. **调用图与动态语言语义恢复**：讨论 reflection、dynamic dispatch、callback 和 library modeling；
3. **污点规范/摘要自动推断**：讨论 specification mining、library summary inference、access-path modeling；
4. **LLM for program analysis/security**：讨论 LLM 生成 source/sink/specification、漏洞检测及静态分析增强。

Related Work 的核心差异句应是：

> 与直接使用 LLM 输出漏洞标签或生成全局规则的方法不同，LAPIS 以静态断链证据触发局部修复，将调用连接与值传播分别编码为可执行契约，并在完整项目注入前使用正向、负向和 kill 行为进行验证。

该差异必须由文献表证明。若已有工作同时具备 evidence-guided gap localization、contract synthesis 和 negative validation，则应缩小新颖性声明。

---

## 12. 结论（草稿）

本文提出 LAPIS，一种修复静态污点分析欠传播的 LLM 辅助框架。LAPIS 从 baseline 静态产物中定位有证据支持的断链，将缺失语义表达为调用边契约 CCEC 或污点传播契约 CTPC，并通过 must-flow、must-not-flow 和 must-kill 验证后注入分析器重新执行。其目标不是以 LLM 替代静态分析，而是建立一个受证据、schema 和执行验证约束的语义修复闭环。最终结论必须根据完整 benchmark、消融、多模型和真实项目实验填写，并明确 Python/YASA 范围与剩余失败模式。

---

## 13. Artifact 与可复现性清单

- [ ] 固定所有 benchmark commit、依赖和容器镜像；
- [ ] 发布纳入/排除标准与数据集筛选漏斗；
- [ ] 分离 development/test，审计 oracle 文件访问；
- [ ] 发布 source/sink rules、case metadata、prompt、JSON schema；
- [ ] 发布每次模型调用的版本、参数、token、hash 和去敏响应；
- [ ] 发布 CCEC/CTPC、三分局部测试与验证结果；
- [ ] 发布 baseline/repaired SARIF、trace 和契约消费日志；
- [ ] 提供一键重跑脚本、预期输出、超时与硬件说明；
- [ ] 表格由原始 JSON/CSV 自动生成，禁止手工复制结果；
- [ ] 对外发布前清除 API key、用户名、绝对路径和未披露漏洞信息；
- [ ] 按 SANER 2027 当届政策准备匿名仓库和 artifact appendix。

---

## 14. 完稿优先级与审稿门槛

### P0：投稿前必须完成

1. 扩充并冻结测试集；当前 5+1 案例只能作为 motivating/feasibility examples。
2. 建立安全负例和 patched-version 对照，才能可靠计算 precision。
3. 实施严格 oracle-blind 审计，排除 prompt 与历史产物泄漏。
4. 增加非 LLM 启发式修复 baseline，证明收益不只是“补更多边”。
5. 完成消融、多次运行、成本与显著性分析。
6. 对所有 TP/FP/FN 做 trace 级人工复核。

### P1：显著增强说服力

1. 增加跨项目契约复用实验；
2. 增加 graph expansion 和性能上界；
3. 真实项目双人审查与负责任披露；
4. 对比至少一种外部成熟分析器或解释不可比原因；
5. 发布高质量匿名 artifact。

### 可能导致拒稿的红线

- 用计划中的“100 CVE”写成已完成实验；
- 只报告 recall，不报告安全负例、precision 或图扩张；
- 用 CVE patch/完整链生成契约后再在同一 CVE 上评估；
- 把 CTPC 直接连接 source 与 sink，缺少局部语义解释；
- 只展示成功案例，没有失败与误报分析；
- 标题/摘要声称通用静态分析，但实验仅覆盖一个 Python 工具且不说明边界。

---

## 15. 建议论文结构与篇幅分配

| 章节 | 建议占比 | 核心任务 |
|---|---:|---|
| Abstract | 3% | 问题、方法、量化结果、结论 |
| 1 Introduction | 12% | 动机、挑战、贡献 |
| 2 Background & Motivation | 10% | 定义与贯穿示例 |
| 3 Approach | 28% | evidence、诊断、CCEC/CTPC、验证、重扫 |
| 4 Implementation | 7% | 可复现工程细节 |
| 5 Evaluation | 25% | RQ、数据、baseline、指标、结果 |
| 6 Discussion & Threats | 8% | 边界、失败、安全、有效性 |
| 7 Related Work | 5% | 文献定位与差异 |
| 8 Conclusion | 2% | 克制总结 |

最终英文稿应优先保障方法定义和评估可信性。CLI 示例、完整 schema、逐案例路径和大表移入附录/artifact。

---

## 16. 仓库证据索引

本文档中的当前状态可由以下材料交叉核验：

- `docs/methodology/overall-repair-workflow.md`：整体闭环与实现状态；
- `docs/datasets/cve-dataset-case-matrix.md`：6 个当前案例及闭环结论；
- `docs/experiment/LAPIS_Experiment_Design.md`：原始实验规划；
- `paper-experiments/tables/`：主表模板，当前均明确为 TBD；
- `LAPIS-Experiments/reports/`：各案例 baseline、契约、验证与复扫产物；
- `LAPIS-Core/src/lapis/`：证据、诊断、生成、验证与端到端编排实现；
- `LAPIS-Tool/src/checker/taint/python/`：CCEC/CTPC 消费实现。

> 写作原则：代码和产物支持到哪里，论文结论就写到哪里；其余内容明确标为研究计划或待验证假设。

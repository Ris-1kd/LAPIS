# LAPIS: 实验方案设计

## 1. 实验总体目标

LAPIS 面向静态污点分析中的 under-propagation 问题，提出基于大模型的污点传播契约增强框架。

核心思想：

1. 利用静态分析证据定位污点传播缺失位置；
2. 利用 LLM 生成调用边契约 CCEC（Call-Edge Contract）；
3. 利用 LLM 生成传播契约 CTPC（Taint Propagation Contract）；
4. 利用 must-flow / must-not-flow / must-kill 三分验证机制过滤错误契约；
5. 将验证后的契约注入静态分析器，恢复完整 source-to-sink 路径。

实验需要回答四个核心问题：

- RQ1：LAPIS 是否能够有效恢复真实漏洞检测能力？
- RQ2：LAPIS 的核心组件是否真正贡献于性能提升？
- RQ3：不同 LLM 后端是否影响 LAPIS 性能，框架是否具有模型鲁棒性？
- RQ4：LAPIS 是否能够在真实世界项目中发现新的安全问题？

---

# 2. Research Questions

# RQ1: Effectiveness on Known Vulnerabilities

## Research Question

**RQ1: How effectively can LAPIS recover vulnerability paths missed by baseline static taint analysis?**

## 研究目标

验证：

- LAPIS 是否提升漏洞检测召回率；
- LAPIS 是否恢复 YASA 漏报漏洞；
- LAPIS 是否能够恢复完整 source-to-sink 污点传播链。

---

## 数据集

### LAPIS-CVE Benchmark

目标：

约 100 个真实 CVE。

来源：

- CVE Database；
- GitHub Security Advisory；

数据分类：


| Category         | Number |
| ---------------- | ------ |
| Connectivity Gap | 30     |
| Propagation Gap  | 30     |
| Mixed Gap        | 20     |
| Safe Case        | 10     |
| Total            | 100    |


---

## Baseline

### YASA

原始静态污点分析工具。

### Full LAPIS

完整流程：

```
YASA
 ↓
Evidence Extraction
 ↓
Gap Diagnosis
 ↓
CCEC / CTPC Generation
 ↓
Validation
 ↓
Contract Injection
 ↓
Re-analysis
```

---

## 指标

- Detected CVEs；
- Recall；
- Precision；
- F1；
- Complete Path Recovery；
- False Positive。

---

## 表格设计

### Table 1 Dataset Statistics


| Vulnerability Type | CWE     | Projects | CVEs | Connectivity Gap | Propagation Gap | Mixed Gap |
| ------------------ | ------- | -------- | ---- | ---------------- | --------------- | --------- |
| SQL Injection      | CWE-89  |          |      |                  |                 |           |
| Command Injection  | CWE-78  |          |      |                  |                 |           |
| Path Traversal     | CWE-22  |          |      |                  |                 |           |
| Deserialization    | CWE-502 |          |      |                  |                 |           |
| Total              | -       |          | 100  |                  |                 |           |


### Table 2 Overall Detection Results


| Method | Detected CVEs | Recall | Precision | F1 | Path Recovery |
|---|---:|---:|---:|---:|---:|
| YASA | | | | | |
| LAPIS | | | | | |


# RQ2: Component Effectiveness and Ablation Study

## Research Question

**RQ2: How much does each component contribute to LAPIS effectiveness?**

## 研究目标

验证：

- Evidence 是否减少 LLM 幻觉；
- CCEC 是否恢复调用关系；
- CTPC 是否恢复传播语义；
- Validation 是否减少错误传播；
- 分阶段修复是否提升复杂案例效果。

---

## 消融设置


| Configuration | Removed Component |
|---|---|
| Full LAPIS | None |
| w/o Evidence | Static Evidence |
| w/o CCEC | Call-edge Contract |
| w/o CTPC | Propagation Contract |
| w/o Validation | Three-way Validation |


---

## 指标

- Recall；
- Precision；
- F1；
- Path Recovery；
- False Positive；
- LLM Calls。

---

## Table 3 Ablation Study


| Configuration | Recall | Precision | F1 | Path Recovery | FP |
|---|---:|---:|---:|---:|---:|
| Full LAPIS||||||
| w/o Evidence||||||
| w/o CCEC||||||
| w/o CTPC||||||
| w/o Validation||||||


# RQ3: Robustness across Different LLM Backends

## Research Question

**RQ3: How does the choice of LLM backend affect LAPIS performance?**

## 研究目标

验证：

- LAPIS 是否依赖某一个特定 LLM；
- 不同模型生成契约质量差异；
- 静态证据和验证机制是否能够稳定约束不同模型。

---

## 数据集

由于多模型运行成本较高：

从 RQ1 的 100 个 CVE 中抽取：

20-30 个代表性案例。

选择原则：


| Gap Type         | Number |
| ---------------- | ------ |
| Connectivity Gap | 8-10   |
| Propagation Gap  | 8-10   |
| Mixed Gap        | 5-10   |


保证：

- 不同 CWE；
- 不同项目；
- 不同难度。

---

## LLM模型


| Model             | Description |
| ----------------- | ----------- |
| GPT-5             | OpenAI 高能力闭源模型 |
| Claude Opus 5     | Anthropic 高能力闭源模型 |
| DeepSeek V4 Flash | DeepSeek 低延迟、低成本模型 |


---

## 控制变量

所有模型：

- 相同 prompt；
- 相同 evidence；
- 相同 candidate；
- 相同 validation；
- 相同输出格式。

---

## 指标

- Contract Accuracy；
- Validation Pass Rate；
- Path Recovery；
- Token Cost；
- Latency。

---

## Table 4 LLM Backend Comparison


| Model | Contract Accuracy | Triple Pass | Path Recovery | Cost |
|---|---:|---:|---:|---:|
| GPT-5|||||
| Claude Opus 5|||||
| DeepSeek V4 Flash|||||


---

# RQ4: Real-world Vulnerability Discovery

## Research Question

**RQ4: Can LAPIS discover security issues in previously unseen real-world projects?**

## 研究目标

验证：

- LAPIS 是否具有实际漏洞发现能力；
- 是否能够应用于未参与 benchmark 的真实项目。

---

## 数据集

选择：

20-50 个真实开源项目。

要求：

- 未出现在 CVE Benchmark；
- 持续维护；
- Python项目；
- 具有一定规模。

---

## 实验流程

```
Real Project

↓

YASA Analysis

↓

LAPIS Enhancement

↓

New Findings

↓

Manual Validation

```

---

## 人工分类


| Category                | Description |
| ----------------------- | ----------- |
| Confirmed Vulnerability | 已确认漏洞       |
| Valid Risky Flow        | 有风险传播路径     |
| Sanitized               | 已被安全机制阻断    |
| False Positive          | 错误结果        |
| Unknown                 | 无法确认        |


---

## 指标

由于没有完整 Ground Truth：

不计算 Recall。

使用：

- New Findings；
- Confirmed Issues；
- Precision；
- False Positive。

---

## Table 5 Real-world Evaluation


| Project   | LOC | YASA Findings | LAPIS Findings | Confirmed | FP  |
| --------- | --- | ------------- | -------------- | --------- | --- |
| Project A |     |               |                |           |     |
| Project B |     |               |                |           |     |
| Project C |     |               |                |           |     |
| Total     |     |               |                |           |     |


# 3. SANER Evaluation章节结构

```
5 Evaluation

5.1 Dataset and Experimental Setup


5.2 RQ1:
Effectiveness on Known Vulnerabilities


5.3 RQ2:
Component Effectiveness and Ablation


5.4 RQ3:
LLM Backend Robustness


5.5 RQ4:
Real-world Vulnerability Discovery

```

---

# 4. 正文推荐表格

正文保留：

1. Dataset Statistics
2. Main Detection Results
3. Gap Type Recovery
4. Ablation Study
5. LLM Backend Comparison
6. Real-world Evaluation

附录：

- CVE详细结果；
- Contract字段准确率；
- Prompt；
- LLM输出。

---

# 总结

四个RQ形成完整实验闭环：

RQ1：
证明 LAPIS 是否有效；

RQ2：
证明 LAPIS 为什么有效；

RQ3：
证明 LAPIS 是否依赖特定 LLM；

RQ4：
证明 LAPIS 是否具有真实应用价值。

该结构更符合 SANER/ICSE/FSE 软件分析论文的实验组织方式。

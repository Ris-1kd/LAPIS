# LAPIS Repair Case Study Report

本文整理三个完整修复例子：

```text
1. RPyC / CVE-2024-27758
   Hard 模式，Connectivity Gap，补充调用边 CCEC。

2. PyMySQL / CVE-2024-36039
   Propagation Gap，补充数据流 CTPC。

3. python-multipart / CVE-2026-24486
   Mixed Case，先补调用边 CCEC，再补数据流 CTPC。
```

报告重点是：

```text
原始 YASA baseline 如何断链
Evidence Gate / Evidence Pack 抽取了什么证据
LLM 应该如何基于证据生成契约
契约补充了哪些边或传播条件
验证与回灌后如何得到完整链路
```

注意：当前仓库实验中，LLM prompt 已生成；实际契约文件使用 seed / oracle-safe inferred / hand-materialized contract 产物模拟 LLM 输出。也就是说，流程是 LLM-ready 的，但这些实验没有调用外部模型 API。

## 1. 总体框架

### 1.1 Step 1: Evidence Gate

Evidence Gate 先判断 case 是否值得修，避免把所有 no-finding 都当成漏报。

检查项包括：

```text
source 是否命中
sink 是否命中
source 和 sink 是否存在上下文关联
source forward frontier 到达哪里
sink backward dependency 依赖什么
是否存在 symbolic/dangling callee
是否存在 sanitizer / safe pattern / infeasible path
补边是否会图爆炸
```

输出：

```text
candidate_fn / true_negative / safe_killed / infeasible / deferred
```

### 1.2 Step 2: Gap Diagnosis

通过门控后，进入断链类型诊断：

| 类型 | 含义 | 修复契约 |
|---|---|---|
| Connectivity Gap | 调用图不完整，分析进不去真实 callee | CCEC |
| Propagation Gap | 调用图基本完整，但 taint / value / access-path 不传播 | CTPC |
| Mixed Case | 调用边和数据流都缺 | 先 CCEC，再 CTPC |

## 2. Case A: RPyC Hard 模式补调用边

### 2.1 Case 信息

```text
case_id: cve-2024-27758-rpyc
project: RPyC
vulnerability: unsafe deserialization
gap_type: connectivity_gap
difficulty: hard
contract: CCEC
```

相关产物：

```text
case:
LAPIS/LAPIS-Experiments/cases/connectivity_gap/cve-2024-27758-rpyc/case.json

oracle-safe prompt:
LAPIS/LAPIS-Experiments/cases/connectivity_gap/cve-2024-27758-rpyc/llm/ccec_prompt.oracle_safe.md

inferred CCEC:
LAPIS/LAPIS-Experiments/cases/connectivity_gap/cve-2024-27758-rpyc/ccec/candidate_edges.oracle_safe_inferred.json

final repaired run:
LAPIS/LAPIS-Experiments/cases/connectivity_gap/cve-2024-27758-rpyc/repaired-runs/taint-ccec-final-sink-only/scan_summary.json
```

### 2.2 原始 baseline 断链

在 final-sink-only 设置下，YASA baseline 能命中 source，但不能命中真实最终 sink `pickle.loads`，也没有完整 finding。

```text
baseline / final sink only:
  source marked = 1
  final sink rule = pickle.loads
  matched sink = 0
  findings = 0
```

这里的关键不是“sink 已经被 YASA 命中但 taint 不通”，而是：

```text
最终 sink pickle.loads 位于 generated __array__ 方法体内；
YASA baseline 没有进入这个 generated method；
所以最终 sink 规则没有被原生触发。
```

断点在动态特殊方法调用：

```python
# poc/poc_cve_2024_27758_rpyc.py:20
array_callback = getattr(obj, "__array__")

# poc/poc_cve_2024_27758_rpyc.py:21
return array_callback()
```

source 构造了恶意 pickle payload：

```python
# poc/poc_cve_2024_27758_rpyc.py:25
payload = cve_2024_27758_source()
```

sink 在动态生成的 `__array__` 方法体内：

```python
# rpyc/core/netref.py:251-255
elif name == "__array__":
    def __array__(self):
        return pickle.loads(syncreq(self, consts.HANDLE_PICKLE, -1))
```

调用图断链发生在：

```text
getattr(obj, "__array__")
  无法解析到 class_factory/type(...) 生成的 __array__ 方法

array_callback()
  无法绑定到 _make_method("__array__") 返回的 inner function
```

所以 baseline 的本质问题不是普通函数调用缺失，而是：

```text
dynamic getattr
factory-generated method
type(..., ns) dynamic class construction
generated inner function materialization
```

### 2.3 Evidence Bundle

无答案版 prompt 不暴露完整 benchmark frontier，只暴露静态证据：

```text
observed callsite:
  poc/poc_cve_2024_27758_rpyc.py:20 getattr(obj, "__array__")

factory call:
  poc/poc_cve_2024_27758_rpyc.py:26
  class_factory(("remote.module.EvilArray", 1, 0), [("__array__", "array protocol")])

factory method creation:
  rpyc/core/netref.py:331
  ns[name] = _make_method(name, doc)

dynamic class construction:
  rpyc/core/netref.py:332
  type(netref_name, (BaseNetref,), ns)

generated method branch:
  rpyc/core/netref.py:251
  name == "__array__"

generated sink:
  rpyc/core/netref.py:255
  pickle.loads(syncreq(self, consts.HANDLE_PICKLE, -1))
```

这些证据足以让 LLM 推理：

```text
__array__ 这个属性名同时出现在 getattr、class_factory methods、_make_method guard 和 inner function 中。
class_factory 把 _make_method(name, doc) 的返回值放进 ns[name]。
type(netref_name, (BaseNetref,), ns) 把 ns 物化成动态类方法集合。
因此 getattr(obj, "__array__") 可以绑定到 generated __array__。
generated __array__ 内部直接调用 pickle.loads。
```

### 2.4 LLM 生成的 CCEC 候选边

该 Hard case 一次生成两条联动候选边，不是严格两轮迭代。

#### Edge 1: dynamic attribute dispatch to generated method

```text
caller:
  poc.poc_cve_2024_27758_rpyc.numpy_like_array_coercion

callsite:
  getattr(obj, "__array__")

callee:
  rpyc.core.netref._make_method.<generated __array__>

callee_kind:
  materialized_factory_method
```

类型：

```text
Hard
Dynamic Attribute Dispatch Gap
Dynamic Class Factory Gap
```

关键 guard：

```text
getattr attribute == "__array__"
class_factory methods contains "__array__"
ns[name] = _make_method(name, doc) is reachable
type(netref_name, (BaseNetref,), ns) materializes namespace
_make_method guard name == "__array__"
```

#### Edge 2: generated method body to sink

```text
caller:
  rpyc.core.netref._make_method.<generated __array__>

callsite:
  pickle.loads(syncreq(self, consts.HANDLE_PICKLE, -1))

callee:
  pickle.loads

callee_kind:
  builtin_sink
```

类型：

```text
Middle / Easy-after-materialization
Generated Method Body Gap
Virtual Sink Reachability Gap
```

一旦 Edge 1 确认 `name == "__array__"`，Edge 2 的证据很直接：inner function body 里直接有 `pickle.loads(...)`。

### 2.5 CCEC 验证

结构验证结果：

```text
validate-ccec-candidates:
  status = accepted
  edges = 2

build-repaired-call-chain:
  status = complete
  complete_at_callgraph_level = true
```

注意：这里的 complete 是调用图 / 虚拟调用链层面的 complete。

CCEC 也需要三分验证，但验证对象是调用边契约，不是数据流传播：

```text
must-link:
  正例必须补出调用边。

must-not-link:
  相似但无关的调用点不能误补边。

must-kill:
  guard 不满足或 negative evidence 存在时必须抑制补边。
```

RPyC 的 link validation 产物：

```text
LLM validation prompt:
LAPIS/LAPIS-Experiments/cases/connectivity_gap/cve-2024-27758-rpyc/llm/ccec_link_validation_prompt.md

seed validation contract:
LAPIS/LAPIS-Experiments/cases/connectivity_gap/cve-2024-27758-rpyc/validation/ccec_link_validation.seed.json

validation report:
LAPIS/LAPIS-Experiments/cases/connectivity_gap/cve-2024-27758-rpyc/validation/ccec_link_validation_report.json
```

验证结果：

```text
status = accepted
must_link = passed
must_not_link = passed
must_kill = passed
```

### 2.6 YASA 消费虚拟边

RPyC 与 IPython 不同，YASA 原生解释器没有真正进入：

```text
rpyc.core.netref._make_method.<generated __array__>
```

因此仅把边放进 callgraph 输出还不够。LAPIS-Tool 增加了 CCEC virtual edge consumer。最终设计中，YASA ruleConfig 只保留真实最终 sink：

```text
pickle.loads
```

`array_callback()` 和 `_make_method(...)` 只作为 CCEC frontier / boundary，不再伪装成 sink rule。

CCEC consumer 的逻辑是：

```text
1. 识别 materialized_factory_method -> builtin_sink 的 CCEC 链。
2. 在 YASA 实际能到达的边界点 array_callback() 消费虚拟链。
3. 构造 synthetic CCEC taint node。
4. 输出带 CCEC trace 的 finding，finding 的 sinkRule 指向最终 sink pickle.loads。
5. 严格限制 _make_method(name, doc) 泛化边界，避免图爆炸和 62 个误触发。
```

最终增强运行：

```text
scan_summary:
  Findings = 1
  Sources marked = 1
  Sinks matched = 0
```

finding 位置：

```text
poc/poc_cve_2024_27758_rpyc.py:21
array_callback()
```

finding 的最终 sink 信息：

```text
SINK RULE: pickle.loads
SINK Attribute: LAPIS CCEC virtual sink: pickle.loads
```

这里 `Sinks matched = 0` 是预期结果：YASA baseline 没有真实执行到 `pickle.loads` 调用点，最终 sink 是由 CCEC 虚拟链路证明并挂到 finding 上的。

trace 表达的虚拟完整链路：

```text
SOURCE:
  poc/poc_cve_2024_27758_rpyc.py:20 getattr(obj, "__array__")

CALL EDGE:
  generated __array__ -> pickle.loads

SINK evidence:
  rpyc/core/netref.py:255 pickle.loads(syncreq(...))
```

### 2.7 RPyC 完整链路

语义链路为：

```text
payload = cve_2024_27758_source()
  -> FakeConnection(payload)
  -> class_factory(..., [("__array__", ...)])
  -> ns["__array__"] = _make_method("__array__", doc)
  -> type(netref_name, (BaseNetref,), ns)
  -> getattr(proxy, "__array__")
  -> array_callback()
  -> generated __array__(self)
  -> pickle.loads(syncreq(self, consts.HANDLE_PICKLE, -1))
```

补充边数量：

```text
2 条 CCEC 调用边
```

链路性质：

```text
真实源码语义上成立。
YASA 没有原生执行 generated method。
LAPIS 用 CCEC 虚拟边在边界点补齐并消费。
```

## 3. Case B: PyMySQL 补数据流

### 3.1 Case 信息

```text
case_id: cve-2024-36039-pymysql
project: PyMySQL
vulnerability: SQL injection
gap_type: propagation_gap
contract: CTPC
```

相关产物：

```text
Evidence Pack:
LAPIS/LAPIS-Experiments/cases/propagation_gap/cve-2024-36039-pymysql/evidence/evidence_pack.json

CTPC prompt:
LAPIS/LAPIS-Experiments/cases/propagation_gap/cve-2024-36039-pymysql/llm/ctpc_prompt.md

CTPC contract:
LAPIS/LAPIS-Experiments/cases/propagation_gap/cve-2024-36039-pymysql/ctpc/ctpc.v2.json

validation report:
LAPIS/LAPIS-Experiments/cases/propagation_gap/cve-2024-36039-pymysql/validation/reports-v2/validation_report.json

full CVE enhanced run:
LAPIS/LAPIS-Experiments/cases/propagation_gap/cve-2024-36039-pymysql/full-cve-runs/lapis-tool-ctpc-v2/scan_summary.json
```

### 3.2 原始 baseline 断链

baseline 状态：

```text
source_hit = true
sink_hit = true
call_context_reachable = true
complete_taint_path_found = false
findings = 0
```

也就是说，调用上下文基本可达，不是 CG 进不去，而是数据传播断了。

source：

```python
# poc/poc_cve_2024_36039_pymysql.py:30
key = cve_2024_36039_source()
```

source 进入 dict key：

```python
# poc/poc_cve_2024_36039_pymysql.py:31
args = {key: "safe-value"}
```

sink：

```python
# pymysql/cursors.py:153
result = self._query(query)
```

sink backward dependency：

```text
result = self._query(query)
  <- query
  <- query = query % self._escape_args(args, conn)
  <- return {key: conn.literal(val) for (key, val) in args.items()}
  <- args.items()
  <- args.keys()[*]
```

断链本质：

```text
source taint 在 key 上。
sink 依赖 query。
query 的结构风险来自 named percent-format mapping 的 key。
YASA 没有把 tainted dict key 传播成 SQL structure risk。
```

这属于：

```text
Propagation Gap
Access-path / container-key / operator semantics missing
```

### 3.3 Evidence Pack

Evidence Pack 抽取到三类关键结构：

```text
1. dict literal key
   args = {key: "safe-value"}

2. dict comprehension key preservation
   return {key: conn.literal(val) for (key, val) in args.items()}

3. named percent format
   query = query % self._escape_args(args, conn)
```

source forward frontier：

```text
key
```

sink backward dependency 会聚点：

```text
args.keys()[*]
```

Evidence Pack 给出的 top-k propagation hypotheses：

```text
key -> args.keys()[*]
args.keys()[*] -> escaped_args.keys()[*]
escaped_args.keys()[*] -> query
```

### 3.4 LLM 生成的 CTPC

CTPC 不是直接写 validation sample，而是生成结构化传播契约。

核心 fact types：

```text
tainted_symbol
mapping_key
sql_structure_value
```

核心 propagation edges：

#### Edge 1: dict literal key to mapping key

```text
dict_literal_key_to_mapping_key

from:
  tainted_symbol($key)

to:
  mapping_key($lhs.keys()[*])

evidence:
  args = {key: "safe-value"}
```

#### Edge 2: dict comprehension preserves keys

```text
dict_comprehension_key_preserved

from:
  mapping_key($map.keys()[*])

to:
  mapping_key($lhs.keys()[*])

evidence:
  return {key: conn.literal(val) for (key, val) in args.items()}
```

#### Edge 3: percent mapping key to SQL structure

```text
percent_mapping_key_to_sql_structure

from:
  mapping_key($rhs.keys()[*])

to:
  sql_structure_value($result)

evidence:
  query = query % self._escape_args(args, conn)
```

Function summary：

```text
escape_args_return_preserves_mapping_keys

_escape_args(arg0) returns a mapping whose keys preserve arg0.keys()[*]
```

Risk upgrade：

```text
mapping_key -> sql_structure_value
when mapping keys are consumed by percent-format query construction
```

Kill conditions：

```text
key_whitelist_guard:
  if key not in {"name"}: return

value_only_parameterization:
  args = {"name": val}
```

### 3.5 三分验证

CTPC 之后，验证器生成三类 validation samples：

```text
must-flow:
  tainted key enters mapping key and percent format.
  expected = finding

must-not-flow:
  tainted value only, mapping key is literal safe key.
  expected = no_finding

must-kill:
  tainted key exists but whitelist guard blocks unsafe key.
  expected = no_finding
```

验证结果：

```text
status = accepted
must-flow = passed
must-not-flow = passed
must-kill = passed
edge coverage = all three propagation edges covered
```

### 3.6 YASA 回灌与完整链路

full CVE baseline：

```text
Findings = 0
Sources marked = 1
Sinks matched = 2
```

LAPIS-Tool + CTPC v2：

```text
Findings = 1
Sources marked = 1
Sinks matched = 2
```

增强后的完整数据流链路：

```text
key = cve_2024_36039_source()
  -> args = {key: "safe-value"}
  -> args.keys()[*] is mapping_key
  -> _escape_args(args, conn)
  -> return {key: conn.literal(val) for (key, val) in args.items()}
  -> escaped mapping preserves args.keys()[*]
  -> query = query % self._escape_args(args, conn)
  -> mapping_key upgrades to SQL_STRUCTURE query
  -> result = self._query(query)
```

补充传播边数量：

```text
3 条 propagation edges
1 条 function summary
1 条 risk upgrade
2 条 kill conditions
```

## 4. Case C: python-multipart Mixed 模式完整链路

### 4.1 Case 信息

```text
case_id: cve-2026-24486-python-multipart
project: python-multipart
vulnerability: path traversal / arbitrary file overwrite
gap_type: mixed_case
difficulty: hard
contract: CCEC + CTPC
```

相关产物：

```text
case:
LAPIS/LAPIS-Experiments/cases/mixed_case/cve-2026-24486-python-multipart/case.json

CCEC candidate edges:
LAPIS/LAPIS-Experiments/cases/mixed_case/cve-2026-24486-python-multipart/ccec/candidate_edges.json

CTPC Evidence Pack:
LAPIS/LAPIS-Experiments/cases/mixed_case/cve-2026-24486-python-multipart/evidence/evidence_pack.json

CTPC repair plan:
LAPIS/LAPIS-Experiments/cases/mixed_case/cve-2026-24486-python-multipart/ctpc/ctpc_repair_plan.json

FILE_PATH CTPC contract:
LAPIS/LAPIS-Experiments/cases/mixed_case/cve-2026-24486-python-multipart/ctpc/ctpc.file_path.json

final repaired run:
LAPIS/LAPIS-Experiments/cases/mixed_case/cve-2026-24486-python-multipart/repaired-runs/ccec-ctpc-file-path/ccec-ctpc-file-path/scan_summary.json
```

### 4.2 原始 baseline 断链

source 在 PoC 里生成不可信文件名：

```python
# poc/poc_cve_2026_24486_python_multipart.py:9
filename = cve_2026_24486_source()
```

source 被传给 parser 构造器：

```python
# poc/poc_cve_2026_24486_python_multipart.py:16-21
parser = FormParser(
    "application/octet-stream",
    on_field=None,
    on_file=None,
    file_name=filename,
    config=config,
)
```

YASA 可见的边界调用：

```python
# poc/poc_cve_2026_24486_python_multipart.py:23
return parser.write(b"file-content")
```

真实最终 sink 在库内部：

```python
# python_multipart/multipart.py:478
tmp_file = open(path, "w+b")
```

baseline 断链包含两层：

```text
Connectivity Gap:
  parser.write(...) 没有完整进入 callback on_start。
  callback on_start 内部的 FileClass(file_name, ...) 没有稳定连到 File.__init__。

Propagation Gap:
  filename 进入 FormParser.file_name 后，
  没有继续传播到 File.__init__.file_name / path / open(path)。
```

实际验证结果：

```text
baseline-check:
  findingCount = 0
  markedSourceCount = 0
  matchedSinkCount = 0

CCEC-only:
  findingCount = 0
  markedSourceCount = 2
  matchedSinkCount = 12
```

这说明 CCEC-only 已经让 YASA 观察到更多 source/sink 上下文，但仍然没有完整 finding；所以它是 Mixed Case，而不是单纯 Connectivity Gap。

### 4.3 CCEC 补充的调用边

mixed 模式先补调用边，目标是推进 source frontier，使后续 CTPC 有上下文可消费。

#### Edge 1: parser.write to callback

```text
caller:
  multipart.OctetStreamParser.write

callsite:
  callbacks["on_start"]()

callee:
  multipart.FormParser.__init__.<locals>.on_start
```

对应源码语义：

```text
FormParser 创建 callbacks["on_start"] = on_start。
parser.write(...) 触发 on_start callback。
```

#### Edge 2: callback to FileClass constructor

```text
caller:
  multipart.FormParser.__init__.<locals>.on_start

callsite:
  FileClass(file_name, ...)

callee:
  multipart.File.__init__
```

对应语句：

```python
# python_multipart/multipart.py:1558
file = FileClass(file_name, None, config=cast("FileConfig", self.config))
```

CCEC 修补后，调用图层面可以表达：

```text
parser.write(...)
  -> on_start()
  -> FileClass(file_name, ...)
  -> File.__init__
```

但 CCEC 不负责证明 `filename` 如何变成 `path`，所以仍需 CTPC。

### 4.4 CTPC 补充的数据流传播

CTPC Evidence Pack 给出的 top-k propagation candidates：

```text
Top 1:
  filename -> FormParser.file_name
  kind = constructor_keyword_capture
  score = 0.88

Top 2:
  FormParser.file_name -> File.__init__.file_name
  kind = closure_capture_to_constructor_arg
  score = 0.84

Top 3:
  File.__init__.file_name -> path
  kind = path_join_keep_filename
  score = 0.80

Top 4:
  path -> open(path)
  kind = filesystem_sink_argument
  score = 0.78
```

具体传播语句：

```python
# poc/poc_cve_2026_24486_python_multipart.py:20
file_name=filename

# python_multipart/multipart.py:1558
file = FileClass(file_name, None, config=cast("FileConfig", self.config))

# python_multipart/multipart.py:370
self._file_name = file_name

# python_multipart/multipart.py:378
base, ext = os.path.splitext(file_name)

# python_multipart/multipart.py:473
fname = self._file_base + self._ext if keep_extensions else self._file_base

# python_multipart/multipart.py:475
path = os.path.join(file_dir, fname)

# python_multipart/multipart.py:478
tmp_file = open(path, "w+b")
```

本 case 的 CTPC 使用通用 fact，而不是 PyMySQL 专属 SQL fact：

```text
risk_kind:
  FILE_PATH

fact_types:
  tainted_symbol
  file_path_component
  file_path_sink_value
```

核心 contract events：

```text
function_call:
  constructor_keyword_capture

assignment:
  path_join_keep_filename

sink / risk_upgrade:
  filesystem_sink_argument
  virtual_final_sink = open(path)
```

### 4.5 通用 CTPC consumer

为了避免把每个 CVE 的语义硬编码进 YASA，LAPIS-Tool 的 CTPC consumer 被改成契约驱动的通用解释器。

它不再只识别：

```text
dict_literal_key
dict_comprehension_key_preserved
percent_mapping_key
SQL_STRUCTURE
```

而是解释 CTPC 中的结构化字段：

```text
event:
  assignment | function_call | sink | risk_upgrade

pattern.kind:
  由 CTPC 合同声明，例如 constructor_keyword_capture、filesystem_sink_argument

from / to:
  由 CTPC 声明 fact 名称、expr、access_path、risk_kind
```

因此 python-multipart 的 FILE_PATH 传播不需要继续在 consumer 里写 CVE 专属逻辑，而是通过：

```text
ctpc.file_path.json
```

声明可消费的传播语义。

当前 consumer 增加的通用能力：

```text
generic fact store:
  按 CTPC fact name 存储传播事实。

tainted identifier seeding:
  支持 YASA TaintSource path=filename 这类 source。

contract-driven assignment/function_call:
  根据 CTPC event 和 pattern.kind 传播 fact。

contract-driven sink / risk_upgrades:
  只有当前 sink 匹配 CTPC sink/risk_upgrade 合同时才 force。

virtual final sink metadata:
  physical boundary 可以是 parser.write(...)，
  但 final sink evidence 指向 open(path)。
```

### 4.6 YASA 回灌与完整链路

最终增强运行：

```text
CCEC + CTPC file-path:
  findingCount = 2
  markedSourceCount = 2
  matchedSinkCount = 12
```

完整 mixed 链路：

```text
filename = cve_2026_24486_source()
  -> FormParser(..., file_name=filename, config=config)
  -> parser.write(b"file-content")
  -> callbacks["on_start"]()
  -> FileClass(file_name, None, config=...)
  -> File.__init__(file_name, ...)
  -> self._file_name = file_name
  -> os.path.splitext(file_name)
  -> fname = self._file_base + self._ext
  -> path = os.path.join(file_dir, fname)
  -> open(path, "w+b")
```

注意：YASA 物理触发点仍是它能到达的边界：

```text
poc/poc_cve_2026_24486_python_multipart.py:23
parser.write(...)
```

但 CCEC/CTPC trace 会给出最终 sink 证据：

```text
LAPIS CCEC final sink evidence:
  open(path, "w+b")

LAPIS CTPC:
  FILE_PATH value filename
  final sink open(path)
```

这和 RPyC 的虚拟 sink 处理方式一致：物理 reporting boundary 不一定等于最终 sink 所在源码行，但 finding 的证据链必须说明最终 sink。

补充数量：

```text
2 条 CCEC 调用边
4 个 CTPC top-k propagation candidates
1 个 FILE_PATH CTPC contract
1 个 virtual final sink upgrade
```

当前还需要继续加强的是三分验证：

```text
must-flow:
  tainted filename reaches virtual open(path)

must-not-flow:
  body bytes tainted but filename untainted，不应报告 FILE_PATH finding

must-kill:
  filename 经 basename / path sanitizer 规范化后应抑制
```

## 5. 三个例子的对比

| 维度 | RPyC Hard CCEC | PyMySQL CTPC | python-multipart Mixed |
|---|---|---|---|
| 缺失类型 | Connectivity Gap | Propagation Gap | Mixed Case |
| baseline 断点 | `getattr(obj, "__array__")` 无法连到 generated method | `key` 无法传播到 `query` 的 SQL structure | `parser.write` callback 与 `filename -> path` 都断 |
| 是否需要补调用边 | 是 | 否 | 是 |
| 是否需要补数据流 | 主要不需要，问题是虚拟 callee 可达 | 是 | 是 |
| 主要证据 | getattr、class_factory、_make_method、type(..., ns)、pickle.loads | dict key、dict comprehension、percent format、sink backward slice | callback、closure、constructor keyword、path join、open |
| LLM 输出 | CCEC candidate_edges | CTPC propagation contract | CCEC edges + CTPC FILE_PATH contract |
| 补充数量 | 2 条调用边 | 3 条传播边 + summary/upgrade/kill | 2 条调用边 + 4 个传播候选 + virtual final sink |
| 验证 | structural CCEC + repaired call chain + YASA virtual consumer | 三分验证 + full CVE enhanced YASA | CCEC-only no finding，CCEC+CTPC finding |
| 回灌方式 | LAPIS CCEC virtual edge consumer | LAPIS CTPC dataflow consumer | CCEC virtual edge + 通用 CTPC consumer |
| 最终 finding | 1 | 1 | 2 |

## 6. LLM 修复方案完整流程

### 6.1 共同入口

所有 case 先走同一个入口，不直接让 LLM 生成 finding。

```text
Step 1. Evidence Gate
  判断是否值得修：
  source 是否命中，sink 是否命中，是否有上下文关联，
  frontier 在哪里断，是否有反证，是否有图爆炸风险。

Step 2. Gap Diagnosis
  将 candidate FN 分成三类：
  Connectivity Gap
  Propagation Gap
  Mixed Case
```

之后进入不同分支。

### 6.2 Connectivity Gap / CCEC 完整流程

CCEC 分支只修调用连接性，不补数据流传播语义。

```text
1. 输入
   Evidence Gate report
   Gap Diagnosis report
   case metadata
   source/sink anchor
   baseline callgraph / symbolic callee / dangling callee 信息
```

```text
2. 构造 Call Edge Evidence Bundle
   CG:
     caller、symbolic callee、dangling callsite、附近 resolved 函数

   AST/UAST:
     调用表达式、receiver、参数、字符串常量

   def-use:
     name = "__array__"、methods = [("__array__", ...)]、ns[name] = ...

   type/class graph:
     type(..., ns)、动态类 namespace、类方法集合

   import/module graph:
     候选 callee 的真实模块和函数位置

   sink backward hint:
     哪些 generated callee 或候选函数靠近最终 sink

   negative evidence:
     属性不存在、guard 不满足、sanitizer、安全分支、图爆炸风险
```

```text
3. CCEC Repair Plan: Difficulty + Top-K Routing
   代码先生成一个 repair plan，而不是直接调用 LLM。

   命令：
     plan-ccec-repair

   输出字段：
     mode: easy | middle | hard | deferred
     llm_required: true | false
     generation_strategy
     top_k
     evidence_kind
     candidate_count_from_static_rules
     next_steps
```

三种模式的调度规则：

```text
Easy:
  规则可唯一或近唯一推出边。
  llm_required = false
  top_k = 1
  generation_strategy = rule_static
  例：IPython module-level rebinding。

Middle:
  规则能生成 top-k 候选，但需要 LLM 排序、解释 guard、生成契约。
  llm_required = true
  top_k = 3~5
  generation_strategy = rule_top_k_then_llm_rank

Hard:
  需要跨多图语义推理或 generated/virtual callee。
  llm_required = true
  top_k = 5
  generation_strategy = llm_oracle_safe
  例：RPyC getattr + class_factory + type(..., ns)。
```

当前代码产物：

```text
IPython:
  LAPIS/LAPIS-Experiments/cases/connectivity_gap/cve-2023-24816-ipython/ccec/ccec_repair_plan.json
  mode = easy
  llm_required = false
  top_k = 1
  strategy = rule_static

RPyC:
  LAPIS/LAPIS-Experiments/cases/connectivity_gap/cve-2024-27758-rpyc/ccec/ccec_repair_plan.json
  mode = hard
  llm_required = true
  top_k = 5
  strategy = llm_oracle_safe
```

```text
4. LLM CCEC Candidate Prompt
   输入：
     oracle-safe evidence bundle
     不给完整 benchmark frontier

   输出：
     candidate_edges

   每条边包含：
     edge_id
     caller
     callsite
     callee
     callee_kind
     confidence
     guards
     evidence
     contract.preconditions
     contract.effects: add_call_edge
     contract.must_not_apply_when
```

RPyC 的 CCEC 输出示例：

```text
Edge 1:
  getattr(obj, "__array__")
    -> rpyc.core.netref._make_method.<generated __array__>

Edge 2:
  rpyc.core.netref._make_method.<generated __array__>
    -> pickle.loads
```

```text
5. Structural CCEC Validation
   检查：
     caller 是否存在或可定位
     callsite 是否存在
     callee 是否真实存在或可 materialize
     guards 是否非空
     evidence 是否非空
     confidence 是否有效
```

```text
6. LLM CCEC Link Validation Prompt
   这一步不是生成候选边，而是让 LLM 生成验证样例：

   must-link:
     正例，必须补出边。

   must-not-link:
     反例，相似结构不能误补边。

   must-kill:
     guard 不满足或 negative evidence 存在时必须抑制补边。
```

RPyC 的三分样例：

```text
must-link:
  getattr(obj, "__array__")
  class_factory(..., [("__array__", ...)])
  _make_method guard name == "__array__"
  => link to generated __array__ and pickle.loads

must-not-link:
  getattr(obj, "__iter__")
  => must not link to generated __array__ or pickle.loads

must-kill:
  getattr(obj, "__array__")
  class_factory methods do not contain "__array__"
  => suppress edge
```

```text
7. CCEC Link Validation
   代码侧验证 LLM 输出的 validation contract：
     must_link 是否完整
     must_not_link 是否完整
     must_kill 是否完整
     是否覆盖所有 candidate_edges
     full_chain_expectation 是否完整

   命令：
     validate-ccec-link-contract
```

```text
8. Apply / Consume CCEC
   根据 callee_kind 分两类：

   real_function / rebound_function:
     可注入 repaired callgraph 或作为边界 trace 消费。

   materialized_factory_method / callback / virtual callee:
     由 LAPIS CCEC virtual edge consumer 消费。
```

```text
9. Final Sink Only Reporting
   ruleConfig 只保留真实最终 sink。
   中间 frontier / boundary 不作为 sink rule。

   对 RPyC：
     最终 sink = pickle.loads
     boundary = array_callback()

   finding 报在 YASA 可达的 boundary，
   但 sinkRule 必须显示最终 sink pickle.loads。
```

```text
10. Stop Condition
   stop when:
     repaired graph reaches final sink or accepted virtual sink boundary;
     must-link/must-not-link/must-kill 全部通过；
     YASA enhanced run 输出 expected finding。

   stop without repair when:
     no graph frontier progress;
     confidence below threshold;
     graph explosion risk is high;
     must-not-link or must-kill fails;
     negative evidence proves path unsafe/infeasible.
```

### 6.3 Propagation Gap / CTPC 完整流程

CTPC 分支只修 taint/value/access-path 传播，不补调用边。

```text
1. 输入
   Evidence Gate report
   Gap Diagnosis report
   source forward slice
   sink backward slice
   local AST/UAST evidence
```

```text
2. 构造 Evidence Pack
   source evidence
   sink evidence
   frontier variable / access path
   backward dependency chain
   local convergence point
   assignment / call / return / operator / container evidence
   sanitizer / kill / safe pattern
```

PyMySQL 的会聚点：

```text
source frontier:
  key

sink backward dependency:
  query
  query = query % self._escape_args(args, conn)
  args.keys()[*]

local convergence:
  args.keys()[*]
```

```text
3. CTPC Repair Plan: Top-K Propagation Candidates
   代码先从 Evidence Pack 中生成并排序候选传播义务。

   命令：
     plan-ctpc-repair

   输出字段：
     top_k_propagation_candidates
     score
     evidence
     generation_strategy
     contract_mapping
```

注意：

```text
CTPC 的 top-k 不是最终契约字段。
它是生成契约时输入给 LLM 的 ranked candidate set。
LLM 从 top-k 中选择、合并、改写，最后映射成：
  propagation_edges
  function_summaries
  risk_upgrades
  kill_conditions
```

PyMySQL 的 top-k propagation candidates：

```text
Top 1:
  key -> args.keys()[*]
  kind = dict_literal_key
  score = 0.92

Top 2:
  args.keys()[*] -> escaped_args.keys()[*]
  kind = dict_comprehension_key_preserved
  score = 0.88

Top 3:
  escaped_args.keys()[*] -> query
  kind = named_percent_format_mapping_key
  score = 0.83
```

当前代码产物：

```text
LAPIS/LAPIS-Experiments/cases/propagation_gap/cve-2024-36039-pymysql/ctpc/ctpc_repair_plan.json

mode = middle
top_k = 3
strategy = ranked_candidates_to_llm_ctpc
```

```text
4. LLM CTPC Prompt
   输入：
     Evidence Pack
     top-k propagation candidates

   输出：
     fact_types
     propagation_edges
     function_summaries
     risk_upgrades
     kill_conditions
```

PyMySQL 的 CTPC 输出：

```text
dict literal key:
  key -> args.keys()[*]

dict comprehension:
  args.keys()[*] -> escaped_args.keys()[*]

percent mapping format:
  escaped_args.keys()[*] -> query as SQL_STRUCTURE

function summary:
  _escape_args(arg0.keys()[*]) -> return.keys()[*]

kill:
  whitelist guard
  value-only parameterization
```

```text
5. LLM CTPC Validation Prompt
   这一步生成数据流三分样例：

   must-flow:
     正例，契约应产生 finding。

   must-not-flow:
     反例，相似结构不应产生 finding。

   must-kill:
     sanitizer / whitelist / safe pattern 应阻断 finding。
```

```text
6. CTPC Three-way Validation
   检查：
     must-flow = finding
     must-not-flow = no_finding
     must-kill = no_finding
     propagation edge coverage 是否完整
```

```text
7. Apply / Consume CTPC
   将 accepted CTPC 交给 LAPIS-Tool CTPC consumer。
   consumer 在 assignment、dict comprehension、operator、sink 等事件上补传播事实。
```

```text
8. YASA Enhanced Run
   baseline:
     Findings = 0

   enhanced with CTPC:
     Findings = 1
```

```text
9. Stop Condition
   stop when:
     CTPC validation accepted;
     original case enhanced run emits expected finding.

   stop without repair when:
     must-not-flow or must-kill fails;
     no new access-path frontier progress;
     source/sink convergence is not supported by evidence;
     kill/sanitizer evidence dominates.
```

### 6.4 Mixed Case 顺序

Mixed Case 同时存在调用边缺失和数据流传播缺失。

```text
1. 先走 CCEC
   补调用边，让分析进入真实/虚拟 callee。

2. 重跑 baseline/enhanced
   检查 source frontier 是否前进。

3. 如果仍然 taint 不通，再走 CTPC
   基于补边后的新证据包补传播语义。

4. 最终验证
   CCEC must-link/must-not-link/must-kill 通过；
   CTPC must-flow/must-not-flow/must-kill 通过；
   enhanced original case 输出 expected finding。
```

### 6.5 CCEC 与 CTPC 三分验证区别

```text
CCEC:
  must-link / must-not-link / must-kill
  验证 callsite -> callee 是否应该补边。

CTPC:
  must-flow / must-not-flow / must-kill
  验证 taint/value/access-path 是否应该传播。
```

CCEC 的三分样例由大模型基于 CCEC validation prompt 生成，代码侧只做结构化校验和覆盖检查：

```text
validate-ccec-link-contract
  --validation ccec_link_validation.seed.json
  --candidates candidate_edges.oracle_safe_inferred.json
```

## 7. 结论

RPyC 展示了 Hard 模式调用边修复：

```text
LLM/证据层推断 generated method 虚拟调用链。
LAPIS CCEC 生成 2 条调用边。
YASA 通过 virtual edge consumer 在 array_callback 边界消费补齐链路。
最终 Findings = 1。
```

PyMySQL 展示了数据流传播修复：

```text
LLM/证据层生成 CTPC。
CTPC 补充 dict key -> mapping key -> SQL structure 的传播语义。
三分验证 accepted。
YASA 增强运行从 Findings = 0 变为 Findings = 1。
```

python-multipart 展示了 Mixed Case 修复：

```text
先用 CCEC 补 parser.write -> on_start -> FileClass 的调用连接。
CCEC-only 让 source/sink 可观察，但 Findings 仍为 0。
再用 CTPC FILE_PATH contract 补 filename -> path -> open(path) 的传播语义。
YASA 增强运行从 Findings = 0 变为 Findings = 2。
```

三者共同说明：

```text
补边和补数据流都应该作为外部契约插件进入 YASA 消费。
CCEC 负责补调用可达性。
CTPC 负责补传播语义。
Hard CCEC 还需要 virtual callee / virtual sink consumer。
Mixed Case 必须先验证 CCEC-only 是否仍断，再进入 CTPC。
验证必须独立于候选契约生成，避免为了报 finding 强行补。
```

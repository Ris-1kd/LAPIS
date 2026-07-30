# CVE 数据集三类断链样本矩阵

本文档把当前 Python CVE benchmark 按修复流程中的三类断链组织：

```text
1. 缺失调用边：Connectivity Gap
2. 缺失数据流：Propagation Gap
3. 调用边和数据流都缺失：Mixed Case
```

这里的三类是实验主分类。`easy / middle / hard` 只作为后续候选生成和大模型调用强度的次级标签，不作为本文档的主分类。

## 1. 总表

| 主分类 | CVE | 项目 | YASA baseline 现象 | 断链核心 | 修复分支 | 难度标签 |
|---|---|---|---|---|---|---|
| 缺失调用边 | CVE-2024-27758 | RPyC | 0 finding，source/sink 均命中 | `type(...)` 动态类、`getattr(obj, "__array__")`、特殊方法协议未进 CG | CCEC | hard |
| 缺失调用边 | CVE-2023-24816 | IPython | 近端 finding，到 `_set_term_title(title)` 后未到真实 sink | 模块级函数重绑定、平台分支下的函数定义未连到调用点 | CCEC | middle |
| 缺失数据流 | CVE-2024-36039 | PyMySQL | 0 finding，source/sink 均命中 | dict key taint、dict comprehension、`%` format 未传播到 query | CTPC | middle |
| 都缺失 | CVE-2026-24486 | python-multipart | 0 finding，source/sink 均命中 | callback/event dispatch 缺调用边，闭包 `file_name` 到 path/open 也缺传播 | 先 CCEC，后 CTPC | hard |
| 都缺失 | CVE-2025-55156 | pyLoad | 近端 finding，只到 `db.update_link_info(data)` | receiver 方法体展开不足，同时 tuple/generator/join/f-string 数据流不足 | 先 CCEC，后 CTPC | hard |
| 对照组 | CVE-2023-4033 | MLflow | YASA upstream 已完整命中真实 sink | 不作为 YASA 修复目标，用于验证 gate 不应强行修复 | no repair | control |

## 2. 第一类：缺失调用边

这一类的特点是 source frontier 已经走到某个调用点，但 baseline CG 没有把调用点连接到真实 callee。此时优先进入 CCEC，即候选调用边契约修复。

### CVE-2024-27758 / RPyC

真实链路：

```text
source payload
-> class_factory(..., [("__array__", ...)])
-> ns[name] = _make_method(name, doc)
-> type(netref_name, (BaseNetref,), ns)
-> getattr(obj, "__array__")
-> generated __array__()
-> pickle.loads(syncreq(...))
```

断链判断：

```text
source 命中：是
sink 命中：是，pickle.loads
source frontier：停在动态类 / getattr / special method protocol 附近
主要缺口：调用边
次要缺口：syncreq 返回值摘要可能还需要数据流补充
```

修复策略：

```text
1. 抽取 Evidence Bundle：
   - callsite: getattr(obj, "__array__")
   - dynamic class: type(..., ns)
   - method factory: _make_method("__array__", ...)
   - sink backward: pickle.loads(syncreq(...))
2. 生成候选调用边：
   - getattr(obj, "__array__") -> generated __array__
   - generated __array__ -> pickle.loads wrapper region
3. CCEC 验证：
   - 结构验证：callee 是否存在或可由 factory materialize
   - 图验证：补边后 frontier 是否越过 getattr/type 断点
   - 污点验证：是否接近或到达 pickle.loads
```

### CVE-2023-24816 / IPython

真实链路：

```text
source title
-> terminal.set_term_title(title)
-> _set_term_title(title)
-> Windows fallback 内重新绑定的 _set_term_title
-> os.system("title " + title)
```

断链判断：

```text
source 命中：是
sink 命中：是，os.system
source frontier：到达 _set_term_title(title) 近端边界
主要缺口：模块级函数变量重绑定导致 CG 不完整
```

修复策略：

```text
1. 识别同名函数 / 变量重绑定候选。
2. 保留平台 guard：sys.platform == "win32"。
3. 生成候选调用边：
   - terminal.py:124 _set_term_title(title)
   - -> terminal.py:104/Windows fallback def _set_term_title(title)
4. CCEC 验证补边后是否到达 os.system sink。
```

## 3. 第二类：缺失数据流

这一类的特点是调用上下文基本可达，但 taint/value/access-path 没有在局部语义中继续传播。此时进入 CTPC，即候选污点传播契约修复。

### CVE-2024-36039 / PyMySQL

真实链路：

```text
source key
-> args = {key: "safe-value"}
-> FakeCursor().execute(query, args)
-> {key: conn.literal(val) for (key, val) in args.items()}
-> query = query % self._escape_args(args, conn)
-> self._query(query)
```

断链判断：

```text
source 命中：是
sink 命中：是，_query(query)
source frontier：停在 dict key / format 传播附近
CG 状态：FakeCursor().execute 到 Cursor.execute 基本可达
主要缺口：数据流传播语义，不是主要调用边缺失
```

需要补的数据流语义：

```text
dict key taint:
  args.**keys 保留 key 污点

dict.items / comprehension:
  for (key, val) in args.items() 中 key 继承 args.**keys

format propagation:
  query % escaped_args 中，如果 escaped_args 的 key tainted，则格式化后的 query tainted
```

修复策略：

```text
1. Evidence Gate 确认 source/sink 和局部结构证据。
2. Gap Diagnosis 输出 propagation_gap。
3. CTPC 生成候选传播契约。
4. 三分验证由 validator 生成 must / must-not / must-kill 样例。
5. accepted CTPC 回灌 YASA rule/config 或 repaired semantic layer。
```

## 4. 第三类：调用边和数据流都缺失

这一类不能一上来同时乱补。处理顺序固定：

```text
1. 先补调用边 CCEC
2. 回灌或在 repaired graph 上重跑
3. 如果 taint 仍断，再补数据流 CTPC
```

原因是：如果真实 callee 还没有进入 CG，sink backward slice 和局部数据流证据往往不完整，过早生成 CTPC 容易误修。

### CVE-2026-24486 / python-multipart

真实链路：

```text
source filename
-> FormParser(..., file_name=filename, config=config)
-> callbacks["on_start"] = on_start
-> parser.write(...)
-> on_start()
-> FileClass(file_name, ...)
-> File._get_disk_file()
-> path = os.path.join(file_dir, fname)
-> open(path, "w+b")
```

断链判断：

```text
source 命中：是
sink 命中：是，open(path, ...)
调用边缺口：parser.write 到 callbacks["on_start"] 的隐式调用边缺失
数据流缺口：闭包捕获 file_name、FileClass 构造、fname/path 拼接传播不足
主分类：Mixed Case
```

修复策略：

```text
CCEC first:
  parser.write(...) -> callbacks["on_start"] / on_start()
  on_start() -> FileClass(file_name, ...)

rerun:
  检查 source frontier 是否进入 File / _get_disk_file

CTPC second:
  closure capture: file_name -> on_start.file_name
  constructor field: File(file_name) -> self._file_name / fname
  path join: os.path.join(file_dir, fname) -> path
```

### CVE-2025-55156 / pyLoad

真实链路：

```text
source url
-> data = [("name", 1, 2, url)]
-> db.update_link_info(data)
-> statuses = "','".join(x[3] for x in data)
-> self.c.execute(f"...{statuses}...")
```

断链判断：

```text
source 命中：是
sink 命中：是，self.c.execute(...)
调用边缺口：db receiver 的具体类 / update_link_info 方法体展开不足
数据流缺口：data[*][3]、generator、join、f-string SQL 传播不足
主分类：Mixed Case
```

修复策略：

```text
CCEC first:
  db.update_link_info(data) -> FileDatabase.update_link_info(data)

rerun:
  检查 source frontier 是否进入 update_link_info 方法体

CTPC second:
  list/tuple element: data[*][3] 继承 url 污点
  generator: x[3] for x in data 继承 element 污点
  join: "','".join(...) 传播到 statuses
  f-string: statuses 传播到 SQL string
```

## 5. 对照组：不应修复的完整样本

### CVE-2023-4033 / MLflow

YASA upstream 已经能从 source 走到真实命令执行 sink：

```text
predict.callback(...)
-> get_flavor_backend(...).predict(...)
-> PyFuncBackend.predict(...)
-> command.format(...)
-> Environment.execute(command)
-> subprocess.Popen(cmd)
```

这个 case 的用途不是修复，而是验证 Evidence Gate：

```text
1. 如果 baseline 已经 reported，应输出 already_reported / no_repair。
2. 不应为了演示流程继续补边或补数据流。
3. 可作为框架 dispatch 正例，帮助对比其他工具的断链。
```

## 6. 实验执行顺序

建议按风险和可控性逐步跑通：

```text
Phase 1:
  对 6 个 CVE 跑 Evidence Gate + Gap Diagnosis。

Phase 2:
  先跑 propagation_gap：
    CVE-2024-36039 / PyMySQL
  目标：复用已有 CTPC 数据流修复闭环。

Phase 3:
  再跑 connectivity_gap：
    CVE-2023-24816 / IPython
    CVE-2024-27758 / RPyC
  目标：补 CCEC 候选调用边契约。

Phase 4:
  最后跑 mixed_case：
    CVE-2026-24486 / python-multipart
    CVE-2025-55156 / pyLoad
  目标：验证“先 CCEC，重跑，再 CTPC”的顺序。

Phase 5:
  跑 MLflow 对照组。
  目标：确认系统不会把已报 finding 的 case 当成待修复样本。
```

## 7. 每个 case 的产物目录建议

```text
LAPIS/LAPIS-Experiments/cases/<case-id>/
  evidence/
    evidence_gate.json
    evidence_bundle.json
    gap_diagnosis.json
  ccec/
    candidate_edges.json
    candidate_contracts.json
    validation_samples.json
    accepted_contracts.json
  ctpc/
    candidate_contracts.json
    validation_samples.json
    accepted_contracts.json
  repaired-runs/
    baseline/
    ccec/
    ctpc/
    mixed-final/
```

注意：不是所有 case 都会生成 `ccec/` 和 `ctpc/`。缺失数据流样本只需要 CTPC；缺失调用边样本优先只需要 CCEC；Mixed Case 才需要两个阶段。

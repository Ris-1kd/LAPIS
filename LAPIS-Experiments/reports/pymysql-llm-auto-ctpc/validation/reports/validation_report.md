# LAPIS CTPC Validation Report

- Status: `accepted`
- CTPC: `LAPIS/LAPIS-Experiments/reports/pymysql-llm-auto-ctpc/ctpc/ctpc.json`
- Validation dir: `LAPIS/LAPIS-Experiments/reports/pymysql-llm-auto-ctpc/validation`

## Three-Way Samples

### must-flow - PASS

- Expected: `finding`
- Predicted: `finding`
- Syntax OK: `True`
- Features: `{"source_hit": true, "sink_hit": true, "tainted_names": ["key"], "dict_vars_with_tainted_key": ["args"], "dict_vars_with_tainted_value": [], "escaped_vars_preserving_keys": ["escaped"], "formatted_query_vars": ["query"], "kill_guard": false}`

### must-not-flow - PASS

- Expected: `no_finding`
- Predicted: `no_finding`
- Syntax OK: `True`
- Features: `{"source_hit": true, "sink_hit": true, "tainted_names": ["unrelated"], "dict_vars_with_tainted_key": [], "dict_vars_with_tainted_value": [], "escaped_vars_preserving_keys": [], "formatted_query_vars": [], "kill_guard": false}`

### must-kill - PASS

- Expected: `no_finding`
- Predicted: `no_finding`
- Syntax OK: `True`
- Features: `{"source_hit": true, "sink_hit": true, "tainted_names": ["key"], "dict_vars_with_tainted_key": ["args"], "dict_vars_with_tainted_value": [], "escaped_vars_preserving_keys": ["escaped"], "formatted_query_vars": ["query"], "kill_guard": true}`

## Propagation Edge Coverage

- `key -> keys()[*]`: covered. tainted source variable appears in dict key position
- `args -> keys()[*]`: covered. dict comprehension preserves keys from tainted-key mapping
- `self._escape_args(args, conn) -> value`: covered. percent formatting consumes mapping with preserved tainted keys

## Feedback

- CTPC passes the current three-way structural validation set.

## Next Runner

当前报告使用结构模拟器完成 CTPC 的第一轮闭环验证；下一步将把同一个 validation_report 接口替换为 YASA baseline/enhanced 双运行结果，用真实 finding/no-finding 判决驱动 CTPC 接受、拒绝和反馈迭代。

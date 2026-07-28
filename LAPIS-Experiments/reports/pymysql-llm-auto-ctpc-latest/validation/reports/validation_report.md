# LAPIS CTPC Validation Report

- Status: `accepted`
- CTPC: `LAPIS/LAPIS-Experiments/reports/pymysql-llm-auto-ctpc-latest/ctpc/ctpc/ctpc.json`
- Validation dir: `LAPIS/LAPIS-Experiments/reports/pymysql-llm-auto-ctpc-latest/validation/validation`

## Three-Way Samples

### must-flow - PASS

- Expected: `finding`
- Predicted: `finding`
- Syntax OK: `True`
- Features: `{"source_hit": true, "sink_hit": true, "tainted_names": ["key"], "dict_vars_with_tainted_key": ["args"], "dict_vars_with_tainted_value": [], "escaped_vars_preserving_keys": [], "formatted_query_vars": ["query"], "filesystem_path_vars": [], "filesystem_sink_hit": false, "filesystem_features": {"constructor_keyword_capture": false, "file_name_split": false, "file_attrs_assigned": false, "fname_from_file_attrs": false, "path_join_with_fname": false, "open_path": false}, "kill_guard": false}`

### must-not-flow - PASS

- Expected: `no_finding`
- Predicted: `no_finding`
- Syntax OK: `True`
- Features: `{"source_hit": true, "sink_hit": true, "tainted_names": ["user"], "dict_vars_with_tainted_key": [], "dict_vars_with_tainted_value": ["args"], "escaped_vars_preserving_keys": [], "formatted_query_vars": [], "filesystem_path_vars": [], "filesystem_sink_hit": false, "filesystem_features": {"constructor_keyword_capture": false, "file_name_split": false, "file_attrs_assigned": false, "fname_from_file_attrs": false, "path_join_with_fname": false, "open_path": false}, "kill_guard": false}`

### must-kill - PASS

- Expected: `no_finding`
- Predicted: `no_finding`
- Syntax OK: `True`
- Features: `{"source_hit": true, "sink_hit": true, "tainted_names": ["user_key"], "dict_vars_with_tainted_key": [], "dict_vars_with_tainted_value": [], "escaped_vars_preserving_keys": [], "formatted_query_vars": [], "filesystem_path_vars": [], "filesystem_sink_hit": false, "filesystem_features": {"constructor_keyword_capture": false, "file_name_split": false, "file_attrs_assigned": false, "fname_from_file_attrs": false, "path_join_with_fname": false, "open_path": false}, "kill_guard": false}`

## Propagation Edge Coverage

- `key -> args.keys()[*]`: covered. tainted source variable appears in dict key position
- `format_mapping.keys()[*] -> query`: covered. percent formatting consumes mapping with preserved tainted keys

## Feedback

- CTPC passes the current three-way structural validation set.

## Next Runner

当前报告使用结构模拟器完成 CTPC 的第一轮闭环验证；下一步将把同一个 validation_report 接口替换为 YASA baseline/enhanced 双运行结果，用真实 finding/no-finding 判决驱动 CTPC 接受、拒绝和反馈迭代。

# LAPIS CTPC Validation Report

- Status: `accepted`
- CTPC: `LAPIS/LAPIS-Experiments/reports/python-multipart-llm-auto-mixed/ctpc/ctpc.json`
- Validation dir: `LAPIS/LAPIS-Experiments/reports/python-multipart-llm-auto-mixed/ctpc-validation/validation`

## Three-Way Samples

### must-flow - PASS

- Expected: `finding`
- Predicted: `finding`
- Syntax OK: `True`
- Features: `{"source_hit": true, "sink_hit": true, "tainted_names": ["filename"], "dict_vars_with_tainted_key": [], "dict_vars_with_tainted_value": [], "escaped_vars_preserving_keys": [], "formatted_query_vars": [], "filesystem_path_vars": ["fname", "parser", "path"], "filesystem_sink_hit": true, "filesystem_features": {"constructor_keyword_capture": true, "file_name_split": true, "file_attrs_assigned": true, "fname_from_file_attrs": true, "path_join_with_fname": true, "open_path": true}, "kill_guard": false}`

### must-not-flow - PASS

- Expected: `no_finding`
- Predicted: `no_finding`
- Syntax OK: `True`
- Features: `{"source_hit": true, "sink_hit": true, "tainted_names": ["filename"], "dict_vars_with_tainted_key": [], "dict_vars_with_tainted_value": [], "escaped_vars_preserving_keys": [], "formatted_query_vars": [], "filesystem_path_vars": ["fname", "path"], "filesystem_sink_hit": true, "filesystem_features": {"constructor_keyword_capture": false, "file_name_split": true, "file_attrs_assigned": true, "fname_from_file_attrs": true, "path_join_with_fname": true, "open_path": true}, "kill_guard": false}`

### must-kill - PASS

- Expected: `no_finding`
- Predicted: `no_finding`
- Syntax OK: `True`
- Features: `{"source_hit": true, "sink_hit": true, "tainted_names": ["filename"], "dict_vars_with_tainted_key": [], "dict_vars_with_tainted_value": [], "escaped_vars_preserving_keys": [], "formatted_query_vars": [], "filesystem_path_vars": ["parser"], "filesystem_sink_hit": false, "filesystem_features": {"constructor_keyword_capture": true, "file_name_split": true, "file_attrs_assigned": true, "fname_from_file_attrs": false, "path_join_with_fname": false, "open_path": true}, "kill_guard": false}`

## Propagation Edge Coverage

- `filename -> FormParser.file_name`: covered. filesystem validation sample propagates source-derived filename/path into sink argument
- `file_name -> self._file_base`: covered. filesystem validation sample propagates source-derived filename/path into sink argument
- `file_name -> self._ext`: covered. filesystem validation sample propagates source-derived filename/path into sink argument
- `self._file_base -> fname`: covered. filesystem validation sample propagates source-derived filename/path into sink argument
- `fname -> path`: covered. filesystem validation sample propagates source-derived filename/path into sink argument
- `path -> path`: covered. filesystem validation sample propagates source-derived filename/path into sink argument
- `file_name -> path`: covered. filesystem validation sample propagates source-derived filename/path into sink argument

## Feedback

- CTPC passes the current three-way structural validation set.

## Next Runner

当前报告使用结构模拟器完成 CTPC 的第一轮闭环验证；下一步将把同一个 validation_report 接口替换为 YASA baseline/enhanced 双运行结果，用真实 finding/no-finding 判决驱动 CTPC 接受、拒绝和反馈迭代。

You are generating validation samples for a CTPC.

Use only the Evidence Pack and CTPC below. Generate small standalone Python
programs. Do not change the CTPC. Do not invent additional source or sink names
unless they are local stubs inside the validation program.

Goal:
- Generate one must-flow sample where the CTPC should recover a finding.
- Generate one must-not-flow sample where a nearby unsupported access path should
  not produce a finding.
- Generate one must-kill sample where a guard/sanitizer should prevent the risky
  flow.

Return one JSON object with this exact top-level shape:

{
  "must_flow": {
    "name": "string",
    "expected": "finding",
    "code": "string"
  },
  "must_not_flow": {
    "name": "string",
    "expected": "no_finding",
    "code": "string"
  },
  "must_kill": {
    "name": "string",
    "expected": "no_finding",
    "code": "string"
  },
  "notes": ["string"]
}

Evidence Pack and CTPC:

```json
{
  "evidence_pack": {
    "case_id": "cve-2026-24486-python-multipart",
    "project": "python-multipart",
    "vulnerability": "path traversal / arbitrary file overwrite",
    "baseline_status": {
      "source_hit": true,
      "sink_hit": true,
      "call_context_reachable": true,
      "complete_taint_path_found": false,
      "sources_marked": 2,
      "sinks_matched": 12,
      "findings": 0,
      "entrypoints": 1
    },
    "source": {
      "file": "poc/poc_cve_2026_24486_python_multipart.py",
      "line": 9,
      "symbol": "filename",
      "expr": "filename = cve_2026_24486_source()",
      "path": "/home/ubuntu/llm-yasa-repair/py-bench/cve-2026-24486-python-multipart/poc/poc_cve_2026_24486_python_multipart.py",
      "observed": "filename = cve_2026_24486_source()",
      "matches_anchor": true
    },
    "sink": {
      "file": "multipart.py",
      "line": 478,
      "callee": "open",
      "argument": "path",
      "expr": "open(path, \"w+b\")",
      "path": "/home/ubuntu/llm-yasa-repair/py-bench/cve-2026-24486-python-multipart/python_multipart/multipart.py",
      "observed": "tmp_file = open(path, \"w+b\")",
      "matches_anchor": false
    },
    "source_forward_slice": {
      "source": "filename",
      "reached": [
        "filename"
      ],
      "frontier": "FormParser(..., file_name=filename)",
      "observations": [
        {
          "label": "source return is assigned to filename",
          "file": "poc/poc_cve_2026_24486_python_multipart.py",
          "line": 9,
          "code": "filename = cve_2026_24486_source()"
        },
        {
          "label": "filename is passed as FormParser file_name keyword",
          "file": "poc/poc_cve_2026_24486_python_multipart.py",
          "line": 20,
          "code": "file_name=filename,"
        }
      ]
    },
    "sink_backward_slice": {
      "sink": "open(path, \"w+b\")",
      "argument": "path",
      "dependency_chain": [
        "path",
        "fname",
        "self._file_base",
        "self._ext"
      ],
      "observations": [
        {
          "label": "open consumes path",
          "file": "python_multipart/multipart.py",
          "line": 478,
          "code": "tmp_file = open(path, \"w+b\")"
        },
        {
          "label": "path depends on fname",
          "file": "python_multipart/multipart.py",
          "line": 475,
          "code": "path = os.path.join(file_dir, fname)  # type: ignore[arg-type]"
        },
        {
          "label": "fname depends on _file_base/_ext",
          "file": "python_multipart/multipart.py",
          "line": 473,
          "code": "fname = self._file_base + self._ext if keep_extensions else self._file_base"
        }
      ]
    },
    "local_structure_evidence": {
      "callback_chain_context": {
        "note": "CCEC stage should repair octet-stream callback dispatch before CTPC is accepted.",
        "facts": [
          {
            "label": "FormParser constructor at public entry",
            "file": "poc/poc_cve_2026_24486_python_multipart.py",
            "line": 16,
            "code": "parser = FormParser("
          },
          {
            "label": "file_name keyword carries the local filename variable",
            "file": "poc/poc_cve_2026_24486_python_multipart.py",
            "line": 20,
            "code": "file_name=filename,"
          },
          {
            "label": "driver invokes parser.write",
            "file": "poc/poc_cve_2026_24486_python_multipart.py",
            "line": 23,
            "code": "return parser.write(b\"file-content\")"
          },
          {
            "label": "OctetStreamParser receives on_start/on_data callbacks",
            "file": "python_multipart/multipart.py",
            "line": 1578,
            "code": "parser = OctetStreamParser("
          },
          {
            "label": "FormParser.write delegates to self.parser.write",
            "file": "python_multipart/multipart.py",
            "line": 1765,
            "code": "return self.parser.write(data)"
          }
        ],
        "post_ccec_virtual_sink_requirement": {
          "boundary_callee": "parser.write",
          "boundary_argument": "data bytes are not the filename source",
          "risk_fact_available_at_boundary": "file_name/filename-derived path fact",
          "virtual_final_sink": "open",
          "reason": "If the analyzer still cannot materialize callback bodies after CCEC validation, CTPC must bind the observed parser.write boundary to the local final filesystem sink using pattern.virtual_final_sink."
        }
      },
      "access_path_evidence": [
        {
          "label": "File.__init__ accepts file_name",
          "file": "python_multipart/multipart.py",
          "line": 360,
          "code": "def __init__(self, file_name: bytes | None, field_name: bytes | None = None, config: FileConfig = {}) -> None:"
        },
        {
          "label": "constructor branches when file_name is provided",
          "file": "python_multipart/multipart.py",
          "line": 377,
          "code": "if file_name is not None:"
        },
        {
          "label": "os.path.splitext splits file_name into base/ext",
          "file": "python_multipart/multipart.py",
          "line": 378,
          "code": "base, ext = os.path.splitext(file_name)"
        },
        {
          "label": "self._file_base stores base",
          "file": "python_multipart/multipart.py",
          "line": 379,
          "code": "self._file_base = base"
        },
        {
          "label": "self._ext stores ext",
          "file": "python_multipart/multipart.py",
          "line": 380,
          "code": "self._ext = ext"
        },
        {
          "label": "keep_filename guard enables filename preservation",
          "file": "python_multipart/multipart.py",
          "line": 468,
          "code": "if file_dir is not None and keep_filename:"
        },
        {
          "label": "fname is derived from self._file_base/self._ext",
          "file": "python_multipart/multipart.py",
          "line": 473,
          "code": "fname = self._file_base + self._ext if keep_extensions else self._file_base"
        },
        {
          "label": "path is os.path.join(file_dir, fname)",
          "file": "python_multipart/multipart.py",
          "line": 475,
          "code": "path = os.path.join(file_dir, fname)  # type: ignore[arg-type]"
        },
        {
          "label": "open consumes path",
          "file": "python_multipart/multipart.py",
          "line": 478,
          "code": "tmp_file = open(path, \"w+b\")"
        }
      ],
      "supported_pattern_hints": [
        "constructor_keyword_capture for FormParser(..., file_name=filename)",
        "direct_assignment for self._file_base/self._ext/fname/path locals derived from filename facts",
        "path_join_keep_filename for os.path.join(file_dir, fname)",
        "filesystem_path_assignment for assigning a derived path local",
        "filesystem_sink_argument for open(path, ...)",
        "filesystem_sink_argument with pattern.callee=parser.write and pattern.virtual_final_sink=open when post-CCEC callback body remains virtual"
      ],
      "negative_evidence": [
        "UPLOAD_KEEP_FILENAME must be true for the original filename to be preserved.",
        "Without file_name, File.__init__ generates a temporary filename rather than preserving user filename.",
        "The CTPC should not treat parser.write(data) bytes as the filename source."
      ]
    },
    "local_convergence": {
      "object": "File/FormParser filename access path",
      "access_path": "file_name -> self._file_base/self._ext -> fname -> path",
      "source_frontier": "FormParser(..., file_name=filename)",
      "sink_dependency_node": "open(path)",
      "is_converged": true
    },
    "top_k_edges": [
      {
        "from": "filename",
        "to": "FormParser.file_name",
        "kind": "constructor_keyword_capture",
        "evidence": "poc passes file_name=filename"
      },
      {
        "from": "file_name",
        "to": "self._file_base/self._ext",
        "kind": "direct_assignment",
        "evidence": "File.__init__ splits and stores file_name parts"
      },
      {
        "from": "fname",
        "to": "path",
        "kind": "path_join_keep_filename",
        "evidence": "path = os.path.join(file_dir, fname)"
      }
    ]
  },
  "ctpc": {
    "schema_version": "ctpc.v2",
    "contract_name": "python_multipart_preserve_filename_path_flow",
    "gap_type": [
      "missing_access_path_propagation"
    ],
    "applies_to": {
      "language": "python",
      "risk_kind": "filesystem_path"
    },
    "fact_types": [
      {
        "name": "fs.path",
        "shape": {
          "access_path": "string"
        }
      }
    ],
    "propagation_edges": [
      {
        "edge_id": "kw_capture_formparser_file_name",
        "event": "function_call",
        "pattern": {
          "kind": "constructor_keyword_capture",
          "callee": "FormParser",
          "argument_index": 0
        },
        "from": {
          "fact": "fs.path",
          "expr": "filename"
        },
        "to": {
          "fact": "fs.path",
          "expr": "file_name",
          "access_path": "file_name",
          "risk_kind": "filesystem_path"
        },
        "evidence": {
          "file": "poc/poc_cve_2026_24486_python_multipart.py",
          "line": 20,
          "code": "file_name=filename,"
        },
        "description": "Capture the user-controlled filename passed via the FormParser constructor keyword 'file_name'."
      },
      {
        "edge_id": "file_name_to_file_base",
        "event": "assignment",
        "pattern": {
          "kind": "direct_assignment",
          "argument_index": 0
        },
        "from": {
          "fact": "fs.path",
          "expr": "file_name"
        },
        "to": {
          "fact": "fs.path",
          "expr": "self._file_base",
          "access_path": "self._file_base",
          "risk_kind": "filesystem_path"
        },
        "evidence": {
          "file": "python_multipart/multipart.py",
          "line": 379,
          "code": "self._file_base = base"
        },
        "description": "File.__init__ stores the split base from file_name into self._file_base; taint from file_name should reach self._file_base."
      },
      {
        "edge_id": "file_name_to_file_ext",
        "event": "assignment",
        "pattern": {
          "kind": "direct_assignment",
          "argument_index": 0
        },
        "from": {
          "fact": "fs.path",
          "expr": "file_name"
        },
        "to": {
          "fact": "fs.path",
          "expr": "self._ext",
          "access_path": "self._ext",
          "risk_kind": "filesystem_path"
        },
        "evidence": {
          "file": "python_multipart/multipart.py",
          "line": 380,
          "code": "self._ext = ext"
        },
        "description": "File.__init__ stores the split extension from file_name into self._ext; taint from file_name should reach self._ext."
      },
      {
        "edge_id": "file_base_to_fname",
        "event": "assignment",
        "pattern": {
          "kind": "direct_assignment",
          "argument_index": 0
        },
        "from": {
          "fact": "fs.path",
          "expr": "self._file_base"
        },
        "to": {
          "fact": "fs.path",
          "expr": "fname",
          "access_path": "fname",
          "risk_kind": "filesystem_path"
        },
        "evidence": {
          "file": "python_multipart/multipart.py",
          "line": 473,
          "code": "fname = self._file_base + self._ext if keep_extensions else self._file_base"
        },
        "description": "fname is derived from preserved filename parts; propagate from self._file_base to fname."
      },
      {
        "edge_id": "fname_to_path_join_guarded",
        "event": "function_call",
        "pattern": {
          "kind": "path_join_keep_filename",
          "argument_index": 1
        },
        "from": {
          "fact": "fs.path",
          "expr": "fname"
        },
        "to": {
          "fact": "fs.path",
          "expr": "path",
          "access_path": "path",
          "risk_kind": "filesystem_path"
        },
        "evidence": {
          "file": "python_multipart/multipart.py",
          "line": 475,
          "code": "path = os.path.join(file_dir, fname)  # type: ignore[arg-type]"
        },
        "description": "Under the keep-filename guard (and file_dir is not None), propagate preserved filename into the joined filesystem path."
      },
      {
        "edge_id": "path_to_open_sink",
        "event": "sink",
        "pattern": {
          "kind": "filesystem_sink_argument",
          "callee": "open",
          "argument_index": 0
        },
        "from": {
          "fact": "fs.path",
          "expr": "path"
        },
        "to": {
          "fact": "fs.path",
          "expr": "$arg0",
          "access_path": "$arg0",
          "risk_kind": "filesystem_path"
        },
        "evidence": {
          "file": "python_multipart/multipart.py",
          "line": 478,
          "code": "tmp_file = open(path, \"w+b\")"
        },
        "description": "The constructed path is used as the filesystem sink argument to open()."
      },
      {
        "edge_id": "virtual_sink_at_parser_write",
        "event": "sink",
        "pattern": {
          "kind": "filesystem_sink_argument",
          "callee": "parser.write",
          "argument_index": 0,
          "virtual_final_sink": "open"
        },
        "from": {
          "fact": "fs.path",
          "expr": "file_name"
        },
        "to": {
          "fact": "fs.path",
          "expr": "$arg0",
          "access_path": "$arg0",
          "risk_kind": "filesystem_path"
        },
        "evidence": {
          "file": "python_multipart/multipart.py",
          "line": 1765,
          "code": "return self.parser.write(data)"
        },
        "description": "Bridges the callback boundary when bodies cannot be materialized post-CCEC: the filename-derived path fact present on the parser instance flows to the local final sink open() triggered by parser.write. Does not treat 'data' bytes as source."
      }
    ],
    "function_summaries": [],
    "risk_upgrades": [],
    "kill_conditions": [],
    "validation_expectations": {
      "must_flow": "finding",
      "must_not_flow": "no_finding",
      "must_kill": "no_finding"
    },
    "description": "Repairs missing access-path propagation for preserved filenames in python-multipart. The user-controlled filename provided as FormParser(..., file_name=filename) is split and stored as self._file_base/self._ext, assembled into fname under keep-filename guards, joined into a filesystem path, and passed to open(path, ...). The CTPC adds constructor keyword capture, direct assignments into internal fields, guarded join semantics, and a filesystem sink edge. If callback bodies remain opaque after CCEC, an additional virtual sink edge binds the observed parser.write boundary to the local open() sink without treating data bytes as a source, aligning with the evidence.",
    "notes": [
      "Propagation honors the keep-filename structure via the path_join_keep_filename pattern, which is only active when file_dir is not None and keep_filename is true.",
      "Without file_name, the library generates temporary names; this CTPC only activates when file_name is supplied.",
      "The virtual sink on parser.write is used only to bridge callback dispatch when bodies cannot be materialized; it leverages the existing filename-derived fact on the parser instance and points to the observed open() sink."
    ]
  }
}
```

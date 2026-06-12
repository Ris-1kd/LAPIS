"""Prompt construction for LAPIS synthesis steps."""

from __future__ import annotations

import json
from typing import Any


def _compact_evidence(evidence: dict[str, Any]) -> dict[str, Any]:
    return {
        "case_id": evidence["case_id"],
        "project": evidence["project"],
        "vulnerability": evidence["vulnerability"],
        "baseline_status": evidence["baseline_status"],
        "source": evidence["source"],
        "sink": evidence["sink"],
        "source_forward_slice": evidence["source_forward_slice"],
        "sink_backward_slice": evidence["sink_backward_slice"],
        "local_structure_evidence": evidence["local_structure_evidence"],
        "local_convergence": evidence["local_convergence"],
        "top_k_edges": evidence["top_k_edges"],
    }


def build_ctpc_prompt(evidence: dict[str, Any]) -> str:
    """Build a deterministic prompt for CTPC synthesis only."""

    evidence_json = json.dumps(_compact_evidence(evidence), indent=2, ensure_ascii=False)

    return f"""You are synthesizing a Conditional Taint Propagation Contract (CTPC).

Use only the Evidence Pack below. Do not invent source functions, sink functions,
variables, files, or edges that are not supported by the evidence.

Goal:
- Explain the missing access-path propagation.
- Synthesize a CTPC that propagates only under the structural guards supported
  by the evidence.
- Do not generate validation programs in this step. Validation sample generation
  is handled by a separate module.

Return one JSON object with this exact top-level shape. Conditions must be
machine-readable: use event + pattern + effect fields. Keep natural-language
explanations only in description/evidence fields.

{{
  "schema_version": "ctpc.v2",
  "contract_name": "string",
  "gap_type": ["string"],
  "applies_to": {{
    "language": "python",
    "risk_kind": "string"
  }},
  "fact_types": [
    {{
      "name": "string",
      "shape": {{"access_path": "string"}}
    }}
  ],
  "propagation_edges": [
    {{
      "edge_id": "string",
      "event": "assignment | binary_operation | function_call | return | member_access | if_condition | sink",
      "pattern": {{"kind": "string"}},
      "from": {{"fact": "string", "expr": "string"}},
      "to": {{"fact": "string", "expr": "string", "access_path": "string", "risk_kind": "string"}},
      "evidence": {{"file": "string", "line": 0, "code": "string"}},
      "description": "string"
    }}
  ],
  "function_summaries": [
    {{
      "summary_id": "string",
      "event": "function_call | return",
      "pattern": {{
        "kind": "return_fact_from_argument",
        "callee": "string",
        "argument_index": 0,
        "receiver_policy": "any | exact"
      }},
      "from": {{"fact": "string", "expr": "$arg0.access_path"}},
      "to": {{"fact": "string", "expr": "$return", "access_path": "$return.access_path", "risk_kind": "string"}},
      "evidence": {{"file": "string", "line": 0, "code": "string"}}
    }}
  ],
  "risk_upgrades": [
    {{
      "upgrade_id": "string",
      "event": "assignment | binary_operation | function_call | return | member_access | sink",
      "pattern": {{"kind": "string"}},
      "from": {{"fact": "string", "expr": "string"}},
      "to": {{"fact": "string", "expr": "string"}},
      "risk_kind": "string"
    }}
  ],
  "kill_conditions": [
    {{
      "kill_id": "string",
      "event": "if_condition | assignment | function_call | sink",
      "pattern": {{"kind": "string"}},
      "effect": {{"action": "suppress", "risk_kind": "string", "for_fact": "string"}},
      "evidence": {{"file": "string", "line": 0, "code": "string"}}
    }}
  ],
  "validation_expectations": {{
    "must_flow": "finding",
    "must_not_flow": "no_finding",
    "must_kill": "no_finding"
  }},
  "description": "string",
  "notes": ["string"]
}}

Evidence Pack:

```json
{evidence_json}
```
"""


def build_validation_prompt(evidence: dict[str, Any], ctpc: dict[str, Any]) -> str:
    """Build a deterministic prompt for validation sample generation."""

    payload = {
        "evidence_pack": _compact_evidence(evidence),
        "ctpc": ctpc,
    }
    payload_json = json.dumps(payload, indent=2, ensure_ascii=False)

    return f"""You are generating validation samples for a CTPC.

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

{{
  "must_flow": {{
    "name": "string",
    "expected": "finding",
    "code": "string"
  }},
  "must_not_flow": {{
    "name": "string",
    "expected": "no_finding",
    "code": "string"
  }},
  "must_kill": {{
    "name": "string",
    "expected": "no_finding",
    "code": "string"
  }},
  "notes": ["string"]
}}

Evidence Pack and CTPC:

```json
{payload_json}
```
"""

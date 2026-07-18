import json
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase

from lapis.prompt import _static_ccec_evidence


class CcecPromptEvidenceTests(TestCase):
    def test_auto_discovers_dynamic_getattr_factory_sink_edges(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            dataset = root / "dataset"
            dataset.mkdir()
            (dataset / "poc.py").write_text(
                "\n".join(
                    [
                        "from netref import class_factory",
                        "",
                        "def coerce(obj):",
                        "    array_callback = getattr(obj, \"__array__\")",
                        "    return array_callback()",
                        "",
                        "def driver():",
                        "    cls = class_factory((\"remote.T\", 1, 0), [(\"__array__\", \"array protocol\")])",
                        "    return coerce(cls())",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            (dataset / "netref.py").write_text(
                "\n".join(
                    [
                        "import pickle",
                        "",
                        "def _make_method(name, doc):",
                        "    if name == \"__array__\":",
                        "        def __array__(self):",
                        "            return pickle.loads(blob)",
                        "        return __array__",
                        "",
                        "def class_factory(id_pack, methods):",
                        "    ns = {}",
                        "    for name, doc in methods:",
                        "        ns[name] = _make_method(name, doc)",
                        "    return type(\"T\", (), ns)",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            rule_file = root / "rules.json"
            rule_file.write_text(
                json.dumps(
                    [
                        {
                            "sinks": {
                                "FuncCallTaintSink": [
                                    {
                                        "fsig": "pickle.loads",
                                        "args": ["0"],
                                    }
                                ]
                            }
                        }
                    ]
                )
                + "\n",
                encoding="utf-8",
            )

            evidence = _static_ccec_evidence({"dataset_dir": str(dataset), "rule_file": str(rule_file)})

        self.assertIsNotNone(evidence)
        self.assertEqual(evidence["kind"], "dynamic_getattr_factory_method_evidence")
        self.assertEqual(evidence["observed_callsite"]["expr"], "array_callback()")
        self.assertEqual(evidence["observed_callsite"]["attribute_name"], "__array__")
        edges = evidence["suggested_virtual_edges"]
        self.assertEqual(len(edges), 2)
        self.assertEqual(edges[0]["boundary_callsite"], "array_callback()")
        self.assertEqual(edges[0]["callee_kind"], "materialized_factory_method")
        self.assertEqual(edges[1]["callee"], "pickle.loads")
        self.assertEqual(edges[1]["callee_kind"], "builtin_sink")

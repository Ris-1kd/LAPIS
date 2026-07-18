from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase
from unittest.mock import patch

from lapis.automation import run_llm_feasibility_suite
from lapis.llm import LLMConfig


class LLMFeasibilitySuiteTests(TestCase):
    def test_writes_blocked_report_when_llm_smoke_fails(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            out_dir = root / "out"
            cases_root = root / "cases"
            cases_root.mkdir()
            config = LLMConfig(api_key="test-key", base_url="https://llm-api.net/v1", model="gpt-5")

            with patch(
                "lapis.automation._dns_preflight",
                return_value={"status": "failed", "error": "dns timeout"},
            ), patch("lapis.automation.chat_json", side_effect=RuntimeError("should not be called")):
                report = run_llm_feasibility_suite(
                    tool_dir=root / "tool",
                    cases_root=cases_root,
                    out_dir=out_dir,
                    uast_sdk_path=root / "uast4py",
                    llm_config=config,
                )

            self.assertEqual(report["status"], "blocked_llm_unreachable")
            self.assertEqual(report["llm"]["smoke_test"]["status"], "failed")
            self.assertTrue((out_dir / "llm_feasibility_report.json").exists())
            self.assertTrue((out_dir / "llm_feasibility_report.md").exists())

    def test_falls_back_to_global_base_url_for_dataset_run(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            out_dir = root / "out"
            cases_root = root / "cases"
            cases_root.mkdir()
            config = LLMConfig(api_key="test-key", base_url="https://llm-api.net/v1", model="gpt-5")
            suite_report = {
                "schema_version": "lapis.end_to_end_suite.v1",
                "cases_root": str(cases_root),
                "out_dir": str(out_dir / "e2e"),
                "case_count": 0,
                "cases": [],
            }

            with patch(
                "lapis.automation.chat_json",
                side_effect=[RuntimeError("dns failure"), {"ok": True, "message": "ready"}],
            ), patch(
                "lapis.automation._dns_preflight",
                return_value={"status": "passed", "addresses": ["203.0.113.10"]},
            ), patch("lapis.automation.run_end_to_end_cases", return_value=suite_report) as run_suite:
                report = run_llm_feasibility_suite(
                    tool_dir=root / "tool",
                    cases_root=cases_root,
                    out_dir=out_dir,
                    uast_sdk_path=root / "uast4py",
                    llm_config=config,
                )

            self.assertEqual(report["status"], "completed")
            self.assertEqual(report["llm"]["selected_base_url"], "https://api.n1n.ai/v1")
            self.assertEqual(run_suite.call_args.kwargs["llm_config"].base_url, "https://api.n1n.ai/v1")

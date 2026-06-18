from __future__ import annotations

import copy
import json
import sys
import unittest
from pathlib import Path


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PLUGIN_ROOT / "runner"))

import runner  # noqa: E402


def load_input(name: str) -> dict:
    with (PLUGIN_ROOT / "examples" / name).open("r", encoding="utf-8") as handle:
        return json.load(handle)


class RunnerTests(unittest.TestCase):
    def test_fixture_import_filters_medium_and_blocked_templates(self) -> None:
        output = runner.run(load_input("input.fixture.json"))
        self.assertEqual(output["source"], "nuclei-adapter-plus")
        self.assertEqual(output["format"], "nuclei_jsonl")
        self.assertEqual(len(output["results"]), 1)
        self.assertEqual(output["summary"]["skipped_record_count"], 2)
        result = output["results"][0]
        self.assertEqual(result["template_severity"], "low")
        self.assertEqual(result["template_id"], "http-missing-security-header")
        self.assertIn("token=[REDACTED]", result["description"])
        self.assertIsNone(result["curl_command"])
        self.assertEqual(output["safety"]["scanner_invocations"], 0)

    def test_approved_medium_import_includes_medium_but_still_blocks_intrusive(self) -> None:
        output = runner.run(load_input("input.approved-medium.json"))
        self.assertEqual(len(output["results"]), 2)
        severities = {item["template_severity"] for item in output["results"]}
        self.assertEqual(severities, {"low", "medium"})
        self.assertEqual(output["summary"]["skipped_record_count"], 1)
        medium = [item for item in output["results"] if item["template_severity"] == "medium"][0]
        self.assertIn("CVE-2026-3001", medium["cve"])

    def test_medium_severity_allowlist_requires_explicit_approval(self) -> None:
        payload = copy.deepcopy(load_input("input.fixture.json"))
        payload["options"]["templates"]["allowed_severities"].append("medium")
        with self.assertRaises(runner.InputError):
            runner.run(payload)

    def test_dry_run_does_not_read_results(self) -> None:
        payload = load_input("input.fixture.json")
        payload["options"]["mode"] = "dry_run"
        output = runner.run(payload)
        self.assertEqual(output["results"], [])
        self.assertEqual(output["summary"]["imported_record_count"], 0)

    def test_rejects_path_traversal(self) -> None:
        payload = copy.deepcopy(load_input("input.fixture.json"))
        payload["options"]["import"]["file"] = "../Cargo.toml"
        with self.assertRaises(runner.InputError):
            runner.run(payload)


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PLUGIN_ROOT / "runner"))

import runner  # noqa: E402


def load_input(name: str) -> dict:
    with (PLUGIN_ROOT / "examples" / name).open("r", encoding="utf-8") as handle:
        return json.load(handle)


class RunnerTests(unittest.TestCase):
    def test_json_import_deduplicates_and_filters_false_positive(self) -> None:
        output = runner.run(load_input("input.fixture.json"))
        self.assertEqual(output["source"], "zap-baseline-plus")
        self.assertEqual(output["format"], "zap_json")
        self.assertEqual(len(output["results"]), 1)
        self.assertEqual(output["summary"]["skipped_record_count"], 2)
        result = output["results"][0]
        self.assertEqual(result["alert_id"], "10020")
        self.assertEqual(result["risk"], "low")
        self.assertIn("token=[REDACTED]", result["description"])
        self.assertIsNone(result["attack"])
        self.assertEqual(output["safety"]["scanner_invocations"], 0)

    def test_xml_import_normalizes_and_redacts_evidence(self) -> None:
        output = runner.run(load_input("input.xml-fixture.json"))
        self.assertEqual(len(output["results"]), 1)
        result = output["results"][0]
        self.assertEqual(result["alert_id"], "10021")
        self.assertEqual(result["confidence_label"], "high")
        self.assertEqual(result["cwe_id"], 693)
        self.assertIn("Bearer [REDACTED]", result["evidence_text"])

    def test_risk_filter_excludes_low_alert(self) -> None:
        payload = copy.deepcopy(load_input("input.fixture.json"))
        payload["options"]["filters"]["minimum_risk"] = "medium"
        output = runner.run(payload)
        self.assertEqual(output["results"], [])
        self.assertEqual(output["summary"]["skipped_record_count"], 3)

    def test_zero_limit_and_evidence_omission_are_enforced(self) -> None:
        payload = copy.deepcopy(load_input("input.fixture.json"))
        payload["options"]["import"]["max_records"] = 0
        self.assertEqual(runner.run(payload)["results"], [])

        payload["options"]["import"]["max_records"] = 100
        payload["options"]["output"]["include_evidence"] = False
        result = runner.run(payload)["results"][0]
        self.assertIsNone(result["evidence_text"])
        self.assertEqual(result["evidence"]["items"], [])

    def test_dry_run_does_not_read_report(self) -> None:
        payload = load_input("input.fixture.json")
        payload["options"]["mode"] = "dry_run"
        payload["options"]["import"]["file"] = "examples/missing.json"
        output = runner.run(payload)
        self.assertEqual(output["results"], [])
        self.assertEqual(output["summary"]["imported_record_count"], 0)

    def test_rejects_active_scan_policy(self) -> None:
        payload = copy.deepcopy(load_input("input.fixture.json"))
        payload["policy"]["allow_active_scan"] = True
        with self.assertRaises(runner.InputError):
            runner.run(payload)

    def test_rejects_path_traversal(self) -> None:
        payload = copy.deepcopy(load_input("input.fixture.json"))
        payload["options"]["import"]["file"] = "../Cargo.toml"
        with self.assertRaises(runner.InputError):
            runner.run(payload)

    def test_rejects_xml_document_type(self) -> None:
        payload = copy.deepcopy(load_input("input.xml-fixture.json"))
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".xml",
            dir=PLUGIN_ROOT / "examples",
            encoding="utf-8",
        ) as handle:
            handle.write('<!DOCTYPE report [<!ENTITY x "expanded">]><OWASPZAPReport>&x;</OWASPZAPReport>')
            handle.flush()
            payload["options"]["import"]["file"] = f"examples/{Path(handle.name).name}"
            with self.assertRaises(runner.InputError):
                runner.run(payload)


if __name__ == "__main__":
    unittest.main()

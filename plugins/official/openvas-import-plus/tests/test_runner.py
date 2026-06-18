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
    def test_xml_import_maps_vulnerabilities_and_filters_log(self) -> None:
        output = runner.run(load_input("input.fixture.xml.json"))
        self.assertEqual(output["source"], "openvas-import-plus")
        self.assertEqual(output["format"], "openvas_xml")
        self.assertEqual(len(output["results"]), 2)
        severities = {item["severity_label"] for item in output["results"]}
        self.assertEqual(severities, {"medium", "critical"})
        self.assertIn("CVE-2026-1003", output["results"][1]["cve"])
        self.assertIn("token=[REDACTED]", output["results"][1]["description"])
        self.assertEqual(output["safety"]["scanner_invocations"], 0)

    def test_csv_import_is_supported(self) -> None:
        output = runner.run(load_input("input.fixture.csv.json"))
        self.assertEqual(output["results"][0]["severity_label"], "medium")
        self.assertEqual(output["results"][0]["nvt_oid"], "1.3.6.1.4.1.25623.1.0.200001")
        self.assertEqual(output["results"][0]["protocol"], "tcp")

    def test_dry_run_does_not_read_results(self) -> None:
        payload = load_input("input.fixture.xml.json")
        payload["options"]["mode"] = "dry_run"
        output = runner.run(payload)
        self.assertEqual(output["results"], [])
        self.assertEqual(output["summary"]["imported_record_count"], 0)

    def test_rejects_path_traversal(self) -> None:
        payload = copy.deepcopy(load_input("input.fixture.xml.json"))
        payload["options"]["import"]["file"] = "../Cargo.toml"
        with self.assertRaises(runner.InputError):
            runner.run(payload)


if __name__ == "__main__":
    unittest.main()

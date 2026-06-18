from __future__ import annotations

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
    def test_fixture_outputs_exposure_results(self) -> None:
        output = runner.run(load_input("input.fixture.json"))
        self.assertEqual(output["source"], "fofa-import-plus")
        self.assertEqual(len(output["results"]), 2)
        self.assertFalse(output["safety"]["user_query_allowed"])
        self.assertIn("certificate", output["results"][0])

    def test_api_missing_secret_is_graceful_skip(self) -> None:
        output = runner.run(load_input("input.api-missing-secret.json"))
        self.assertEqual(output["results"], [])
        self.assertEqual(output["source_status"][0]["status"], "skipped_missing_secret")
        self.assertFalse(output["safety"]["secret_emitted"])

    def test_rejects_query_metacharacters_in_target(self) -> None:
        payload = load_input("input.fixture.json")
        payload["target"]["value"] = 'example.com" || ip="1.2.3.4'
        with self.assertRaises(runner.InputError):
            runner.run(payload)


if __name__ == "__main__":
    unittest.main()

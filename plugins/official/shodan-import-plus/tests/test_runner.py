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
    def test_fixture_outputs_host_intel(self) -> None:
        output = runner.run(load_input("input.fixture.json"))
        self.assertEqual(output["source"], "shodan-import-plus")
        self.assertEqual(len(output["results"]), 1)
        self.assertEqual(output["results"][0]["ip"], "93.184.216.34")
        self.assertIn("banner", output["results"][0])
        self.assertFalse(output["safety"]["user_query_allowed"])

    def test_api_missing_secret_is_graceful_skip(self) -> None:
        output = runner.run(load_input("input.api-missing-secret.json"))
        self.assertEqual(output["results"], [])
        self.assertEqual(output["source_status"][0]["status"], "skipped_missing_secret")
        self.assertFalse(output["safety"]["secret_emitted"])

    def test_rejects_invalid_ip_scope(self) -> None:
        payload = load_input("input.fixture.json")
        payload["target"]["value"] = "not-an-ip"
        with self.assertRaises(runner.InputError):
            runner.run(payload)


if __name__ == "__main__":
    unittest.main()

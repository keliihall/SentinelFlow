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
    def test_fixture_outputs_fingerprints(self) -> None:
        output = runner.run(load_input("input.fixture.json"))
        technologies = {item["technology"] for item in output["results"]}
        self.assertIn("WordPress", technologies)
        self.assertIn("Grafana", technologies)
        self.assertEqual(output["safety"]["active_http_requests"], 0)

    def test_from_http_probe_observations(self) -> None:
        output = runner.run(load_input("input.from-http-probe.json"))
        self.assertEqual(output["errors"], [])
        self.assertIn("WordPress", {item["technology"] for item in output["results"]})

    def test_dry_run_does_not_emit_results(self) -> None:
        payload = load_input("input.fixture.json")
        payload["options"]["mode"] = "dry_run"
        output = runner.run(payload)
        self.assertEqual(output["results"], [])
        self.assertEqual(output["summary"]["observation_count"], 0)


if __name__ == "__main__":
    unittest.main()

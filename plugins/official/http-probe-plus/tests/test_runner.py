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
    def test_fixture_outputs_http_result(self) -> None:
        output = runner.run(load_input("input.fixture.json"))
        self.assertEqual(output["source"], "http-probe-plus")
        self.assertEqual(output["results"][0]["type"], "http_result")
        self.assertEqual(output["results"][0]["source_agreement"], "passive_only")

    def test_active_http_is_p7_disabled(self) -> None:
        payload = load_input("input.fixture.json")
        payload["options"]["mode"] = "active_safe"
        payload["options"]["active"]["enabled"] = True
        output = runner.run(payload)
        self.assertEqual(output["errors"][0]["code"], "P7_SCOPE_DISABLED")
        self.assertEqual(output["source_status"][0]["status"], "skipped_p7_disabled")

    def test_active_http_runner_is_not_called_in_p5_6(self) -> None:
        payload = load_input("input.active-local.json")
        original = runner.run_active_http

        def fail_active(*args, **kwargs):
            raise AssertionError("HTTP probing must not run in P5.6")

        runner.run_active_http = fail_active
        try:
            output = runner.run(payload)
        finally:
            runner.run_active_http = original

        self.assertEqual(output["errors"][0]["code"], "P7_SCOPE_DISABLED")
        self.assertEqual(output["safety"]["active_http_probes"], 0)


if __name__ == "__main__":
    unittest.main()

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
    def test_fixture_outputs_open_port(self) -> None:
        output = runner.run(load_input("input.fixture.json"))
        self.assertEqual(output["source"], "port-probe-plus")
        self.assertEqual(output["results"][0]["port"], 443)
        self.assertEqual(output["results"][0]["source_agreement"], "passive_only")

    def test_active_tcp_connect_is_p7_disabled(self) -> None:
        payload = load_input("input.fixture.json")
        payload["options"]["mode"] = "active_tcp_connect"
        payload["options"]["active"]["enabled"] = True
        output = runner.run(payload)
        self.assertEqual(output["results"], [])
        self.assertEqual(output["errors"][0]["code"], "P7_SCOPE_DISABLED")
        self.assertEqual(output["source_status"][0]["status"], "skipped_p7_disabled")

    def test_tcp_connect_runner_is_not_called_in_p5_6(self) -> None:
        payload = load_input("input.fixture.json")
        payload["options"]["mode"] = "active_tcp_connect"
        payload["options"]["active"]["enabled"] = True
        payload["options"]["active"]["ports"] = [443]
        payload["policy"]["allow_active_verify"] = True

        original = runner.run_tcp_connect

        def fail_connect(*args, **kwargs):
            raise AssertionError("TCP connect must not run in P5.6")

        runner.run_tcp_connect = fail_connect
        try:
            output = runner.run(payload)
        finally:
            runner.run_tcp_connect = original

        self.assertEqual(output["errors"][0]["code"], "P7_SCOPE_DISABLED")
        self.assertEqual(output["safety"]["tcp_connect_probes"], 0)

    def test_no_public_ip_active_request_is_still_p7_disabled(self) -> None:
        payload = load_input("input.fixture.json")
        payload["options"]["mode"] = "active_tcp_connect"
        payload["options"]["active"]["enabled"] = True
        payload["inputs"]["addresses"] = ["198.18.0.75", "127.0.0.1"]
        payload["policy"]["allow_active_verify"] = True

        output = runner.run(payload)

        self.assertEqual(output["results"], [])
        self.assertEqual(output["errors"][0]["code"], "P7_SCOPE_DISABLED")
        self.assertEqual(output["source_status"][0]["status"], "skipped_p7_disabled")


if __name__ == "__main__":
    unittest.main()

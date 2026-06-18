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
    def test_fixture_outputs_certificate_results(self) -> None:
        output = runner.run(load_input("input.fixture.json"))
        self.assertEqual(output["source"], "tls-certificate-check-plus")
        self.assertEqual(len(output["results"]), 2)
        statuses = {item["host"]: item["status"] for item in output["results"]}
        self.assertEqual(statuses["www.example.com"], "valid")
        self.assertEqual(statuses["soon-expire.example.com"], "expires_soon")

    def test_active_policy_denial_skips_handshake(self) -> None:
        payload = load_input("input.active-local.json")
        payload["policy"]["allow_active_verify"] = False
        output = runner.run(payload)
        self.assertEqual(output["results"], [])
        self.assertEqual(output["errors"][0]["code"], "PolicyDenied")
        self.assertEqual(output["source_status"][0]["status"], "skipped_policy_denied")

    def test_dry_run_has_no_results(self) -> None:
        payload = load_input("input.fixture.json")
        payload["options"]["mode"] = "dry_run"
        output = runner.run(payload)
        self.assertEqual(output["results"], [])
        self.assertEqual(output["summary"]["estimated_tls_handshakes"], 0)


if __name__ == "__main__":
    unittest.main()

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
    def test_fixture_outputs_public_ip_enrichment(self) -> None:
        output = runner.run(load_input("input.fixture.json"))
        self.assertEqual(output["source"], "ip-enrichment-plus")
        result = output["results"][0]
        self.assertEqual(result["ip"], "93.184.216.34")
        self.assertEqual(result["classification"], "public")
        self.assertTrue(result["is_public"])
        self.assertEqual(result["asn"], 15133)
        self.assertEqual(result["cdn_waf"]["provider"], "Edgecast")
        self.assertEqual(output["safety"]["active_target_connections"], 0)

    def test_private_ip_is_classified_without_sources(self) -> None:
        output = runner.run(load_input("input.private.json"))
        result = output["results"][0]
        self.assertEqual(result["classification"], "private")
        self.assertFalse(result["is_public"])
        self.assertEqual(result["asn"], None)

    def test_provider_missing_secret_is_graceful_skip(self) -> None:
        output = runner.run(load_input("input.provider-missing-secret.json"))
        statuses = {item["source"]: item["status"] for item in output["source_status"]}
        self.assertEqual(statuses["ipinfo"], "skipped_missing_secret")
        self.assertEqual(statuses["maxmind"], "skipped_missing_secret")
        self.assertFalse(output["safety"]["secret_emitted"])

    def test_rejects_invalid_ip(self) -> None:
        payload = load_input("input.fixture.json")
        payload["target"]["value"] = "not-an-ip"
        with self.assertRaises(runner.InputError):
            runner.run(payload)


if __name__ == "__main__":
    unittest.main()

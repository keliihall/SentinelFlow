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
    def test_fixture_outputs_cleaned_subdomains_and_certificates(self) -> None:
        output = runner.run(load_input("input.fixture.json"))
        self.assertEqual(output["source"], "crtsh-subdomain-plus")
        subdomains = {item["subdomain"] for item in output["findings"]}
        self.assertIn("api.example.com", subdomains)
        self.assertIn("login.example.com", subdomains)
        self.assertIn("www.example.com", subdomains)
        self.assertNotIn("outside.example.net", subdomains)
        self.assertNotIn("old.example.com", subdomains)
        self.assertGreater(output["summary"]["wildcard_cleaned_count"], 0)
        self.assertEqual(len(output["certificates"]), 2)
        self.assertEqual(output["safety"]["active_target_connections"], 0)

    def test_provider_unavailable_is_graceful_skip(self) -> None:
        output = runner.run(load_input("input.api-unavailable.json"))
        self.assertEqual(output["findings"], [])
        self.assertEqual(output["source_status"][0]["status"], "skipped_unavailable")

    def test_rejects_invalid_domain(self) -> None:
        payload = load_input("input.fixture.json")
        payload["target"]["value"] = "not a domain"
        with self.assertRaises(runner.InputError):
            runner.run(payload)

    def test_can_include_expired_when_requested(self) -> None:
        payload = load_input("input.fixture.json")
        payload["options"]["lookup"]["include_expired"] = True
        output = runner.run(payload)
        subdomains = {item["subdomain"] for item in output["findings"]}
        self.assertIn("old.example.com", subdomains)


if __name__ == "__main__":
    unittest.main()

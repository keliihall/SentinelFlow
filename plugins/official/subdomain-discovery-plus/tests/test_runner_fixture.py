from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path
import sys


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PLUGIN_ROOT / "runner"))

import runner  # noqa: E402


def load_input(name: str) -> dict:
    with (PLUGIN_ROOT / "examples" / name).open("r", encoding="utf-8") as handle:
        return json.load(handle)


class RunnerFixtureTests(unittest.TestCase):
    def test_passive_fixture_outputs_expected_subdomains(self) -> None:
        output = runner.run(load_input("input.passive-fixture.json"))

        self.assertEqual(output["source"], "subdomain-discovery-plus")
        self.assertEqual(output["summary"]["active_queries"], 0)
        subdomains = {item["subdomain"] for item in output["findings"]}
        self.assertIn("www.example.com", subdomains)
        self.assertIn("api.example.com", subdomains)
        self.assertIn("docs.example.com", subdomains)
        for item in output["findings"]:
            self.assertEqual(item["domain"], "example.com")
            self.assertIn("passive_fixture", item["sources"])
            self.assertEqual(item["record_type"], "unknown")
            self.assertTrue(item["synthetic_fixture"])
            self.assertFalse(item["real_scan"])

    def test_fixture_target_mismatch_refuses_synthetic_results(self) -> None:
        payload = load_input("input.passive-fixture.json")
        payload = copy.deepcopy(payload)
        payload["target"]["value"] = "weikan.net.cn"
        payload["context"]["authorization_scope"] = "real:weikan-net-cn"

        output = runner.run(payload)

        self.assertEqual(output["findings"], [])
        self.assertEqual(output["errors"][0]["code"], "CONFIG_ERROR")
        self.assertIn("fixture_domain", output["errors"][0]["details"])

    def test_fixture_scope_cannot_be_used_for_real_target(self) -> None:
        payload = load_input("input.active-dictionary.json")
        payload = copy.deepcopy(payload)
        payload["target"]["value"] = "weikan.net.cn"
        payload["context"]["authorization_scope"] = "fixture:local-only"
        payload["options"]["mode"] = "active_dictionary"
        payload["policy"]["allow_active_verify"] = True

        output = runner.run(payload)

        self.assertEqual(output["findings"], [])
        self.assertEqual(output["errors"][0]["code"], "AUTHZ_ERROR")

    def test_dry_run_reports_planned_sources_without_findings(self) -> None:
        payload = load_input("input.active-dictionary.json")
        payload = copy.deepcopy(payload)
        payload["target"]["value"] = "weikan.net.cn"
        payload["context"]["authorization_scope"] = "real:weikan-net-cn"
        payload["options"]["mode"] = "dry_run"

        output = runner.run(payload)

        self.assertEqual(output["mode"], "dry_run")
        self.assertEqual(output["findings"], [])
        self.assertGreater(output["summary"]["candidate_count"], 0)
        self.assertIn("active_dictionary", output["summary"]["planned_sources"])

    def test_active_policy_denial_does_not_query_dns(self) -> None:
        payload = load_input("input.active-dictionary.json")
        payload = copy.deepcopy(payload)
        payload["policy"]["allow_active_verify"] = False

        output = runner.run(payload)

        self.assertEqual(output["summary"]["active_queries"], 0)
        self.assertEqual(output["summary"]["candidate_count"], 0)
        self.assertEqual(output["errors"][0]["code"], "PolicyDenied")
        self.assertEqual(output["findings"], [])

    def test_active_dry_run_reports_candidates_without_queries(self) -> None:
        payload = load_input("input.active-dictionary.json")
        payload = copy.deepcopy(payload)
        payload["options"]["active"]["dry_run"] = True

        output = runner.run(payload)

        self.assertEqual(output["summary"]["candidate_count"], 12)
        self.assertEqual(output["summary"]["active_queries"], 0)
        self.assertEqual(output["findings"], [])

    def test_active_dictionary_uses_dns_results_when_authorized(self) -> None:
        payload = load_input("input.active-dictionary.json")
        payload = copy.deepcopy(payload)
        payload["options"]["active"]["dry_run"] = False
        payload["options"]["active"]["max_candidates"] = 2

        original = runner.resolve_candidate

        def fake_resolve(hostname, record_types, resolvers, timeout):
            if hostname.startswith("sf-"):
                return {"records": [], "query_count": 1}
            return {
                "records": [{"record_type": "A", "value": "93.184.216.34"}],
                "query_count": 1,
            }

        runner.resolve_candidate = fake_resolve
        try:
            output = runner.run(payload)
        finally:
            runner.resolve_candidate = original

        self.assertEqual(output["summary"]["candidate_count"], 2)
        self.assertEqual(output["summary"]["active_queries"], 5)
        self.assertEqual(len(output["findings"]), 2)
        self.assertTrue(all(item["resolved"] for item in output["findings"]))
        self.assertTrue(
            all("active_dictionary" in item["sources"] for item in output["findings"])
        )

    def test_unresolved_dictionary_entries_are_candidates_not_findings(self) -> None:
        payload = load_input("input.active-dictionary.json")
        payload = copy.deepcopy(payload)
        payload["options"]["active"]["dry_run"] = False
        payload["options"]["active"]["max_candidates"] = 3
        payload["options"]["output"]["include_unresolved"] = True
        payload["options"]["passive"]["sources"] = []
        payload["context"]["authorization_scope"] = "real:example-com"

        original = runner.resolve_candidate

        def fake_resolve(hostname, record_types, resolvers, timeout):
            return {"records": [], "query_count": 1}

        runner.resolve_candidate = fake_resolve
        try:
            output = runner.run(payload)
        finally:
            runner.resolve_candidate = original

        self.assertFalse(output["summary"]["synthetic_fixture"])
        self.assertEqual(output["summary"]["candidate_count"], 3)
        self.assertEqual(output["summary"]["finding_count"], 0)
        self.assertEqual(output["summary"]["confirmed_count"], 0)
        self.assertEqual(output["summary"]["candidate_observation_count"], 3)
        self.assertTrue(all(item["type"] == "subdomain_candidate" for item in output["findings"]))
        self.assertTrue(all(item["status"] == "candidate" for item in output["findings"]))
        self.assertTrue(all(item["confidence"] <= 0.15 for item in output["findings"]))


if __name__ == "__main__":
    unittest.main()

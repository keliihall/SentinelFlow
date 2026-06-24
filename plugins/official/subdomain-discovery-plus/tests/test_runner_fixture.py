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
        payload["target"]["value"] = "example.test"
        payload["context"]["authorization_scope"] = "fixture:local-only"

        output = runner.run(payload)

        self.assertEqual(output["findings"], [])
        self.assertEqual(output["errors"][0]["code"], "CONFIG_ERROR")
        self.assertIn("fixture_domain", output["errors"][0]["details"])

    def test_fixture_scope_cannot_relabel_another_fixture_domain(self) -> None:
        payload = load_input("input.active-dictionary.json")
        payload = copy.deepcopy(payload)
        payload["target"]["value"] = "example.test"
        payload["context"]["authorization_scope"] = "fixture:local-only"
        payload["options"]["mode"] = "active_dictionary"
        payload["policy"]["allow_active_verify"] = True

        output = runner.run(payload)

        self.assertEqual(output["findings"], [])
        self.assertEqual(output["errors"][0]["code"], "CONFIG_ERROR")

    def test_dry_run_reports_planned_sources_without_findings(self) -> None:
        payload = load_input("input.active-dictionary.json")
        payload = copy.deepcopy(payload)
        payload["target"]["value"] = "example.test"
        payload["context"]["authorization_scope"] = "fixture:local-only"
        payload["options"]["passive"]["fixture_file"] = "examples/fixture.passive.example.test.json"
        payload["options"]["mode"] = "dry_run"
        payload["options"]["active"]["enabled"] = True

        output = runner.run(payload)

        self.assertEqual(output["mode"], "dry_run")
        self.assertEqual(output["findings"], [])
        self.assertGreater(output["summary"]["candidate_count"], 0)
        self.assertIn("active_dictionary", output["summary"]["planned_sources"])

    def test_active_policy_denial_does_not_query_dns(self) -> None:
        payload = load_input("input.active-dictionary.json")
        payload = copy.deepcopy(payload)
        payload["policy"]["allow_active_verify"] = False
        payload["options"]["active"]["dry_run"] = False

        output = runner.run(payload)

        self.assertEqual(output["summary"]["active_queries"], 0)
        self.assertEqual(output["summary"]["candidate_count"], 0)
        self.assertEqual(output["errors"][0]["code"], "P7_SCOPE_DISABLED")
        self.assertEqual(output["findings"], [])

    def test_active_dry_run_reports_candidates_without_queries(self) -> None:
        payload = load_input("input.active-dictionary.json")
        payload = copy.deepcopy(payload)
        payload["options"]["active"]["enabled"] = True
        payload["options"]["active"]["dry_run"] = True

        output = runner.run(payload)

        self.assertEqual(output["summary"]["candidate_count"], 12)
        self.assertEqual(output["summary"]["active_queries"], 0)
        self.assertEqual(output["findings"], [])

    def test_active_dictionary_non_dry_run_is_p7_disabled(self) -> None:
        payload = load_input("input.active-dictionary.json")
        payload = copy.deepcopy(payload)
        payload["options"]["active"]["dry_run"] = False
        payload["options"]["active"]["max_candidates"] = 2

        output = runner.run(payload)

        self.assertEqual(output["summary"]["active_queries"], 0)
        self.assertEqual(output["summary"]["candidate_count"], 0)
        self.assertEqual(output["errors"][0]["code"], "P7_SCOPE_DISABLED")
        self.assertEqual(output["findings"], [])

    def test_active_dictionary_disabled_before_resolver_query(self) -> None:
        payload = load_input("input.active-dictionary.json")
        payload = copy.deepcopy(payload)
        payload["options"]["active"]["dry_run"] = False
        payload["options"]["active"]["max_candidates"] = 3
        payload["options"]["output"]["include_unresolved"] = True
        payload["options"]["passive"]["sources"] = []

        original = runner.resolve_candidate

        def fake_resolve(hostname, record_types, resolvers, timeout):
            return {"records": [], "query_count": 1}

        runner.resolve_candidate = fake_resolve
        try:
            output = runner.run(payload)
        finally:
            runner.resolve_candidate = original

        self.assertEqual(output["summary"]["active_queries"], 0)
        self.assertEqual(output["errors"][0]["code"], "P7_SCOPE_DISABLED")
        self.assertEqual(output["findings"], [])
        self.assertEqual(output["candidates"], [])

    def test_active_disabled_keeps_special_address_probe_out_of_p5_6(self) -> None:
        payload = copy.deepcopy(load_input("input.active-dictionary.json"))
        payload["options"]["active"]["dry_run"] = False
        payload["options"]["active"]["max_candidates"] = 1
        payload["options"]["passive"]["sources"] = []

        original = runner.resolve_candidate

        def fake_resolve(hostname, record_types, resolvers, timeout):
            if hostname.startswith("sf-"):
                return {"records": [], "query_count": 1, "status": "nxdomain"}
            return {
                "records": [{"record_type": "A", "value": "198.18.0.75"}],
                "query_count": 1,
                "status": "ok",
            }

        runner.resolve_candidate = fake_resolve
        try:
            output = runner.run(payload)
        finally:
            runner.resolve_candidate = original

        self.assertEqual(output["errors"][0]["code"], "P7_SCOPE_DISABLED")
        self.assertEqual(output["findings"], [])
        self.assertEqual(output["candidates"], [])
        self.assertEqual(output["summary"]["invalid_count"], 0)

    def test_active_disabled_keeps_wildcard_probe_out_of_p5_6(self) -> None:
        payload = copy.deepcopy(load_input("input.active-dictionary.json"))
        payload["options"]["active"]["dry_run"] = False
        payload["options"]["active"]["max_candidates"] = 2
        payload["options"]["passive"]["sources"] = []
        payload["options"]["output"]["include_unresolved"] = True

        original = runner.resolve_candidate

        def fake_resolve(hostname, record_types, resolvers, timeout):
            return {
                "records": [{"record_type": "A", "value": "93.184.216.34"}],
                "query_count": 1,
                "status": "ok",
            }

        runner.resolve_candidate = fake_resolve
        try:
            output = runner.run(payload)
        finally:
            runner.resolve_candidate = original

        self.assertFalse(output["summary"]["wildcard_detected"])
        self.assertEqual(output["errors"][0]["code"], "P7_SCOPE_DISABLED")
        self.assertEqual(output["findings"], [])
        self.assertEqual(output["summary"]["wildcard_filtered_count"], 0)
        self.assertEqual(output["candidates"], [])

    def test_passive_external_sources_are_p7_disabled(self) -> None:
        payload = copy.deepcopy(load_input("input.passive-fixture.json"))
        payload["options"]["mode"] = "passive_intel"
        payload["options"]["passive"]["sources"] = ["local_cache", "crtsh", "shodan"]
        payload["options"]["passive"]["crtsh_enabled"] = True

        output = runner.run(payload)
        statuses = {item["source"]: item["status"] for item in output["source_status"]}

        self.assertEqual(statuses["local_cache"], "skipped_not_configured")
        self.assertEqual(statuses["crtsh"], "skipped_p7_disabled")
        self.assertEqual(statuses["shodan"], "skipped_p7_disabled")
        self.assertEqual(output["summary"]["active_queries"], 0)


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path
import sys


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PLUGIN_ROOT / "runner"))
sys.path.insert(0, str(PLUGIN_ROOT / "parser"))

import runner  # noqa: E402
import parser as parser_helper  # noqa: E402
from sources import resolver_client  # noqa: E402


def load_input(name: str) -> dict:
    with (PLUGIN_ROOT / "examples" / name).open("r", encoding="utf-8") as handle:
        return json.load(handle)


class DnsResolvePlusRunnerTests(unittest.TestCase):
    def test_fixture_outputs_dns_results(self) -> None:
        output = runner.run(load_input("input.fixture.json"))

        self.assertEqual(output["source"], "dns-resolve-plus")
        self.assertEqual(output["summary"]["estimated_dns_queries"], 0)
        values = {(item["domain"], item["record_type"], item["value"]) for item in output["results"]}
        self.assertIn(("www.example.com", "A", "93.184.216.34"), values)
        self.assertTrue(all(0 <= item["confidence"] <= 1 for item in output["results"]))

    def test_passive_intel_missing_secret_is_graceful_skip(self) -> None:
        output = runner.run(load_input("input.passive-intel.json"))

        statuses = {(item["source"], item["status"]) for item in output["source_status"]}
        self.assertIn(("external_dns_intel", "skipped_missing_secret"), statuses)
        self.assertEqual(output["errors"], [])

    def test_local_cache_and_passive_cache_merge_consistent_sources(self) -> None:
        output = runner.run(load_input("input.passive-intel.json"))

        api_a = [
            item
            for item in output["results"]
            if item["domain"] == "api.example.com" and item["record_type"] == "A"
        ][0]
        self.assertGreaterEqual(api_a["source_count"], 1)
        self.assertIn(api_a["source_agreement"], {"consistent", "passive_only"})
        self.assertTrue(api_a["source_details"])

    def test_conflicting_values_are_preserved(self) -> None:
        payload = load_input("input.fixture.json")
        payload = copy.deepcopy(payload)
        original_load = runner.local_cache.load_records

        def fake_load(plugin_root, relative_path):
            records = original_load(plugin_root, relative_path)
            records.append(
                {
                    "domain": "www.example.com",
                    "record_type": "A",
                    "value": "93.184.216.99",
                    "source": "public_resolver",
                    "source_type": "active",
                    "observed_at": "2026-06-01T00:00:00Z",
                    "source_updated_at": None,
                    "confidence": 0.85,
                    "evidence": {"summary": "conflicting active fixture", "items": []},
                }
            )
            return records

        runner.local_cache.load_records = fake_load
        try:
            output = runner.run(payload)
        finally:
            runner.local_cache.load_records = original_load

        conflicts = [item for item in output["results"] if item["source_agreement"] == "conflict"]
        self.assertTrue(conflicts)
        self.assertEqual(conflicts[0]["conflict_reason"], "dns_value_mismatch")

    def test_active_policy_denial_does_not_query(self) -> None:
        payload = load_input("input.active.json")
        payload = copy.deepcopy(payload)
        payload["policy"]["allow_active_verify"] = False

        output = runner.run(payload)

        self.assertEqual(output["errors"][0]["code"], "PolicyDenied")
        self.assertIn(("active_dns", "skipped_policy_denied"), {(item["source"], item["status"]) for item in output["source_status"]})
        self.assertEqual(output["safety"]["active_dns_queries"], 0)

    def test_authoritative_trace_requires_risk_acknowledgement(self) -> None:
        payload = load_input("input.active.json")
        payload = copy.deepcopy(payload)
        payload["options"]["active"]["authoritative_trace"] = True
        payload["options"]["risk_acknowledged"] = False

        output = runner.run(payload)

        self.assertEqual(output["errors"][0]["code"], "PolicyDenied")
        self.assertEqual(output["errors"][0]["field"], "$.options.risk_acknowledged")

    def test_invalid_domain_is_rejected(self) -> None:
        payload = load_input("input.fixture.json")
        payload = copy.deepcopy(payload)
        payload["inputs"]["domains"] = ["bad domain.example.com"]

        with self.assertRaises(runner.InputError):
            runner.run(payload)

    def test_limits_are_reported(self) -> None:
        payload = load_input("input.active.json")
        payload = copy.deepcopy(payload)
        payload["inputs"]["domains"] = [f"a{i}.example.com" for i in range(4)]
        payload["options"]["active"]["max_domains"] = 2
        payload["options"]["active"]["max_queries"] = 2

        output = runner.run(payload)

        self.assertEqual(output["errors"][0]["code"], "InputLimitExceeded")
        self.assertGreaterEqual(output["summary"]["error_count"], 1)

    def test_stale_result_is_marked(self) -> None:
        payload = load_input("input.fixture.json")
        payload = copy.deepcopy(payload)
        payload["options"]["merge"]["stale_after_days"] = 1
        output = runner.run(payload)

        self.assertTrue(any(item["source_agreement"] == "stale_passive" for item in output["results"]))

    def test_parser_exposes_source_details_and_conflict_reason(self) -> None:
        output = runner.run(load_input("input.fixture.json"))
        parsed = parser_helper.parse(output)

        self.assertTrue(parsed["findings"])
        data = parsed["findings"][0]["evidence"][0]["data"]
        self.assertIn("x-sentinelflow-dns.source_details", data)

    def test_benchmark_addresses_are_invalid_observations_not_findings(self) -> None:
        payload = load_input("input.active.json")
        payload = copy.deepcopy(payload)
        payload["inputs"]["domains"] = ["admin.example.com"]
        payload["options"]["record_types"] = ["A", "AAAA"]

        original = runner.resolver_client.resolve_public

        def fake_resolve_public(domain, record_types, resolvers, timeout_seconds):
            return (
                [
                    {"record_type": "A", "value": "198.18.0.75", "ttl": None},
                    {"record_type": "AAAA", "value": "::ffff:198.18.0.75", "ttl": None},
                ],
                2,
            )

        runner.resolver_client.resolve_public = fake_resolve_public
        try:
            output = runner.run(payload)
        finally:
            runner.resolver_client.resolve_public = original

        self.assertTrue(output["results"])
        for item in output["results"]:
            self.assertEqual(item["status"], "invalid_special_address")
            self.assertFalse(item["public_routable"])
            self.assertFalse(item["valid_for_port_probe"])
            self.assertEqual(item["confidence"], 0.0)
        classes = {item["address_class"] for item in output["results"]}
        self.assertIn("benchmark", classes)
        self.assertIn("ipv4_mapped_benchmark", classes)
        self.assertEqual(output["summary"]["invalid_special_address_count"], 2)
        self.assertEqual(output["summary"]["public_routable_result_count"], 0)
        self.assertEqual(output["summary"]["valid_for_port_probe_count"], 0)
        parsed = parser_helper.parse(output)
        self.assertEqual(parsed["findings"], [])

    def test_public_resolver_uses_udp_client_not_system_resolver(self) -> None:
        original_system = resolver_client.resolve_system
        original_udp = resolver_client.udp_dns_query

        def fail_system(domain, record_types, timeout_seconds):
            raise AssertionError("public_resolver must not call system resolver")

        def fake_udp(domain, record_type, resolver, timeout_seconds):
            self.assertEqual(domain, "www.example.com")
            self.assertEqual(record_type, "A")
            self.assertEqual(resolver, "1.1.1.1")
            return [{"record_type": "A", "value": "93.184.216.34", "ttl": 60}]

        resolver_client.resolve_system = fail_system
        resolver_client.udp_dns_query = fake_udp
        try:
            records, query_count = resolver_client.resolve_public(
                "www.example.com",
                ["A"],
                ["1.1.1.1"],
                1,
            )
        finally:
            resolver_client.resolve_system = original_system
            resolver_client.udp_dns_query = original_udp

        self.assertEqual(query_count, 1)
        self.assertEqual(records, [{"record_type": "A", "value": "93.184.216.34", "ttl": 60}])


if __name__ == "__main__":
    unittest.main()

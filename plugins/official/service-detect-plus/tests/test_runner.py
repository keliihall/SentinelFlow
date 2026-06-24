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


def load_input(name: str) -> dict:
    with (PLUGIN_ROOT / "examples" / name).open("r", encoding="utf-8") as handle:
        return json.load(handle)


class ServiceDetectPlusRunnerTests(unittest.TestCase):
    def test_fixture_outputs_service_result(self) -> None:
        output = runner.run(load_input("input.fixture.json"))

        self.assertEqual(output["source"], "service-detect-plus")
        self.assertEqual(output["summary"]["estimated_service_probes"], 0)
        self.assertTrue(output["results"])
        self.assertEqual(output["results"][0]["service"], "https")
        self.assertTrue(all(0 <= item["confidence"] <= 1 for item in output["results"]))

    def test_passive_intel_extracts_upstream_and_missing_secret_skips(self) -> None:
        output = runner.run(load_input("input.passive-intel.json"))

        statuses = {(item["source"], item["status"]) for item in output["source_status"]}
        self.assertIn(("upstream_port_result", "ok"), statuses)
        self.assertIn(("external_fingerprint_intel", "skipped_p7_disabled"), statuses)
        sources = {source for item in output["results"] for source in item["sources"]}
        self.assertIn("upstream_port_result", sources)

    def test_local_cache_is_used(self) -> None:
        output = runner.run(load_input("input.hybrid.json"))

        sources = {source for item in output["results"] for source in item["sources"]}
        self.assertIn("local_cache", sources)

    def test_conflicting_service_sources_are_preserved(self) -> None:
        payload = load_input("input.fixture.json")
        payload = copy.deepcopy(payload)
        original_load = runner.local_cache.load_services

        def fake_load(plugin_root, relative_path):
            records = original_load(plugin_root, relative_path)
            records.append(
                {
                    "address": "93.184.216.34",
                    "port": 443,
                    "protocol": "tcp",
                    "service": "https",
                    "transport": "tls",
                    "product": "different-product",
                    "version": None,
                    "hostnames": ["www.example.com"],
                    "banner_summary": "Server: different",
                    "http": {"status": 200, "server": "different", "title": "Example"},
                    "tls": {},
                    "source": "http_head",
                    "source_type": "active",
                    "detection_depth": "safe",
                    "observed_at": "2026-06-01T00:00:00Z",
                    "source_updated_at": None,
                    "confidence": 0.85,
                    "evidence": {"summary": "conflicting active fixture", "items": []},
                }
            )
            return records

        runner.local_cache.load_services = fake_load
        try:
            output = runner.run(payload)
        finally:
            runner.local_cache.load_services = original_load

        conflicts = [item for item in output["results"] if item["source_agreement"] == "conflict"]
        self.assertTrue(conflicts)
        self.assertIn(conflicts[0]["conflict_reason"], {"product_version_mismatch", "service_product_mismatch"})

    def test_safe_mode_is_p7_disabled(self) -> None:
        payload = load_input("input.safe.json")
        payload = copy.deepcopy(payload)

        output = runner.run(payload)

        self.assertEqual(output["errors"][0]["code"], "P7_SCOPE_DISABLED")
        self.assertEqual(output["safety"]["active_service_probes"], 0)

    def test_deep_mode_is_p7_disabled(self) -> None:
        payload = load_input("input.high-risk-deep.example.json")
        payload = copy.deepcopy(payload)
        payload["policy"]["allow_high_risk"] = False
        payload["options"]["risk_acknowledged"] = False
        payload["options"]["execution_profile"] = "active_safe"

        output = runner.run(payload)

        codes = [error["code"] for error in output["errors"]]
        self.assertIn("P7_SCOPE_DISABLED", codes)

    def test_external_fingerprint_rejects_arbitrary_command_config(self) -> None:
        payload = load_input("input.high-risk-deep.example.json")
        payload = copy.deepcopy(payload)
        payload["options"]["active"]["external_fingerprint"] = {"command": "nmap -sV"}

        output = runner.run(payload)

        self.assertTrue(any(error["code"] == "InputRejected" for error in output["errors"]))

    def test_no_open_ports_skips_service_detection(self) -> None:
        payload = load_input("input.safe.json")
        payload = copy.deepcopy(payload)
        payload["inputs"]["services"] = []
        payload["inputs"]["findings"] = []

        output = runner.run(payload)

        self.assertEqual(output["results"], [])
        self.assertEqual(output["errors"][0]["code"], "P7_SCOPE_DISABLED")
        self.assertEqual(output["source_status"][0]["status"], "skipped_p7_disabled")

    def test_banner_and_headers_are_redacted_and_truncated(self) -> None:
        record = {
            "address": "93.184.216.34",
            "port": 443,
            "protocol": "tcp",
            "service": "https",
            "banner_summary": "Authorization: secret\nServer: example",
            "http": {"headers": {"Authorization": "secret", "Server": "example"}},
            "source": "fixture",
        }
        target = [{"address": "93.184.216.34", "port": 443, "protocol": "tcp", "hostnames": []}]
        normalized = runner.normalize_services(
            [record],
            "fixture",
            target,
            {"mask_sensitive_headers": True, "truncate_banner_bytes": 64},
        )[0]

        self.assertNotIn("secret", normalized["banner_summary"])
        self.assertEqual(normalized["http"]["headers"]["Authorization"], "[redacted]")
        self.assertLessEqual(len(normalized["banner_summary"]), 64)

    def test_stale_passive_is_marked(self) -> None:
        payload = load_input("input.fixture.json")
        payload = copy.deepcopy(payload)
        payload["options"]["merge"]["stale_after_days"] = 1

        output = runner.run(payload)

        self.assertTrue(any(item["source_agreement"] == "stale_passive" for item in output["results"]))

    def test_parser_exposes_detection_depth_and_risk_level(self) -> None:
        output = runner.run(load_input("input.fixture.json"))
        parsed = parser_helper.parse(output)

        self.assertTrue(parsed["findings"])
        data = parsed["findings"][0]["evidence"][0]["data"]
        self.assertIn("x-sentinelflow-service.source_details", data)
        self.assertIn("x-sentinelflow-service.detection_depth", data)
        self.assertIn("x-sentinelflow-service.risk_level", data)


if __name__ == "__main__":
    unittest.main()

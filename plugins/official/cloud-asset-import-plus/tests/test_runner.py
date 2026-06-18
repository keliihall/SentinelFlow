from __future__ import annotations

import copy
import json
import sys
import unittest
from pathlib import Path


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PLUGIN_ROOT / "runner"))

import runner  # noqa: E402


def load_input() -> dict:
    with (PLUGIN_ROOT / "examples" / "input.fixture.json").open("r", encoding="utf-8") as handle:
        return json.load(handle)


class RunnerTests(unittest.TestCase):
    def test_multicloud_fixture_imports_all_declared_sources(self) -> None:
        output = runner.run(load_input())
        self.assertEqual(output["source"], "cloud-asset-import-plus")
        self.assertEqual(output["summary"]["source_count"], 8)
        self.assertEqual(output["summary"]["result_count"], 8)
        self.assertEqual(set(output["summary"]["providers"]), {"alibaba", "tencent", "huawei", "aws", "azure"})
        self.assertEqual(output["safety"]["cloud_api_calls"], 0)
        self.assertEqual(output["safety"]["active_asset_connections"], 0)

    def test_aws_compute_extracts_addresses_dns_and_redacts_secret_tag(self) -> None:
        output = runner.run(load_input())
        result = next(item for item in output["results"] if item["resource_id"] == "i-0123456789abcdef0")
        self.assertEqual(result["name"], "web-prod-1")
        self.assertEqual(result["public_ips"], ["198.51.100.15"])
        self.assertIn("ec2-198-51-100-15.compute-1.amazonaws.com", result["dns_names"])
        self.assertEqual(result["tags"]["api_token"], "[REDACTED]")
        self.assertTrue(result["internet_exposed"])

    def test_open_security_group_and_public_bucket_are_medium_risk(self) -> None:
        output = runner.run(load_input())
        security_group = next(item for item in output["results"] if item["resource_id"] == "sg-ali-001")
        bucket = next(item for item in output["results"] if item["resource_id"] == "obs-public-assets")
        self.assertIn("open_security_group_rule", security_group["exposure_reasons"])
        self.assertEqual(security_group["risk"], "medium")
        self.assertIn("public_object_storage", bucket["exposure_reasons"])
        self.assertEqual(bucket["risk"], "medium")

    def test_declared_public_ip_and_dns_resource_follow_resource_semantics(self) -> None:
        output = runner.run(load_input())
        public_ip = next(item for item in output["results"] if item["resource_type"] == "public_ip")
        dns = next(item for item in output["results"] if item["resource_type"] == "dns")
        self.assertEqual(public_ip["public_ips"], ["192.0.2.44"])
        self.assertEqual(public_ip["private_ips"], [])
        self.assertIn("web-ip.eastus.cloudapp.azure.com", public_ip["dns_names"])
        self.assertEqual(public_ip["status"], "Succeeded")
        self.assertEqual(dns["public_ips"], ["198.51.100.15"])
        self.assertEqual(dns["dns_names"], ["app.example.com"])
        self.assertIn("public_dns_record", dns["exposure_reasons"])

    def test_provider_and_exposure_filters_work(self) -> None:
        payload = copy.deepcopy(load_input())
        payload["options"]["filters"]["providers"] = ["azure"]
        payload["options"]["filters"]["internet_exposed_only"] = True
        output = runner.run(payload)
        self.assertEqual({item["provider"] for item in output["results"]}, {"azure"})
        self.assertTrue(all(item["internet_exposed"] for item in output["results"]))

    def test_output_omission_and_zero_limit_are_enforced(self) -> None:
        payload = copy.deepcopy(load_input())
        payload["options"]["output"]["include_tags"] = False
        payload["options"]["output"]["include_security_rules"] = False
        payload["options"]["output"]["include_source_details"] = False
        result = runner.run(payload)["results"][0]
        self.assertEqual(result["tags"], {})
        self.assertEqual(result["security_rules"], [])
        self.assertEqual(result["source_details"], [])
        payload["options"]["output"]["max_records"] = 0
        self.assertEqual(runner.run(payload)["results"], [])

    def test_dry_run_validates_sources_without_reading_files(self) -> None:
        payload = copy.deepcopy(load_input())
        payload["options"]["mode"] = "dry_run"
        payload["options"]["sources"][0]["file"] = "examples/missing.json"
        output = runner.run(payload)
        self.assertEqual(output["results"], [])
        self.assertTrue(all(item["status"] == "planned" for item in output["source_status"]))

    def test_rejects_online_policy_and_path_traversal(self) -> None:
        payload = copy.deepcopy(load_input())
        payload["policy"]["allow_cloud_api"] = True
        with self.assertRaises(runner.InputError):
            runner.run(payload)
        payload = copy.deepcopy(load_input())
        payload["options"]["sources"][0]["file"] = "../Cargo.toml"
        output = runner.run(payload)
        self.assertEqual(output["summary"]["error_count"], 1)
        self.assertEqual(output["source_status"][0]["status"], "error")


if __name__ == "__main__":
    unittest.main()

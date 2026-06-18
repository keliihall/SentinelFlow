from __future__ import annotations

import copy
import json
import sys
import unittest
from pathlib import Path


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PLUGIN_ROOT / "runner"))

import runner  # noqa: E402


def load_input(name: str = "input.fixture.json") -> dict:
    with (PLUGIN_ROOT / "examples" / name).open("r", encoding="utf-8") as handle:
        return json.load(handle)


class RunnerTests(unittest.TestCase):
    def test_json_import_maps_ownership_and_criticality(self) -> None:
        output = runner.run(load_input())
        self.assertEqual(output["summary"]["cmdb_asset_count"], 2)
        api = next(item for item in output["results"] if item["external_id"] == "ci-api-001")
        self.assertEqual(api["department"], "Platform")
        self.assertEqual(api["business_system"], "Public API")
        self.assertEqual(api["criticality"], "critical")
        self.assertIn("token=[REDACTED]", api["owner"])
        self.assertEqual(output["safety"]["direct_cmdb_writes"], 0)
        self.assertFalse(output["safety"]["gateway_apply_required"])

    def test_csv_import_is_supported(self) -> None:
        payload = copy.deepcopy(load_input())
        payload["options"]["cmdb"] = {"format": "csv", "file": "examples/cmdb.fixture.csv"}
        output = runner.run(payload)
        self.assertEqual(output["summary"]["cmdb_asset_count"], 2)
        self.assertEqual({item["external_id"] for item in output["results"]}, {"ci-web-001", "ci-db-001"})

    def test_writeback_plan_generates_create_update_and_noop(self) -> None:
        output = runner.run(load_input("input.writeback-plan.json"))
        actions = [item["action"] for item in output["operations"]]
        self.assertEqual(actions.count("create"), 1)
        self.assertEqual(actions.count("update"), 2)
        self.assertTrue(all(item["operation_id"].startswith("cmdb-op-") for item in output["operations"]))
        self.assertTrue(output["summary"]["requires_gateway_apply"])
        self.assertEqual(output["summary"]["direct_write_count"], 0)

    def test_conflict_policies_and_disabled_create_are_respected(self) -> None:
        payload = copy.deepcopy(load_input("input.writeback-plan.json"))
        payload["options"]["writeback"]["conflict_policy"] = "manual_review"
        payload["options"]["writeback"]["create_missing"] = False
        output = runner.run(payload)
        actions = {item["match"]["external_id"]: item["action"] for item in output["operations"]}
        self.assertEqual(actions["ci-web-001"], "manual_review")
        self.assertEqual(actions["ci-new-001"], "skip")

    def test_operation_ids_are_deterministic(self) -> None:
        payload = load_input("input.writeback-plan.json")
        first = [item["operation_id"] for item in runner.run(payload)["operations"]]
        second = [item["operation_id"] for item in runner.run(payload)["operations"]]
        self.assertEqual(first, second)

    def test_dry_run_does_not_read_files(self) -> None:
        payload = copy.deepcopy(load_input())
        payload["options"]["mode"] = "dry_run"
        payload["options"]["cmdb"]["file"] = "examples/missing.json"
        output = runner.run(payload)
        self.assertEqual(output["results"], [])
        self.assertEqual(output["operations"], [])

    def test_rejects_direct_writeback_and_path_traversal(self) -> None:
        payload = copy.deepcopy(load_input())
        payload["policy"]["allow_direct_writeback"] = True
        with self.assertRaises(runner.InputError):
            runner.run(payload)
        payload = copy.deepcopy(load_input())
        payload["options"]["cmdb"]["file"] = "../Cargo.toml"
        with self.assertRaises(runner.InputError):
            runner.run(payload)


if __name__ == "__main__":
    unittest.main()

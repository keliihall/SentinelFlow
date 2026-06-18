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
    def test_asset_discovery_report_is_generated_and_redacted(self) -> None:
        output = runner.run(load_input("input.asset-discovery.json"))
        self.assertEqual(output["source"], "markdown-report-plus")
        self.assertEqual(output["report"]["type"], "markdown_report")
        self.assertIn("Asset Discovery Overview", output["report"]["markdown"])
        self.assertIn("[REDACTED]", output["report"]["markdown"])
        self.assertNotIn("example-secret-token", output["report"]["markdown"])
        self.assertGreater(output["report"]["redaction_count"], 0)
        self.assertEqual(output["safety"]["network_connections"], 0)

    def test_audit_mode_can_omit_findings(self) -> None:
        output = runner.run(load_input("input.audit.json"))
        self.assertEqual(output["mode"], "audit")
        self.assertIn("## Audit", output["report"]["markdown"])
        self.assertNotIn("## Findings", output["report"]["markdown"])

    def test_rejects_unknown_mode(self) -> None:
        payload = load_input("input.asset-discovery.json")
        payload["options"]["mode"] = "template"
        with self.assertRaises(runner.InputError):
            runner.run(payload)

    def test_enforces_markdown_byte_limit(self) -> None:
        payload = load_input("input.asset-discovery.json")
        payload["options"]["limits"]["max_markdown_bytes"] = 1024
        payload["data"]["findings"] = payload["data"]["findings"] * 200
        output = runner.run(payload)
        self.assertTrue(output["report"]["truncated"])
        self.assertLessEqual(output["report"]["bytes"], 1100)


if __name__ == "__main__":
    unittest.main()

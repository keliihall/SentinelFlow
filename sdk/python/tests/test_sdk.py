import io
import json
import unittest

from sentinelflow_sdk import (
    evidence,
    finding,
    invoke_json,
    read_input,
    standard_error,
    write_output,
)


class SdkTests(unittest.TestCase):
    def test_reads_and_writes_standard_streams(self):
        self.assertEqual(read_input(io.StringIO('{"message":"fixture"}')), {"message": "fixture"})
        output = io.StringIO()
        write_output({"ok": True}, output)
        self.assertEqual(json.loads(output.getvalue()), {"ok": True})

    def test_builds_protocol_drafts(self):
        item = finding(
            "Fixture",
            "info",
            "Synthetic evidence only.",
            evidence_items=[evidence("fixture", "Local data", {"value": 1})],
        )
        self.assertEqual(item["evidence"][0]["evidenceType"], "fixture")
        self.assertEqual(
            standard_error("InvalidFixture", "bad fixture", field="$.message")["field"],
            "$.message",
        )

    def test_invoke_json_supports_plugin_tests(self):
        result = invoke_json(lambda value: {"message": value["message"]}, '{"message":"ok"}')
        self.assertEqual(json.loads(result), {"message": "ok"})


if __name__ == "__main__":
    unittest.main()

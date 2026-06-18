from __future__ import annotations

import json
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PLUGIN_ROOT / "runner"))

import runner  # noqa: E402


def load_input(name: str) -> dict:
    with (PLUGIN_ROOT / "examples" / name).open("r", encoding="utf-8") as handle:
        return json.load(handle)


class Handler(BaseHTTPRequestHandler):
    def do_HEAD(self) -> None:
        self.send_response(200)
        self.send_header("Server", "fixture-server")
        self.send_header("Content-Type", "text/html")
        self.end_headers()

    def do_GET(self) -> None:
        body = b"<html><title>Local Fixture</title><body>ok</body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format: str, *_args: object) -> None:
        return


class RunnerTests(unittest.TestCase):
    def test_fixture_outputs_http_result(self) -> None:
        output = runner.run(load_input("input.fixture.json"))
        self.assertEqual(output["source"], "http-probe-plus")
        self.assertEqual(output["results"][0]["type"], "http_result")
        self.assertEqual(output["results"][0]["source_agreement"], "passive_only")

    def test_active_policy_denial_skips_probe(self) -> None:
        payload = load_input("input.fixture.json")
        payload["options"]["mode"] = "active_safe"
        payload["options"]["active"]["enabled"] = True
        payload["policy"]["allow_active_verify"] = False
        output = runner.run(payload)
        self.assertEqual(output["errors"][0]["code"], "PolicyDenied")
        self.assertEqual(output["source_status"][0]["status"], "skipped_policy_denied")

    def test_active_safe_detects_local_http(self) -> None:
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        port = server.server_address[1]
        try:
            payload = load_input("input.active-local.json")
            payload["inputs"]["endpoints"] = [f"http://127.0.0.1:{port}/"]
            output = runner.run(payload)
        finally:
            server.shutdown()
            server.server_close()
        self.assertEqual(output["errors"], [])
        self.assertEqual(output["results"][0]["status_code"], 200)
        self.assertTrue(output["results"][0]["active_verified"])
        self.assertEqual(output["results"][0]["title"], "Local Fixture")


if __name__ == "__main__":
    unittest.main()

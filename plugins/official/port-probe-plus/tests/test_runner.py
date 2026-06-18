from __future__ import annotations

import json
import socket
import sys
import threading
import unittest
from pathlib import Path


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PLUGIN_ROOT / "runner"))

import runner  # noqa: E402


def load_input(name: str) -> dict:
    with (PLUGIN_ROOT / "examples" / name).open("r", encoding="utf-8") as handle:
        return json.load(handle)


class RunnerTests(unittest.TestCase):
    def test_fixture_outputs_open_port(self) -> None:
        output = runner.run(load_input("input.fixture.json"))
        self.assertEqual(output["source"], "port-probe-plus")
        self.assertEqual(output["results"][0]["port"], 443)
        self.assertEqual(output["results"][0]["source_agreement"], "passive_only")

    def test_active_policy_denial_skips_tcp_connect(self) -> None:
        payload = load_input("input.fixture.json")
        payload["options"]["mode"] = "active_tcp_connect"
        payload["options"]["active"]["enabled"] = True
        payload["policy"]["allow_active_verify"] = False
        output = runner.run(payload)
        self.assertEqual(output["results"], [])
        self.assertEqual(output["errors"][0]["code"], "PolicyDenied")

    def test_tcp_connect_detects_local_open_port(self) -> None:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]
        stop = threading.Event()

        def accept_once() -> None:
            try:
                conn, _ = server.accept()
                conn.close()
            finally:
                stop.set()
                server.close()

        thread = threading.Thread(target=accept_once, daemon=True)
        thread.start()

        payload = load_input("input.fixture.json")
        payload["options"]["mode"] = "active_tcp_connect"
        payload["options"]["active"]["enabled"] = True
        payload["options"]["active"]["ports"] = [port]
        payload["options"]["active"]["execution_profile"] = "lab"
        payload["inputs"]["addresses"] = ["127.0.0.1"]
        payload["policy"]["allow_active_verify"] = True

        output = runner.run(payload)
        stop.wait(2)
        self.assertEqual(output["errors"], [])
        self.assertEqual(output["results"][0]["port"], port)
        self.assertTrue(output["results"][0]["active_verified"])

    def test_no_public_ip_skips_port_probe(self) -> None:
        payload = load_input("input.fixture.json")
        payload["options"]["mode"] = "active_tcp_connect"
        payload["options"]["active"]["enabled"] = True
        payload["inputs"]["addresses"] = ["198.18.0.75", "127.0.0.1"]
        payload["policy"]["allow_active_verify"] = True

        output = runner.run(payload)

        self.assertEqual(output["results"], [])
        self.assertEqual(output["summary"]["status"], "skipped")
        self.assertEqual(output["summary"]["reason"], "no_public_routable_targets")
        self.assertEqual(output["source_status"][0]["status"], "skipped")


if __name__ == "__main__":
    unittest.main()

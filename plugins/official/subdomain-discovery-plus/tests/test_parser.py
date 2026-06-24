from __future__ import annotations

import unittest
from pathlib import Path
import sys


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PLUGIN_ROOT / "parser"))

import parser  # noqa: E402


class ParserTests(unittest.TestCase):
    def test_parser_converts_subdomain_finding_to_envelope(self) -> None:
        raw = {
            "source": "subdomain-discovery-plus",
            "domain": "example.com",
            "mode": "hybrid",
            "findings": [
                {
                    "type": "subdomain_result",
                    "status": "confirmed",
                    "confirmed": True,
                    "public_routable": True,
                    "domain": "example.com",
                    "subdomain": "www.example.com",
                    "source": "merged",
                    "sources": ["passive_fixture", "active_dictionary"],
                    "resolved": True,
                    "record_type": "A",
                    "addresses": ["93.184.216.34"],
                    "records": [{"record_type": "A", "value": "93.184.216.34"}],
                    "confidence": 0.9,
                    "evidence": {
                        "summary": "www.example.com discovered by fixture and DNS.",
                        "items": [],
                    },
                    "raw": {"retained": True},
                }
            ],
            "summary": {
                "domain": "example.com",
                "mode": "hybrid",
                "candidate_count": 1,
                "finding_count": 1,
                "active_queries": 1,
                "wildcard_detected": False,
                "errors": [],
            },
            "errors": [],
            "safety": {
                "target_type_domain_only": True,
                "authorization_scope_required": True,
                "active_policy_allowed": True,
                "active_dns_queries": 1,
                "dictionary_candidates": 1,
                "brute_force_attempts": 0,
                "port_scan_attempts": 0,
                "exploit_attempts": 0,
            },
        }

        envelope = parser.parse(raw)

        self.assertEqual(envelope["errors"], [])
        self.assertEqual(len(envelope["findings"]), 1)
        finding = envelope["findings"][0]
        self.assertEqual(finding["title"], "Confirmed subdomain")
        evidence = finding["evidence"][0]["data"]
        self.assertEqual(evidence["findingType"], "asset.subdomain")
        self.assertEqual(
            evidence["x-sentinelflow-subdomain.subdomain"], "www.example.com"
        )
        self.assertTrue(evidence["x-sentinelflow-subdomain.resolved"])
        self.assertTrue(evidence["x-sentinelflow-subdomain.public_routable"])

    def test_parser_never_turns_candidates_or_invalid_items_into_findings(self) -> None:
        envelope = parser.parse(
            {
                "findings": [],
                "candidates": [
                    {
                        "type": "subdomain_candidate",
                        "status": "candidate_unresolved",
                        "subdomain": "admin.example.test",
                    }
                ],
                "invalid_observations": [
                    {
                        "type": "invalid_observation",
                        "status": "invalid_special_address",
                        "subdomain": "test.example.test",
                    }
                ],
                "errors": [],
            }
        )

        self.assertEqual(envelope["findings"], [])
        self.assertEqual(len(envelope["values"]["candidates"]), 1)
        self.assertEqual(len(envelope["values"]["invalid_observations"]), 1)

    def test_parser_preserves_standard_errors(self) -> None:
        envelope = parser.parse(
            {
                "findings": [],
                "errors": [
                    {
                        "code": "PolicyDenied",
                        "message": "active denied",
                        "field": "$.policy.allow_active_verify",
                        "details": {"activeEnabled": True},
                    }
                ],
            }
        )

        self.assertEqual(envelope["errors"][0]["code"], "PolicyDenied")
        self.assertEqual(envelope["findings"], [])


if __name__ == "__main__":
    unittest.main()

import json
import tempfile
import unittest
from pathlib import Path

from zerotrustmap.core import PolicyError, analyze, analyze_file, boundaries

PRINCIPAL = "arn:aws:iam::123456789012:role/TestRole"


class PolicyTests(unittest.TestCase):
    def test_broad_allow_and_deny_not_effective_access(self):
        policy = {"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": "s3:*", "Resource": "*"},
            {"Effect": "Deny", "Action": "s3:DeleteObject", "Resource": "*"}]}
        report = analyze(json.dumps(policy).encode(), PRINCIPAL)
        self.assertEqual(len(report["potential_allow_edges"]), 1)
        self.assertEqual(len(report["deny_assertions_not_resolved"]), 1)
        self.assertEqual(report["review_indicators"][0]["type"], "broad_allow_review")
        self.assertIn("not evaluated", report["assessment_limit"])

    def test_unsupported_notaction_and_conditions(self):
        policy = {"Statement": [{"Effect": "Allow", "NotAction": "s3:Delete*", "Resource": "*"},
                                {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::bucket/*",
                                 "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "true"}}}]}
        report = analyze(json.dumps(policy).encode(), PRINCIPAL)
        self.assertEqual(len(report["potential_allow_edges"]), 1)
        self.assertTrue(report["potential_allow_edges"][0]["condition_present"])
        self.assertTrue(any("NotAction" in issue for issue in report["issues"]))

    def test_boundary_and_comparison(self):
        policy = {"Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::bucket/*"}]}
        zones = {"principals": {PRINCIPAL: "zone-a"}, "resources": {"arn:aws:s3:::bucket/*": "zone-b"}}
        first = analyze(json.dumps(policy).encode(), PRINCIPAL, zones)
        second = analyze(json.dumps({"Statement": []}).encode(), PRINCIPAL, zones, first)
        self.assertEqual(first["review_indicators"][0]["type"], "cross_boundary_review")
        self.assertEqual(len(second["changes"]["not_observed_statement_hashes"]), 1)

    def test_duplicate_json_and_wrong_principal(self):
        with self.assertRaises(PolicyError):
            analyze(b'{"Statement":[],"Statement":[]}', PRINCIPAL)
        with self.assertRaises(PolicyError):
            analyze(b'{"Statement":[]}', "user")

    def test_file_import(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "policy.json"
            path.write_text(json.dumps({"Statement": [{"Effect": "Allow", "Action": "s3:GetObject",
                                                        "Resource": "arn:aws:s3:::bucket/*"}]}))
            zone_file = Path(tmp) / "zones.json"
            zone_file.write_text(json.dumps({"principals": {PRINCIPAL: "zone-a"}}))
            report = analyze_file(path, PRINCIPAL, boundaries(zone_file))
        self.assertEqual(report["principal_type"], "role")
        self.assertEqual(len(report["source_sha256"]), 64)


if __name__ == "__main__":
    unittest.main()

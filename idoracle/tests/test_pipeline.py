"""The fusion: a list of candidate findings becomes one honest audit bundle."""

import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
AUTHZ = os.path.abspath(os.path.join(HERE, ".."))
sys.path.insert(0, AUTHZ)

import pipeline  # noqa: E402
from target_app import make_server  # noqa: E402

TS = "2026-06-22T00:00:00+00:00"
SECRET = "pipeline-secret"

FINDINGS = [
    {"collection": "/api/bola/notes"},                                  # -> confirmed
    {"collection": "/api/secure/notes"},                               # -> no-bug
    {"collection": "/api/reassign_owner/notes"},                       # -> hold
    {"collection": "/api/sharing/notes", "create_extra": {"shared": True}},  # -> legit, no-bug
]


class TestPipeline(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv, cls.base, cls.store = make_server()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def setUp(self):
        self.store.reset()

    def test_audit_bundle(self):
        bundle = pipeline.run_audit(
            self.base, findings=FINDINGS, verification_collection="/api/secure/notes",
            created_at=TS, secret=SECRET, draws=80, seed=1)

        self.assertEqual(bundle["findings"]["confirmed"], 1)     # the bola finding
        self.assertEqual(bundle["findings"]["hold"], 1)          # reassigned owner
        self.assertEqual(bundle["findings"]["no_bug"], 2)        # secure + legit share

        cov = bundle["coverage"]
        self.assertEqual(cov["classes_covered"], 2)              # both A_owns classes
        self.assertEqual(cov["plantable_classes"], 2)
        self.assertEqual(cov["declared_classes"], 6)             # 4 provably-blind by construction
        self.assertGreater(cov["coverage_pct"], 0.0)
        self.assertLessEqual(cov["residual_mass_upper"], 1.0)

        self.assertIn("confirmed", bundle["honest_report"])
        self.assertIn("provably_blind", bundle["honest_report"])

    def test_every_finding_carries_a_signed_receipt(self):
        bundle = pipeline.run_audit(
            self.base, findings=FINDINGS, verification_collection="/api/secure/notes",
            created_at=TS, secret=SECRET, draws=10, seed=2)
        for r in bundle["results"]:
            self.assertIn("receipt_json", r)
            self.assertIn("signature", r["receipt_json"])


if __name__ == "__main__":
    unittest.main()

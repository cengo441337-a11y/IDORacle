"""External-validity pilot: does the oracle hold up against an app it was NOT
co-designed with (Bearer auth, /items, secret/bio fields, no sharing model)?

The honest result: with its toy defaults the oracle HOLDs (wrong auth -> 401 -> cannot
plant), it does not pretend to work. Given a target profile (Bearer auth + the fields it
DISCOVERS), it produces a sound witness on the BOLA build and stays clean on the secure
one - proving the soundness transfers to a differently-shaped real target.
"""

import json
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
AUTHZ = os.path.abspath(os.path.join(HERE, ".."))
sys.path.insert(0, AUTHZ)

import oracle  # noqa: E402
from ext_target import make_ext_server  # noqa: E402

TS = "2026-06-22T00:00:00+00:00"
SECRET = "pilot-secret"
BEARER = lambda p: {"Authorization": f"Bearer tok{p}"}  # noqa: E731


class TestPilot(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.s_secure, cls.b_secure, cls.st_secure = make_ext_server("secure")
        cls.s_bola, cls.b_bola, cls.st_bola = make_ext_server("bola")

    @classmethod
    def tearDownClass(cls):
        cls.s_secure.shutdown()
        cls.s_bola.shutdown()

    def setUp(self):
        self.st_secure.reset()
        self.st_bola.reset()

    def test_toy_defaults_hold_against_a_foreign_shaped_app(self):
        # wrong auth (X-Principal, not Bearer) -> 401 -> cannot plant -> HOLD, never a guess.
        rec, _, f = oracle.probe(self.b_bola, "/items", created_at=TS, secret=SECRET)
        self.assertFalse(f["plantable_confirmed"])
        self.assertEqual(rec.overall, "hold")

    def test_field_discovery_finds_the_real_fields(self):
        found = oracle.discover_writable_fields(
            self.b_bola, "/items", principal="A", auth=BEARER,
            candidate_fields=["secret", "bio", "canary", "title"])
        self.assertEqual(set(found), {"secret", "bio"})

    def test_profiled_oracle_witnesses_on_bola(self):
        fields = oracle.discover_writable_fields(
            self.b_bola, "/items", principal="A", auth=BEARER,
            candidate_fields=["secret", "bio"])
        rec, artifact, f = oracle.probe(self.b_bola, "/items", auth=BEARER, fields=fields,
                                        confirm_shared=False, created_at=TS, secret=SECRET)
        self.assertTrue(f["witness"])
        self.assertEqual(rec.overall, "fail")
        self.assertTrue(oracle.verify_witness(rec, artifact, SECRET)["ok"])

    def test_profiled_oracle_is_clean_on_secure(self):
        rec, _, f = oracle.probe(self.b_secure, "/items", auth=BEARER,
                                 fields=["secret", "bio"], confirm_shared=False,
                                 created_at=TS, secret=SECRET)
        self.assertFalse(f["witness"])
        self.assertEqual(rec.overall, "pass")


if __name__ == "__main__":
    unittest.main()

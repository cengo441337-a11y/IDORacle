"""Soundness CI-gate (v2) for the canary-write-IDOR oracle.

Mechanizes the adversarial audit that broke v1. Every case below either confirms a
sound verdict or pins a former false-positive / false-negative / integrity hole:

  0 FP        : secure never fires.
  0 FN        : bola always fires.
  decoys      : 200-no-op silent, 403-but-wrote fires (verdict tracks STATE not status).
  FP regress  : normalize (A-side canary normalization) and readonly_canary
                (non-writable field) must NOT fire -> they become honest non-witnesses
                because the field is not confirmed-plantable.
  FN fix      : sibling_write (B mutates `title`, not `canary`) MUST fire via the
                multi-field witness (v1 signed overall=pass here).
  gone -> HOLD: ghost (object vanishes) is inconclusive, never a write-witness.
  plant fail  : an unknown collection -> HOLD, never a witness on a never-created object.
  integrity   : a VALIDLY-SIGNED receipt whose `overall` contradicts its facts is
                rejected by verify_witness (signed assertion != correctness).
  receipt     : validates under the EXISTING examples/offline_verify.py.
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
AUTHZ = os.path.abspath(os.path.join(HERE, ".."))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, AUTHZ)

import oracle              # noqa: E402
from target_app import make_server  # noqa: E402
from receipt import hmac_signer, sign_receipt  # noqa: E402

TS = "2026-06-22T00:00:00+00:00"
SECRET = "authz-canary-test-secret"


class TestSoundness(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server, cls.base, cls.store = make_server()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def setUp(self):
        self.store.reset()

    def _probe(self, collection, **kw):
        return oracle.probe(self.base, collection, created_at=TS, secret=SECRET, **kw)

    def _mode(self, mode, **kw):
        return self._probe(f"/api/{mode}/notes", **kw)

    # --- core soundness ---------------------------------------------------
    def test_secure_no_false_positive(self):
        rec, _, f = self._mode("secure")
        self.assertFalse(f["witness"])
        self.assertEqual(rec.overall, "pass")

    def test_bola_no_false_negative(self):
        rec, _, f = self._mode("bola")
        self.assertTrue(f["witness"])
        self.assertEqual(rec.overall, "fail")

    def test_decoy_200_noop_status_agnostic(self):
        rec, _, f = self._mode("decoy_200_noop")
        self.assertEqual(f["b_http_status"], 200)
        self.assertFalse(f["witness"])
        self.assertEqual(rec.overall, "pass")

    def test_decoy_403_wrote_status_agnostic(self):
        rec, _, f = self._mode("decoy_403_wrote")
        self.assertEqual(f["b_http_status"], 403)
        self.assertTrue(f["witness"])
        self.assertEqual(rec.overall, "fail")

    # --- false-positive regressions (the v1 breaks) -----------------------
    def test_normalize_does_not_false_positive(self):
        # server lowercases canary on A's own store -> canary not confirmed-plantable;
        # title still round-trips; secure non-owner -> no write -> NO witness.
        rec, _, f = self._mode("normalize")
        self.assertNotIn("canary", f["confirmed_fields"])
        self.assertIn("title", f["confirmed_fields"])
        self.assertFalse(f["witness"])
        self.assertEqual(rec.overall, "pass")

    def test_readonly_canary_does_not_false_positive(self):
        rec, _, f = self._mode("readonly_canary")
        self.assertNotIn("canary", f["confirmed_fields"])
        self.assertFalse(f["witness"])
        self.assertEqual(rec.overall, "pass")

    def test_plant_failure_holds_not_witness(self):
        rec, _, f = self._probe("/api/no_such_mode/notes")  # POST 404 -> cannot plant
        self.assertFalse(f["plantable_confirmed"])
        self.assertFalse(f["asserted_bug"])
        self.assertEqual(rec.overall, "hold")

    # --- false-negative fix ----------------------------------------------
    def test_sibling_write_is_caught(self):
        rec, _, f = self._mode("sibling_write")
        self.assertEqual(f["changed_fields"], ["title"])
        self.assertNotIn("canary", f["changed_fields"])
        self.assertTrue(f["witness"])
        self.assertEqual(rec.overall, "fail")

    # --- gone -> HOLD -----------------------------------------------------
    def test_ghost_disappearance_holds(self):
        rec, _, f = self._mode("ghost")
        self.assertTrue(f["object_gone"])
        self.assertFalse(f["asserted_bug"])
        self.assertEqual(rec.overall, "hold")

    def test_provably_blind_never_asserts(self):
        rec, _, f = self._mode("secure", plantable=False)
        self.assertEqual(rec.overall, "hold")
        self.assertFalse(f["asserted_bug"])

    # --- determinism ------------------------------------------------------
    def test_determinism_across_replays(self):
        for mode, expected in [("secure", "pass"), ("bola", "fail"),
                               ("decoy_200_noop", "pass"), ("decoy_403_wrote", "fail"),
                               ("sibling_write", "fail"), ("normalize", "pass"),
                               ("ghost", "hold")]:
            overalls = {self._mode(mode)[0].overall for _ in range(120)}
            self.assertEqual(overalls, {expected}, f"non-deterministic for {mode}")

    # --- integrity: verdict re-derived from facts, not trusted ------------
    def test_validly_signed_but_wrong_overall_is_rejected(self):
        rec, artifact, _ = self._mode("secure")            # honest verdict = pass
        self.assertTrue(oracle.verify_witness(rec, artifact, SECRET)["ok"])
        forged = oracle.Receipt(**{k: v for k, v in rec.__dict__.items() if k != "signature"})
        forged.overall = "fail"                            # issuer lies: clean -> fail
        sign_receipt(forged, hmac_signer(SECRET))          # and signs the lie validly
        res = oracle.verify_witness(forged, artifact, SECRET)
        self.assertTrue(res["signature_ok"])               # signature DOES verify
        self.assertFalse(res["verdict_consistent"])        # but the facts say pass
        self.assertFalse(res["ok"])

    def test_receipt_validates_under_existing_offline_verifier(self):
        rec, artifact, _ = self._mode("bola")
        rfd, rpath = tempfile.mkstemp(suffix=".json")
        afd, apath = tempfile.mkstemp(suffix=".json")
        os.close(rfd)
        os.close(afd)
        try:
            with open(rpath, "w", encoding="utf-8") as fh:
                fh.write(rec.to_json())
            with open(apath, "w", encoding="utf-8") as fh:
                fh.write(artifact)
            r = subprocess.run(
                [sys.executable, os.path.join("examples", "offline_verify.py"),
                 rpath, apath, SECRET],
                capture_output=True, text=True, cwd=REPO)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            self.assertIn("artifact_ok : True", r.stdout)
            self.assertIn("signature   : ok", r.stdout)
        finally:
            for p in (rpath, apath):
                if os.path.exists(p):
                    os.unlink(p)


if __name__ == "__main__":
    unittest.main()

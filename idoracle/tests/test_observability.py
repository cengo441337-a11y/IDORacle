"""Observability soundness self-test (the surviving sliver, made runnable).

Demonstrates that the qualification test - not the token search itself - is what makes
a foreign-object write-witness SOUND (BACScan, CCS 2025, ships the heuristic search):

  - `search`       (committed-state)      -> QUALIFIES   (O1+O3+O2'+O4' all pass)
  - `audit`        (attempt-derived)      -> disqualified BY THE NEGATIVE CONTROL (O2')
  - `search_plus`  (state + attacker feed)-> disqualified BY UNIQUE-CAUSAL-PATH (O4')
  - foreign-object witness via the QUALIFIED `search` view succeeds on a BOLA server and
    stays inconclusive on a secure one - WITHOUT ever GETting the foreign object.
"""

import json
import os
import sys
import unittest
import urllib.error
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
AUTHZ = os.path.abspath(os.path.join(HERE, ".."))
sys.path.insert(0, AUTHZ)

import views  # noqa: E402
from obs_target import make_obs_server  # noqa: E402

TS = "2026-06-22T00:00:00+00:00"
SECRET = "obs-test-secret"


def _api(base, method, path, principal="anon", body=None, q=None):
    url = base + path + (("?q=" + urllib.parse.quote(q)) if q is not None else "")
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=data, method=method,
                                 headers={"X-Principal": principal,
                                          "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read() or b"null")
    except urllib.error.HTTPError as e:
        try:
            return e.code, None
        finally:
            e.close()


class TestObservability(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.s_secure, cls.b_secure, cls.st_secure = make_obs_server("secure")
        cls.s_bola, cls.b_bola, cls.st_bola = make_obs_server("bola")

    @classmethod
    def tearDownClass(cls):
        cls.s_secure.shutdown()
        cls.s_bola.shutdown()

    def setUp(self):
        self.st_secure.reset()
        self.st_bola.reset()

    def _wiring(self, base):
        view = lambda name, path, kind: views.View(  # noqa: E731
            name, (lambda t: _api(base, "GET", path, "B", q=t)[1]["hit"]), kind)
        controls = dict(
            committer=lambda t: _api(base, "POST", "/notes", "A", {"canary": t}),
            dropper=lambda t: _api(base, "POST", "/control_drop", "B", {"canary": t}),
            alt_injectors=[lambda t: _api(base, "POST", "/feed", "B", {"canary": t})],
        )
        return view, controls

    def test_committed_state_view_qualifies(self):
        view, controls = self._wiring(self.b_secure)
        ok, report = views.qualify_view(view("search", "/search", "committed-state"), **controls)
        self.assertTrue(ok, report)
        self.assertTrue(all(report[k] for k in
                            ("O1_authorized", "O3_entropy_preserving",
                             "O2_commit_gated", "O4_unique_causal_path")))

    def test_attempt_derived_view_fails_negative_control(self):
        view, controls = self._wiring(self.b_secure)
        ok, report = views.qualify_view(view("audit", "/audit", "attempt-derived"), **controls)
        self.assertFalse(ok)
        self.assertTrue(report["O3_entropy_preserving"])     # it DOES echo committed tokens
        self.assertFalse(report["O2_commit_gated"])          # ...but also dropped ones -> unsound

    def test_attacker_writable_view_fails_unique_causal_path(self):
        view, controls = self._wiring(self.b_secure)
        ok, report = views.qualify_view(view("search_plus", "/search_plus", "state+feed"), **controls)
        self.assertFalse(ok)
        self.assertTrue(report["O2_commit_gated"])
        self.assertFalse(report["O4_unique_causal_path"])    # a token enters via the feed

    def test_greybox_db_replica_qualifies(self):
        # the grey-box channel (read-only committed-store replica) passes the same test.
        view, controls = self._wiring(self.b_secure)
        ok, report = views.qualify_view(view("db_replica", "/db_replica", "greybox-db"), **controls)
        self.assertTrue(ok, report)

    def test_oob_listener_qualifies(self):
        # the OOB webhook channel (callback fires only on commit) passes the same test.
        view, controls = self._wiring(self.b_secure)
        ok, report = views.qualify_view(view("oob", "/oob", "oob-webhook"), **controls)
        self.assertTrue(ok, report)

    def _foreign_witness(self, base, state):
        # A owns a note; B (attacker) cannot GET it but writes it; a qualified global
        # search view witnesses the committed write without B ever reading the object.
        _, v = _api(base, "POST", "/notes", "A", {"canary": "seed"})
        nid = v["id"]
        self.assertEqual(_api(base, "GET", f"/notes/{nid}", "B")[0], 403)  # foreign: no read
        view, _ = self._wiring(base)
        search = view("search", "/search", "committed-state")
        return views.witness_via_view(
            search, lambda t: _api(base, "PATCH", f"/notes/{nid}", "B", {"canary": t})[0])

    def test_foreign_object_witness_on_bola(self):
        w = self._foreign_witness(self.b_bola, self.st_bola)
        self.assertTrue(w["witness"])                        # write committed, proven via view
        self.assertEqual(w["verdict"], "witness")

    def test_foreign_object_witness_inconclusive_on_secure(self):
        w = self._foreign_witness(self.b_secure, self.st_secure)
        self.assertFalse(w["witness"])                       # rejected -> token absent
        self.assertEqual(w["verdict"], "inconclusive")       # absence != no-write

    def test_receipt_emitted_and_consistent(self):
        view, controls = self._wiring(self.b_bola)
        search = view("search", "/search", "committed-state")
        _, report = views.qualify_view(search, **controls)
        w = self._foreign_witness(self.b_bola, self.st_bola)
        rec, artifact, _ = views.emit_receipt(report, w, created_at=TS, secret=SECRET)
        self.assertEqual(rec.overall, "fail")               # qualified view + observed write
        self.assertEqual(views.sha256_hex(artifact), rec.artifact_sha256)
        self.assertTrue(any(e["status"] == "provably_blind"
                            for e in rec.assurance["negative_envelope"]))


if __name__ == "__main__":
    unittest.main()

"""ARES integration: a heuristic candidate becomes a SOUND verdict + signed receipt."""

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

import ares_adapter as ares  # noqa: E402
import views  # noqa: E402
from target_app import make_server  # noqa: E402
from obs_target import make_obs_server  # noqa: E402

TS = "2026-06-22T00:00:00+00:00"
SECRET = "ares-test-secret"


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


class TestAresAdapter(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv, cls.base, cls.store = make_server()
        cls.osrv, cls.obase, cls.ostate = make_obs_server("bola")

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.osrv.shutdown()

    def setUp(self):
        self.store.reset()
        self.ostate.reset()

    def _validate(self, mode, **kw):
        return ares.validate_finding(self.base, collection=f"/api/{mode}/notes",
                                     created_at=TS, secret=SECRET, **kw)

    def test_bola_is_confirmed_bug(self):
        self.assertEqual(self._validate("bola")["verdict"], ares.CONFIRMED)

    def test_secure_is_no_bug(self):
        self.assertEqual(self._validate("secure")["verdict"], ares.NO_BUG)

    def test_legit_shared_write_is_no_bug(self):
        # the policy-aware tier: B writing a shared object is allowed -> not a bug.
        self.assertEqual(self._validate("sharing", create_extra={"shared": True})["verdict"],
                         ares.NO_BUG)

    def test_reassigned_owner_is_hold(self):
        self.assertEqual(self._validate("reassign_owner")["verdict"], ares.HOLD)

    def test_receipt_is_signed_json(self):
        r = self._validate("bola")
        rec = json.loads(r["receipt_json"])
        self.assertEqual(rec["overall"], "fail")
        self.assertIn("signature", rec)

    def test_foreign_object_via_qualified_view_is_confirmed(self):
        view = views.View("search",
                          lambda t: _api(self.obase, "GET", "/search", "B", q=t)[1]["hit"],
                          "committed-state")
        qkw = dict(committer=lambda t: _api(self.obase, "POST", "/notes", "A", {"canary": t}),
                   dropper=lambda t: _api(self.obase, "POST", "/control_drop", "B", {"canary": t}),
                   alt_injectors=[lambda t: _api(self.obase, "POST", "/feed", "B", {"canary": t})])
        _, v = _api(self.obase, "POST", "/notes", "A", {"canary": "seed"})
        nid = v["id"]
        out = ares.validate_via_view(
            view, lambda t: _api(self.obase, "PATCH", f"/notes/{nid}", "B", {"canary": t})[0],
            qkw, created_at=TS, secret=SECRET)
        self.assertTrue(out["qualified"])
        self.assertEqual(out["verdict"], ares.CONFIRMED)

    def test_unqualified_view_is_hold(self):
        view = views.View("audit",
                          lambda t: _api(self.obase, "GET", "/audit", "B", q=t)[1]["hit"],
                          "attempt-derived")
        qkw = dict(committer=lambda t: _api(self.obase, "POST", "/notes", "A", {"canary": t}),
                   dropper=lambda t: _api(self.obase, "POST", "/control_drop", "B", {"canary": t}),
                   alt_injectors=[lambda t: _api(self.obase, "POST", "/feed", "B", {"canary": t})])
        out = ares.validate_via_view(view, lambda t: 200, qkw, created_at=TS, secret=SECRET)
        self.assertFalse(out["qualified"])
        self.assertEqual(out["verdict"], ares.HOLD)


if __name__ == "__main__":
    unittest.main()

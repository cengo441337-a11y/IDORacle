"""Weeks 4-6 decidability gate (do this BEFORE building the martingale).

Pins the load-bearing question: is the authorization-equivalence-class partition
ONLINE-realizable (classify any probed ref with ONLY schema + tester-known facts,
no ground-truth answer key)?

  - classifier correctness : every plantable class is recovered from (owner=A,
    shared set by tester), matching the enumerated truth.
  - blindness boundary      : a pre-existing object (owner not observable) -> UNDECIDABLE.
  - decoupling              : the class is a property of the object's typed shape,
    independent of the app's actual decision -> classification needs no answer key.
  - policy-aware soundness   : a legitimately shared object that B may write fires
    the raw witness but is NOT a bug; a private object B can write IS a bug. This is
    the v1/v2 owner-only assumption made explicit and correct.
  - new-class detector + declared P over plantable classes.

If classification ever required ground truth, the sigma-algebra is not online-
realizable and the project is on the impossibility track, not the certificate track.
"""

import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
AUTHZ = os.path.abspath(os.path.join(HERE, ".."))
sys.path.insert(0, AUTHZ)

import oracle  # noqa: E402
from target_app import make_server  # noqa: E402
from schema import AuthzClass, EndpointSchema  # noqa: E402
from coverage import (NOT_A_OWNS, NewClassDetector, UNDECIDABLE,  # noqa: E402
                      classify_bug, classify_online, classify_via_authorized_read,
                      is_bug, true_masses, within_class_agreement)

TS = "2026-06-22T00:00:00+00:00"
SECRET = "decidability-test-secret"


class TestDecidability(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server, cls.base, cls.store = make_server()
        cls.schema = EndpointSchema(obj_type="note")

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def setUp(self):
        self.store.reset()

    # --- the partition -----------------------------------------------------
    def test_plantable_classes_are_exactly_A_owns(self):
        plantable = {c.id for c in self.schema.plantable_classes()}
        self.assertEqual(plantable, {
            AuthzClass("note", "A_owns", False).id,
            AuthzClass("note", "A_owns", True).id,
        })
        self.assertEqual(len(self.schema.enumerate_classes()), 6)  # 3 ownership x 2 shared

    def test_classifier_recovers_every_plantable_class_online(self):
        for shared in (False, True):
            cls = classify_online(self.schema, owner_principal="A", shared=shared)
            self.assertEqual(cls, AuthzClass("note", "A_owns", shared))
            self.assertIn(cls, self.schema.plantable_classes())

    def test_preexisting_object_is_undecidable(self):
        self.assertIs(classify_online(self.schema, owner_principal=None, shared=False),
                      UNDECIDABLE)

    def test_classification_is_decoupled_from_the_app_decision(self):
        # The class of an A-owned shared note is the same no matter how the app
        # actually behaves (secure / sharing / bola) -> no answer key needed.
        ids = set()
        for mode in ("secure", "sharing", "bola"):
            self.store.reset()
            oracle.probe(self.base, f"/api/{mode}/notes", create_extra={"shared": True},
                         created_at=TS, secret=SECRET)
            ids.add(classify_online(self.schema, owner_principal="A", shared=True).id)
        self.assertEqual(ids, {AuthzClass("note", "A_owns", True).id})

    # --- classifying fields must be CONFIRMED, not trusted ----------------
    def test_ignore_shared_holds(self):
        # server ignores the visibility flag -> shared not faithfully writable ->
        # the policy-bearing field is untrusted -> HOLD, never a bug/clean verdict.
        rec, _, f = oracle.probe(self.base, "/api/ignore_shared/notes",
                                 create_extra={"shared": True}, created_at=TS, secret=SECRET)
        self.assertEqual(f["confirmed_shared"], False)     # server stored False, not True
        self.assertFalse(f["plantable_confirmed"])
        self.assertEqual(rec.overall, "hold")

    def test_reassign_owner_holds(self):
        # server records owner != the POSTer -> plant did not yield an A-owned object
        # -> HOLD (a B-owned object B writes is legitimate, not an IDOR).
        rec, _, f = oracle.probe(self.base, "/api/reassign_owner/notes",
                                 created_at=TS, secret=SECRET)
        self.assertEqual(f["confirmed_owner"], "B")
        self.assertFalse(f["plantable_confirmed"])
        self.assertEqual(rec.overall, "hold")

    def test_authorized_read_extends_coverage_beyond_plantable(self):
        # a pre-existing A-owned ref is fully classifiable from a 200 read;
        # a pre-existing B-owned ref reads 403 -> coarse not_A_owns (not UNDECIDABLE).
        _, a_view = oracle._http(self.base, "POST", "/api/secure/notes", "A",
                                 {"canary": "x", "shared": True})
        s_a, v_a = oracle._http(self.base, "GET", f"/api/secure/notes/{a_view['id']}", "A")
        self.assertEqual(classify_via_authorized_read(self.schema, s_a, v_a),
                         AuthzClass("note", "A_owns", True))
        _, b_view = oracle._http(self.base, "POST", "/api/secure/notes", "B", {"canary": "y"})
        s_b, v_b = oracle._http(self.base, "GET", f"/api/secure/notes/{b_view['id']}", "A")
        self.assertEqual(s_b, 403)
        self.assertEqual(classify_via_authorized_read(self.schema, s_b, v_b), NOT_A_OWNS)

    # --- policy-aware bug verdict (the new soundness property) -------------
    def _witness(self, mode, shared):
        _, _, f = oracle.probe(self.base, f"/api/{mode}/notes",
                               create_extra={"shared": shared}, created_at=TS, secret=SECRET)
        cls = classify_online(self.schema, owner_principal="A", shared=f["confirmed_shared"])
        return f["witness"], is_bug(self.schema, cls, f["witness"])

    def test_legitimate_shared_write_is_witnessed_but_not_a_bug(self):
        witness, bug = self._witness("sharing", shared=True)   # B may write a shared obj
        self.assertTrue(witness)                               # the raw write persisted
        self.assertFalse(bug)                                  # ... but policy ALLOWS it

    def test_private_write_by_B_is_a_real_bug(self):
        witness, bug = self._witness("bola", shared=False)     # B wrote a private obj
        self.assertTrue(witness)
        self.assertTrue(bug)

    def test_denied_private_write_is_neither(self):
        witness, bug = self._witness("sharing", shared=False)  # not shared -> B denied
        self.assertFalse(witness)
        self.assertFalse(bug)

    def test_undecidable_class_is_never_a_confirmed_bug(self):
        self.assertFalse(is_bug(self.schema, UNDECIDABLE, True))

    # --- two-tier bug verdict (policy-circularity made honest) -------------
    def test_bug_tier_confirmed_on_construction_sound_cell(self):
        # A_owns & not shared: B writing it is a bug regardless of any declaration.
        self.assertEqual(classify_bug(self.schema, AuthzClass("note", "A_owns", False), True),
                         ("confirmed", True))

    def test_bug_tier_conditional_on_declared_policy_cell(self):
        # other_owns & not shared: 'bug' here rests on declared==intended policy.
        self.assertEqual(classify_bug(self.schema, AuthzClass("note", "other_owns", False), True),
                         ("conditional", True))

    def test_shared_cell_is_not_a_bug(self):
        self.assertEqual(classify_bug(self.schema, AuthzClass("note", "A_owns", True), True),
                         ("none", False))

    # --- partition determinism (hidden-dimension detection) ---------------
    def _two_member_results(self, mode):
        out = []
        for _ in range(2):
            _, _, f = oracle.probe(self.base, f"/api/{mode}/notes",
                                   created_at=TS, secret=SECRET)
            cid = classify_online(self.schema, owner_principal="A",
                                  shared=f["confirmed_shared"]).id
            out.append((cid, f["witness"]))
        return out

    def test_within_class_agreement_holds_on_deterministic_endpoint(self):
        self.assertTrue(within_class_agreement(self._two_member_results("secure")))

    def test_within_class_agreement_fails_on_per_object_acl(self):
        # flaky_acl decides by object-id parity -> two members of the same declared
        # class disagree -> partition is too coarse -> must NOT be counted covered.
        results = self._two_member_results("flaky_acl")
        self.assertEqual(len({cid for cid, _ in results}), 1)   # same declared class
        self.assertFalse(within_class_agreement(results))       # but verdicts disagree

    # --- new-class detector + declared measure ----------------------------
    def test_new_class_detector(self):
        d = NewClassDetector()
        c0 = classify_online(self.schema, owner_principal="A", shared=False)
        c1 = classify_online(self.schema, owner_principal="A", shared=True)
        self.assertTrue(d.observe(c0))
        self.assertTrue(d.observe(c1))
        self.assertFalse(d.observe(c0))                        # already seen
        self.assertFalse(d.observe(UNDECIDABLE))               # never a class

    def test_declared_masses_sum_to_one_over_plantable(self):
        m = true_masses(self.schema)
        self.assertEqual(set(m), {c.id for c in self.schema.plantable_classes()})
        self.assertAlmostEqual(sum(m.values()), 1.0)


if __name__ == "__main__":
    unittest.main()

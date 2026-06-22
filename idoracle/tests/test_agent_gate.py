"""The agent effect gate catches the silent no-op (claimed success, committed nothing)."""

import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
AUTHZ = os.path.abspath(os.path.join(HERE, ".."))
sys.path.insert(0, AUTHZ)

import agent_gate  # noqa: E402
from receipt import hmac_signer, sign_receipt  # noqa: E402

TS = "2026-06-22T00:00:00+00:00"
SECRET = "agent-test-secret"


class TestAgentGate(unittest.TestCase):
    def setUp(self):
        self.store = []

    def _tools(self):
        store = self.store

        def commit(p):
            store.append(p)
            return {"ok": True}

        def noop(p):
            return {"ok": True}                       # claims success, commits nothing

        def observe(token):
            return any(token in str(t) for t in store)

        return commit, noop, observe

    def test_real_commit_passes(self):
        commit, _, observe = self._tools()
        rec, _, f = agent_gate.gate_effect(lambda t: commit({"c": t}), observe,
                                           created_at=TS, secret=SECRET)
        self.assertTrue(f["observed"])
        self.assertEqual(rec.overall, "pass")

    def test_silent_no_op_is_caught(self):
        _, noop, observe = self._tools()
        rec, _, f = agent_gate.gate_effect(lambda t: noop({"c": t}), observe,
                                           created_at=TS, secret=SECRET)
        self.assertFalse(f["observed"])
        self.assertEqual(f["verdict"], "silent_no_op")
        self.assertEqual(rec.overall, "fail")

    def test_unobservable_channel_holds(self):
        commit, _, observe = self._tools()
        rec, _, _ = agent_gate.gate_effect(lambda t: commit({"c": t}), observe,
                                           qualified=False, created_at=TS, secret=SECRET)
        self.assertEqual(rec.overall, "hold")

    def test_a2a_verify_rejects_a_validly_signed_lie(self):
        _, noop, observe = self._tools()
        rec, artifact, _ = agent_gate.gate_effect(lambda t: noop({"c": t}), observe,
                                                  created_at=TS, secret=SECRET)   # fail
        self.assertEqual(rec.overall, "fail")
        forged = agent_gate.Receipt(**{k: v for k, v in rec.__dict__.items() if k != "signature"})
        forged.overall = "pass"                       # issuer lies: no-op -> pass
        sign_receipt(forged, hmac_signer(SECRET))     # and signs it validly
        res = agent_gate.verify_effect(forged, artifact, SECRET)
        self.assertTrue(res["signature_ok"])
        self.assertFalse(res["verdict_consistent"])
        self.assertFalse(res["ok"])

    def test_decorator_raises_on_silent_no_op(self):
        _, noop, observe = self._tools()

        @agent_gate.effect_gated(observe, secret=SECRET, created_at=TS, action="create")
        def create(token):
            return noop({"c": token})

        with self.assertRaises(agent_gate.EffectNotWitnessed):
            create()

    def test_decorator_returns_on_real_commit(self):
        commit, _, observe = self._tools()

        @agent_gate.effect_gated(observe, secret=SECRET, created_at=TS, action="create")
        def create(token):
            return commit({"c": token})

        result, rec, f = create()
        self.assertEqual(rec.overall, "pass")
        self.assertTrue(f["observed"])


if __name__ == "__main__":
    unittest.main()

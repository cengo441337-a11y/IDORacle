"""Weeks 7-9 coverage-certificate validity (the falsification arm).

The decisive test: across many i.i.d. verification sub-streams, the true uncovered
mass U must exceed the certified upper bound m_hat_upper at most at rate <= alpha.
A wrong martingale (e.g. the v1 Q-relative draft, or a sign error) fails this.
"""

import os
import random
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
AUTHZ = os.path.abspath(os.path.join(HERE, ".."))
sys.path.insert(0, AUTHZ)

from certificate import CoverageCertificate  # noqa: E402


def _simulate(P, n_draws, rng):
    """Draw n_draws classes i.i.d. from P (dict class->mass); return (certificate, true U)."""
    classes = list(P)
    weights = [P[c] for c in classes]
    cert = CoverageCertificate(alpha=0.05)
    seen = set()
    for _ in range(n_draws):
        c = rng.choices(classes, weights=weights, k=1)[0]
        cert.update(c not in seen)
        seen.add(c)
    true_U = sum(P[c] for c in classes if c not in seen)
    return cert, true_U


class TestCertificate(unittest.TestCase):
    def test_bound_in_unit_interval(self):
        cert, _ = _simulate({i: 1 / 10 for i in range(10)}, 20, random.Random(1))
        self.assertGreaterEqual(cert.bound(), 0.0)
        self.assertLessEqual(cert.bound(), 1.0)

    def test_bound_shrinks_as_coverage_grows(self):
        P = {i: 1 / 8 for i in range(8)}
        early, _ = _simulate(P, 3, random.Random(2))
        late, _ = _simulate(P, 400, random.Random(2))
        self.assertGreater(early.bound(), late.bound())     # more draws -> tighter bound
        self.assertLess(late.bound(), 0.05)                 # all covered -> near-zero residual
        self.assertGreater(late.coverage(), 0.95)

    def test_certified_gate(self):
        P = {i: 1 / 6 for i in range(6)}
        late, _ = _simulate(P, 500, random.Random(3))
        self.assertTrue(late.certified(max_uncovered=0.05))

    def test_determinism_given_the_substream(self):
        seq = [True, False, True, True, False, False, True]
        a, b = CoverageCertificate(), CoverageCertificate()
        for x in seq:
            a.update(x)
            b.update(x)
        self.assertEqual(a.bound(), b.bound())

    def test_falsification_coverage_validity(self):
        # 20 uniform classes, 40 draws -> U is often > 0, so the bound is genuinely tested.
        K, n_draws, seeds, alpha = 20, 40, 500, 0.05
        P = {i: 1 / K for i in range(K)}
        misses = 0
        nontrivial = 0
        for s in range(seeds):
            cert, true_U = _simulate(P, n_draws, random.Random(1000 + s))
            if true_U > 0:
                nontrivial += 1
            if true_U > cert.bound() + 1e-9:
                misses += 1
        miss_rate = misses / seeds
        self.assertGreater(nontrivial, seeds // 2)          # the test actually exercises U>0
        self.assertLessEqual(miss_rate, alpha + 0.03,       # <= alpha (+ Monte-Carlo slack)
                             f"miss rate {miss_rate} exceeds {alpha}")


if __name__ == "__main__":
    unittest.main()

"""Weeks 7-9: anytime-valid coverage certificate over authorization-equivalence classes.

The corrected betting test-martingale (the v1 draft was UNSOUND: it asserted truth-
relative validity under an ADAPTIVE sampler). The fix from the adversarial review:
DECOUPLE discovery from certification. The certificate is computed ONLY on a separate
VERIFICATION sub-stream sampled i.i.d. from a DECLARED measure P over the plantable
classes, so E[X_t | F_{t-1}] = U_{t-1} EXACTLY (X_t = 1 if draw t hits a NEW class,
U_{t-1} = current uncovered mass). The adaptive bug-hunting stream certifies nothing.

Test the composite null H0(m): U >= m by BETTING against it:
    W_t(m) = W_{t-1}(m) * (1 + lambda(m) * (m - X_t)),   lambda(m) in [0, 1/(1-m)]
Under H0(m): r_t ~ P gives E[X_t|F]=U_{t-1}>=m, so E[m - X_t|F] = m-U_{t-1} <= 0, hence
{W_t(m)} is a NONNEGATIVE SUPERMARTINGALE. Ville: P(exists t: W_t(m) >= 1/alpha) <= alpha.
The (1-alpha) confidence sequence is C_t = {m : W_t(m) < 1/alpha}; the true U is in C_t
for all t simultaneously w.p. >= 1-alpha, so the anytime-valid UPPER bound is
    m_hat_upper(tau) = sup{ m : W_tau(m) < 1/alpha }   (no union bound: single-parameter Ville)
and Coverage(tau) = 1 - m_hat_upper(tau). '95% no untested class' <=> m_hat_upper <= 0.05.

Honest envelope (see coverage.ENVELOPE_NOTES): sound only because the sub-stream is
i.i.d.-from-P (P-relative, must be published); schema-conditional; bounds MASS not COUNT
(a rare low-mass class can sit uncovered at small m_hat_upper); a relative/fraction
guarantee is impossible distribution-free (Mossel-Ohannessian 2019).
"""

from __future__ import annotations

import math


class CoverageCertificate:
    def __init__(self, alpha: float = 0.05, grid_step: float = 0.01, lam0: float = 0.5):
        if not 0.0 < lam0 <= 1.0:
            raise ValueError("lam0 must be in (0,1] to keep the capital nonnegative")
        self.alpha = alpha
        self.lam0 = lam0
        # candidate ceilings m in (0,1); m=1 is the trivial 'nothing covered' bound.
        n = int(round(1.0 / grid_step))
        self.grid = [i / n for i in range(1, n)]
        self.log_thr = math.log(1.0 / alpha)
        self.logW = {m: 0.0 for m in self.grid}     # log capital (numerically stable)
        self.t = 0

    def update(self, is_new_class: bool) -> None:
        """Feed one VERIFICATION-sub-stream draw (i.i.d. from P). MUST NOT be fed from
        the adaptive bug-hunting stream - that would make the bound Q-relative."""
        x = 1.0 if is_new_class else 0.0
        self.t += 1
        for m in self.grid:
            lam = self.lam0 / (1.0 - m)              # predictable, in [0, 1/(1-m)]
            factor = 1.0 + lam * (m - x)             # >= 1-lam0 > 0 since x in {0,1}
            self.logW[m] += math.log(factor)

    def bound(self) -> float:
        """Anytime-valid upper bound on the current uncovered-class mass."""
        not_rejected = [m for m in self.grid if self.logW[m] < self.log_thr]
        return max(not_rejected) if not_rejected else 0.0

    def coverage(self) -> float:
        return 1.0 - self.bound()

    def certified(self, max_uncovered: float = 0.05) -> bool:
        """The honest gate: residual uncovered mass provably below the ceiling."""
        return self.bound() <= max_uncovered

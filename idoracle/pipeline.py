"""Weeks 10-12 fusion: one end-to-end audit that ties everything together.

Given a target and a list of candidate findings (the kind ARES discovers), produce a
single AUDIT BUNDLE:
  1. validate each candidate with the sound oracle  -> confirmed / conditional / no-bug / hold
  2. build the coverage certificate over the plantable authorization-equivalence classes
     from a DECOUPLED i.i.d. verification sub-stream (NOT the finding stream)
  3. report BOTH denominators honestly: confirmed bugs, coverage over plantable classes,
     and the non-plantable classes that are provably_blind by construction.

This is the honest deliverable: not "0 findings", but "here is what I proved, here is
how much of the (declared) space I covered, and here is exactly where I am blind".
"""

import os
import random
import sys
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import ares_adapter as ares  # noqa: E402
import oracle  # noqa: E402
from certificate import CoverageCertificate  # noqa: E402
from coverage import NewClassDetector, classify_online, true_masses  # noqa: E402
from schema import EndpointSchema  # noqa: E402


def _coverage(base, verification_collection, schema, *, auth, confirm_shared,
              draws, rng, created_at, secret):
    """Anytime-valid coverage over the plantable classes via an i.i.d.-from-P sub-stream
    (decoupled from the finding validation - that adaptive stream certifies nothing)."""
    cert, detector = CoverageCertificate(), NewClassDetector()
    P = true_masses(schema)
    by_id = {c.id: c for c in schema.plantable_classes()}
    ids, weights = list(P), [P[i] for i in P]
    for _ in range(draws):
        cid = rng.choices(ids, weights=weights, k=1)[0]
        extra = {"shared": by_id[cid].shared} if confirm_shared else None
        _, _, f = oracle.probe(base, verification_collection, auth=auth, create_extra=extra,
                               confirm_shared=confirm_shared, created_at=created_at, secret=secret)
        cls = classify_online(schema, owner_principal="A", shared=f["confirmed_shared"])
        cert.update(detector.observe(cls))
    return cert, len(detector.seen)


def run_audit(base, *, findings, verification_collection, schema=None, auth=None,
              confirm_shared=True, secret, created_at, draws=120, seed=0):
    """Run the full audit. `findings` is a list of validate_finding kwargs dicts."""
    schema = schema or EndpointSchema()
    results = [ares.validate_finding(base, schema=schema, auth=auth,
                                     confirm_shared=confirm_shared, created_at=created_at,
                                     secret=secret, **fnd) for fnd in findings]
    counts = Counter(r["verdict"] for r in results)

    cert, covered = _coverage(base, verification_collection, schema, auth=auth,
                              confirm_shared=confirm_shared, draws=draws,
                              rng=random.Random(seed), created_at=created_at, secret=secret)
    plantable = len(schema.plantable_classes())
    total = len(schema.enumerate_classes())
    cov_pct = round(cert.coverage() * 100, 1)
    report = (f"{counts[ares.CONFIRMED]} confirmed bug(s), {counts[ares.CONDITIONAL]} "
              f"conditional, {counts[ares.NO_BUG]} clean, {counts[ares.HOLD]} held; "
              f"coverage >= {cov_pct}% over {covered}/{plantable} plantable classes; "
              f"{total - plantable}/{total} declared classes are provably_blind by "
              f"construction (pre-existing, owner not online-observable).")
    return {
        "findings": {"confirmed": counts[ares.CONFIRMED], "conditional": counts[ares.CONDITIONAL],
                     "no_bug": counts[ares.NO_BUG], "hold": counts[ares.HOLD]},
        "coverage": {"residual_mass_upper": round(cert.bound(), 4), "coverage_pct": cov_pct,
                     "classes_covered": covered, "plantable_classes": plantable,
                     "declared_classes": total},
        "honest_report": report,
        "results": results,
    }

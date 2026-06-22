"""Online equivalence-class classification, decidability, and the policy-aware bug
verdict (weeks 4-6).

The decidability question the gate answers: can a probed object-ref be sorted into
its authorization-equivalence class using ONLY (a) the declared schema and (b)
facts knowable online - WITHOUT the ground-truth class label?

Answer (and the boundary): YES for a tester-PLANTED ref, because the owner and the
visibility state are CONFIRMED from an authorized A read-back (not trusted as tester
assertions - a server that reassigns ownership or ignores `shared` is caught and the
probe HOLDs). The plant-only classifier returns UNDECIDABLE for pre-existing objects.
That is conservative, NOT the tight boundary: an authorized A-GET additionally decides
`A_owns` vs `not_A_owns` online even for pre-existing refs (200 vs 403), and fully
classifies A-owned pre-existing refs from the 200 view - this is DEFERRED coverage
(`classify_via_authorized_read`), not impossibility. `B_owns` vs `other_owns` is NOT
decidable from A's vantage and stays UNDECIDABLE. If classification ever needed the
ground-truth answer key, the certificate would be unbuildable (impossibility track).
"""

from schema import OWNERSHIP, AuthzClass  # noqa: F401

UNDECIDABLE = "UNDECIDABLE"
NOT_A_OWNS = "not_A_owns"   # coarse bucket: B_owns or other_owns, indistinguishable from A

_OWNER_REL = {"A": "A_owns", "B": "B_owns"}

# Honest exclusions the coverage layer MUST declare (from the adversarial audit).
ENVELOPE_NOTES = [
    "conditional-policy: the BUG verdict is unconditionally sound only on the A_owns "
    "AND NOT shared cell; on every other cell 'bug' = deviation from the DECLARED "
    "policy and is sound only if declared==intended (undischarged inside the oracle).",
    "policy-model-heuristic: b_write_allowed = B_owns OR shared is a labeled heuristic; "
    "field-level, lifecycle (draft/locked), role/group, delegated, time-bounded, and "
    "shared-read-vs-shared-write authorization need an endpoint-specific policy.",
    "closed-world denominator: coverage is over the tester-DECLARED finite class set; "
    "authorization regimes the schema failed to enumerate are out of envelope.",
    "partition-relative: coverage assumes (obj_type, ownership, shared) is "
    "decision-determining; per-object/lifecycle/role/time refinements are caught only "
    "by the within-class agreement check, else they silently inflate the denominator.",
    "classifying fields owner+shared must round-trip via authorized A read-back, else HOLD.",
    "report BOTH denominators: covered/plantable AND covered/declared (non-plantable "
    "cells are provably-blind by construction, not assurance).",
]


def classify_online(schema, *, owner_principal, shared):
    """Classify from ONLY online-knowable facts.

    `owner_principal` is who the tester knows created/owns the object: "A" or "B"
    for an object the tester planted, None for a pre-existing object (owner not
    observable). `shared` is the state the tester set at plant time. Returns an
    AuthzClass, or UNDECIDABLE when ownership is not online-knowable.
    """
    if owner_principal is None:
        return UNDECIDABLE
    ownership = _OWNER_REL.get(owner_principal, "other_owns")
    return AuthzClass(schema.obj_type, ownership, bool(shared))


def classify_via_authorized_read(schema, get_status, get_view):
    """Deferred coverage beyond the plantable subspace: an authorized A-GET decides
    A_owns-vs-not online even for a pre-existing object. 200 -> fully classified
    A_owns class (owner+shared from the view); 403 -> the coarse not_A_owns bucket
    (B_owns vs other_owns is NOT decidable from A's vantage); else UNDECIDABLE."""
    if get_status == 200 and isinstance(get_view, dict):
        return AuthzClass(schema.obj_type, "A_owns", bool(get_view.get("shared", False)))
    if get_status == 403:
        return NOT_A_OWNS
    return UNDECIDABLE


def classify_bug(schema, cls, b_write_persisted: bool):
    """Two-tier bug verdict. Returns (tier, is_bug) where tier is:

      'confirmed'   - the CONSTRUCTION-SOUND cell A_owns AND NOT shared: B writing an
                      object A created private and never shared violates ANY sane
                      policy, so it needs NO declared-policy assumption.
      'conditional' - any other denied cell: 'bug' here means deviation from the
                      tester-DECLARED policy, which is sound ONLY if declared==intended
                      (a condition that cannot be discharged from inside the oracle).
      'none'        - not persisted / unknown class / the declared policy permits B.

    Emitting a 'conditional' as a confirmed bug is the actual unsoundness; a consumer
    must be able to reject conditional findings that rest on an unverified policy.
    Note: on the PLANTABLE subspace the only denied cell is A_owns&not-shared, so
    plantable bug verdicts are always 'confirmed' - the policy dependency only enters
    via deferred (authorized-read) coverage of non-plantable cells.
    """
    if not b_write_persisted or cls is UNDECIDABLE or not isinstance(cls, AuthzClass):
        return ("none", False)
    if schema.b_write_allowed(cls):
        return ("none", False)                       # declared policy permits B
    if cls.ownership == "A_owns" and not cls.shared:
        return ("confirmed", True)                   # no declared policy needed
    return ("conditional", True)                     # rests on declared==intended


def is_bug(schema, cls, b_write_persisted: bool) -> bool:
    """Bool convenience: any tier of bug. Prefer classify_bug to carry the tier."""
    return classify_bug(schema, cls, b_write_persisted)[1]


def within_class_agreement(probe_results) -> bool:
    """Partition-determinism check. `probe_results` = [(class_id, witness_bool), ...]
    for >=2 independently planted refs of the SAME declared class. Returns True iff
    all witnesses agree. A disagreement proves a HIDDEN splitting dimension (per-object
    ACL, lifecycle/locked state, role/time gating) - the partition is too coarse, so
    'one probed member = class covered' is unsound and the caller must HOLD
    ('class-refinement-detected') instead of counting the class covered."""
    return len({w for _, w in probe_results}) <= 1


class NewClassDetector:
    """Online detector of first-time-seen classes - the X_t indicator the coverage
    martingale (weeks 7-9) runs on. UNDECIDABLE never counts as a class."""

    def __init__(self):
        self.seen = set()

    def observe(self, cls) -> bool:
        cid = cls if cls is UNDECIDABLE else cls.id
        is_new = cid != UNDECIDABLE and cid not in self.seen
        self.seen.add(cid)
        return is_new


def true_masses(schema, weights=None):
    """A declared sampling measure P over the PLANTABLE classes (the verification
    sub-stream draws from this in weeks 7-9). Uniform by default; the weights MUST
    be declared and published with any coverage number (the bound is P-relative)."""
    classes = schema.plantable_classes()
    if weights is None:
        w = 1.0 / len(classes)
        return {c.id: w for c in classes}
    total = float(sum(weights.get(c.id, 0.0) for c in classes)) or 1.0
    return {c.id: weights.get(c.id, 0.0) / total for c in classes}

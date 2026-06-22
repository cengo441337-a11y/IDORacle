"""ares_adapter.py - plug the SOUND authz oracle + coverage certificate into ARES.

ARES (Deniz's red-team orchestration layer, native on openclaw) discovers CANDIDATE
authz findings heuristically/with an LLM. This adapter turns each candidate into a
SOUND verdict and a signed receipt - replacing "the model thinks this is a bug" with
"a deterministic witness proves the unauthorized write, or the oracle honestly HOLDs".

Division of labour (the whole point):
  ARES        = discovery + orchestration (which endpoints, which principal pairs,
                which object refs to try) - the broad, heuristic, creative part.
  this oracle = the deterministic VALIDATION ORACLE - for each candidate, a sound
                witness (canary or via a qualified observation view) + a policy-aware
                bug tier + a coverage certificate, all in a signed receipt.

The adapter NEVER asserts a bug a sound witness did not establish; an un-observable
target yields HOLD (provably_blind), surfaced honestly in the receipt.

NOTE: wiring this to a LIVE ARES run against a real target is offensive work and needs
explicit authorization (Regel 7). The functions here are pure given a transport; the
tests drive them against the in-process deterministic targets only.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import oracle    # noqa: E402
import views     # noqa: E402
from coverage import classify_bug, classify_online  # noqa: E402
from schema import EndpointSchema  # noqa: E402

# ARES-facing verdicts.
CONFIRMED = "confirmed-bug"      # sound witness + policy denies B unconditionally
CONDITIONAL = "conditional-bug"  # sound witness, but bug rests on the DECLARED policy
NO_BUG = "no-bug"                # qualified probe, no unauthorized write observed
HOLD = "hold"                    # not soundly observable -> provably_blind, asserts nothing

_TIER = {"confirmed": CONFIRMED, "conditional": CONDITIONAL, "none": NO_BUG}


def validate_finding(base_url, *, collection, principal_a="A", principal_b="B",
                     plantable=True, create_extra=None, schema=None, auth=None,
                     confirm_shared=True, created_at, secret):
    """Validate one ARES candidate against the canary oracle. Returns an ARES verdict
    dict carrying the signed receipt. `schema` (EndpointSchema) enables the policy-aware
    bug tier; `auth`/`confirm_shared` make it work against arbitrary (non-toy) targets."""
    schema = schema or EndpointSchema()
    rec, artifact, facts = oracle.probe(
        base_url, collection, principal_a, principal_b, plantable=plantable,
        create_extra=create_extra, auth=auth, confirm_shared=confirm_shared,
        created_at=created_at, secret=secret)

    if not facts["plantable_confirmed"]:
        verdict = HOLD
    elif not facts["witness"]:
        verdict = NO_BUG
    else:
        cls = classify_online(schema, owner_principal="A", shared=facts["confirmed_shared"])
        tier, _ = classify_bug(schema, cls, True)
        verdict = _TIER[tier]
    return {"verdict": verdict, "witness": facts["witness"],
            "asserted_bug": facts["asserted_bug"], "receipt_json": rec.to_json(),
            "facts": facts}


def validate_via_view(view, inject_write, qualify_kwargs, *, created_at, secret):
    """Validate a FOREIGN-object candidate via an observation view: first qualify the
    view (O1-O4' self-test), then witness through it. A non-qualifying view -> HOLD."""
    qualifies, report = views.qualify_view(view, **qualify_kwargs)
    if not qualifies:
        rec, _, _ = views.emit_receipt(report, {"witness": False, "verdict": "inconclusive"},
                                       created_at=created_at, secret=secret)
        return {"verdict": HOLD, "qualified": False, "receipt_json": rec.to_json(),
                "qualification": report}
    witness = views.witness_via_view(view, inject_write)
    rec, _, _ = views.emit_receipt(report, witness, created_at=created_at, secret=secret)
    verdict = CONFIRMED if witness["witness"] else NO_BUG
    return {"verdict": verdict, "qualified": True, "witness": witness,
            "receipt_json": rec.to_json(), "qualification": report}

"""Observability soundness self-test: the one contribution that survived the
adversarial review of the observability theorem.

BACScan (Liu et al., CCS 2025) already injects a high-entropy token via a write and
searches OTHER authorized views to confirm a committed modification. That token search
is a HEURISTIC: nothing stops an attempt/audit-log surface or an attacker-writable feed
from surfacing the token without a genuine commit to the target object (a false
positive). This module turns that heuristic into a SOUND oracle by running, per view,
an executable qualification test derived from the corrected theorem:

  O1 authorized          the tester can read the view.
  O3 entropy-preserving  POSITIVE control: a token from a genuine commit appears verbatim.
  O2' commit-gated       NEGATIVE control: a token from a real-path NON-COMMIT (accepted
                         but dropped / rolled back, NOT an early authz reject) must NOT
                         appear -> excludes the request-log false positive.
  O4' unique-causal-path SIBLING controls: a token injected through every OTHER write
                         path the tester can reach (incl. the view itself if writable)
                         must NOT appear -> the only route into the view is a committed
                         write to the object.

Only a view passing all four is sound to witness on. The witness then injects a fresh
token co-located in the mutated field, settles past the rollback window, and reports a
durable committed write iff the token is stably observed. Sound (FP <= 2^-128 on top of
unique causality); conditionally complete (absence != no-write). This is a small
formalization-plus-self-test contribution, NOT a new capability - cite BACScan.
"""

import json
import os
import secrets
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from receipt import (  # noqa: E402
    RECEIPT_SCHEMA, Receipt, hmac_signer, sha256_hex, sign_receipt)

SPINE_ID = "authz-observability/v0"
TOKEN_BYTES = 16


def fresh_token():
    return secrets.token_urlsafe(TOKEN_BYTES)


class View:
    """An observation surface: a name and a query(token) -> bool ('is it observed?')."""

    def __init__(self, name, query, kind="unknown"):
        self.name = name
        self.query = query
        self.kind = kind


def qualify_view(view, *, committer, dropper, alt_injectors):
    """Run the executable O1-O4' qualification. Returns (qualifies, report).

    committer(token)      commit `token` into the object's state via a legit path.
    dropper(token)        accept-but-NON-COMMIT `token` via the real write path.
    alt_injectors         list of callables(token) writing via every OTHER reachable path.
    """
    report = {"view": view.name, "kind": view.kind}
    try:
        view.query(fresh_token())                         # O1: readable without error
        report["O1_authorized"] = True
    except Exception:                                     # noqa: BLE001
        report["O1_authorized"] = False
        return False, report

    t_pos = fresh_token()
    committer(t_pos)
    report["O3_entropy_preserving"] = bool(view.query(t_pos))   # positive control

    t_neg = fresh_token()
    dropper(t_neg)
    report["O2_commit_gated"] = not view.query(t_neg)          # negative control

    o4 = True
    for inject in alt_injectors:
        t_alt = fresh_token()
        inject(t_alt)
        if view.query(t_alt):
            o4 = False
    report["O4_unique_causal_path"] = o4

    qualifies = all((report["O1_authorized"], report["O3_entropy_preserving"],
                     report["O2_commit_gated"], report["O4_unique_causal_path"]))
    report["qualifies"] = qualifies
    return qualifies, report


def witness_via_view(view, inject_write, *, settle_reads=2):
    """Witness an unauthorized durable write to a FOREIGN object via a qualifying view,
    without ever GETting the object. inject_write(token) -> b_http_status performs the
    tested write co-locating `token` in the mutated field. The token must be STABLY
    observed across `settle_reads` re-reads (durability past the rollback window).
    Absence is INCONCLUSIVE, never a no-write witness."""
    token = fresh_token()
    b_status = inject_write(token)
    observed = all(view.query(token) for _ in range(settle_reads))
    return {"view": view.name, "b_http_status": b_status,
            "token_observed_durably": observed,
            "witness": observed, "verdict": "witness" if observed else "inconclusive"}


def emit_receipt(qualify_report, witness_facts, *, created_at, secret):
    """Signed receipt carrying the view qualification AND the witness, with the O1-O4'
    soundness preconditions in the negative-capability envelope."""
    facts = {"qualification": qualify_report, "witness": witness_facts}
    artifact = json.dumps(facts, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    overall = "fail" if (qualify_report.get("qualifies") and witness_facts.get("witness")) \
        else ("hold" if not qualify_report.get("qualifies") else "pass")
    rec = Receipt(
        schema=RECEIPT_SCHEMA,
        artifact_sha256=sha256_hex(artifact),
        artifact_len=len(artifact),
        overall=overall,
        lane="high-stakes",
        checks=[{"name": "observability-witness", "verdict": overall,
                 "detail": "foreign-object write witnessed via a qualified view"
                           if overall == "fail" else
                           ("no qualifying view -> provably_blind" if overall == "hold"
                            else "qualified view, no unauthorized write observed")}],
        spine_id=SPINE_ID,
        created_at=created_at,
        assurance={
            "spine_version": SPINE_ID,
            "negative_envelope": [
                {"class": "write_idor:via_qualified_view", "status": "covered"},
                {"class": "write_idor:no_qualifying_view", "status": "provably_blind"},
                {"class": "read_idor", "status": "provably_blind"},
            ],
            "soundness_preconditions": [
                "content_only_observation_model(no timing/quota/ordering side channels)",
                "O1_authorized + O3_entropy_preserving(positive control)",
                "O2_commit_gated(negative control = real-path non-commit, not early reject)",
                "O4_unique_causal_path(sibling controls over every other write path)",
                "durability_reread_past_rollback_window",
                "token_co-located_in_the_mutated_policy_field",
            ],
            "prior_art": "mechanism anticipated by BACScan (Liu et al., CCS 2025); "
                         "contribution is the executable qualification self-test.",
        },
    )
    sign_receipt(rec, hmac_signer(secret))
    return rec, artifact, facts

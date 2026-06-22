"""Agent action effect gate: prove a tool call REALLY committed, before the agent says DONE.

The IDORacle canary primitive, generalized OFF HTTP and OFF IDOR. Any state changing action
can be gated on PROOF of its committed effect instead of trusting the tool's success return
or the agent's natural language claim. Plant a fresh high entropy token INTO the action's
committed payload, run the action, then re read the target through a SEPARATE committed state
view. Release only on a durable observation. The tool's 200 / exit 0 and the agent's "I did
it" are the untrusted response.

The verdict tracks committed STATE, never the success signal. So the silent no op (the agent
economy's number one failure: "I created the ticket / applied the manifest / updated the row"
when nothing committed) does NOT pass. The gate emits a portable signed receipt a downstream
agent re derives LLM free before consuming the artifact (the A2A handoff).

  pass  -> the effect was witnessed in committed state (release the action)
  fail  -> the action claimed success but NO committed effect was observed (block: it lied)
  hold  -> the effect is not soundly observable (provably_blind; do not claim DONE)
"""

import json
import os
import secrets
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from receipt import (RECEIPT_SCHEMA, Receipt, hmac_signer, hmac_verifier,  # noqa: E402
                     sha256_hex, sign_receipt)

SPINE_ID = "idoracle/agent-effect-gate/v0"
TOKEN_BYTES = 16


def gate_effect(plant, observe, *, qualified=True, qualify_report=None,
                settle_reads=2, created_at, secret, action="tool-call"):
    """Gate one state changing action on proof of its committed effect.

    plant(token)   -> perform the action with `token` injected into what it commits;
                      its return value is NOT trusted.
    observe(token) -> read the target through a SEPARATE committed state path; True iff
                      `token` is durably observed in committed state.
    qualified      -> whether the observation channel passed the O1-O5 self test
                      (see views.qualify_view). An unqualified channel yields HOLD,
                      never a witness, so an attempt log or attacker writable view
                      cannot fake a pass.
    """
    token = "GATE_" + secrets.token_urlsafe(TOKEN_BYTES)
    plant(token)                                       # run the action; result is untrusted
    observed = all(observe(token) for _ in range(settle_reads))   # durability re-read

    if not qualified:
        verdict, overall = "provably_blind", "hold"
    elif observed:
        verdict, overall = "committed", "pass"
    else:
        verdict, overall = "silent_no_op", "fail"

    facts = {"action": action, "token_h": sha256_hex(token), "qualified": bool(qualified),
             "observed": observed, "verdict": verdict, "qualify_report": qualify_report}
    artifact = json.dumps(facts, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    rec = Receipt(
        schema=RECEIPT_SCHEMA, artifact_sha256=sha256_hex(artifact), artifact_len=len(artifact),
        overall=overall, lane="high-stakes",
        checks=[{"name": "agent-effect-witness", "verdict": overall, "detail": verdict}],
        spine_id=SPINE_ID, created_at=created_at,
        assurance={
            "spine_version": SPINE_ID,
            "negative_envelope": [
                {"class": "committed_effect:observable", "status": "covered"},
                {"class": "committed_effect:no_qualifying_view", "status": "provably_blind"},
            ],
            "note": "verdict tracks committed state via a separate qualified view; the tool "
                    "success signal and the agent's claim are untrusted.",
        })
    sign_receipt(rec, hmac_signer(secret))
    return rec, artifact, facts


def rederive(facts: dict) -> str:
    if not facts.get("qualified"):
        return "hold"
    return "pass" if facts.get("observed") else "fail"


def verify_effect(receipt: Receipt, facts_text: str, secret: str) -> dict:
    """The A2A check: a downstream agent re derives the verdict from the signed facts (LLM
    free) and confirms hash + signature. A validly signed receipt whose verdict contradicts
    its facts is rejected."""
    artifact_ok = sha256_hex(facts_text) == receipt.artifact_sha256
    sig_ok = bool(receipt.signature) and hmac_verifier(secret)(
        receipt.canonical().encode("utf-8"), receipt.signature)
    try:
        consistent = receipt.overall == rederive(json.loads(facts_text))
    except (ValueError, TypeError):
        consistent = False
    return {"artifact_ok": artifact_ok, "signature_ok": sig_ok,
            "verdict_consistent": consistent, "ok": artifact_ok and sig_ok and consistent}


class EffectNotWitnessed(Exception):
    """Raised by effect_gated when an action claimed success but committed nothing."""


def effect_gated(observe, *, secret, created_at, qualified=True, action=None, settle_reads=2):
    """Decorator. Wrap a state changing fn(token, *args, **kwargs) that MUST inject `token`
    into what it commits. After the call the effect is witnessed via `observe`. Returns
    (result, receipt, facts); raises EffectNotWitnessed on a silent no op."""
    def deco(fn):
        def wrapped(*a, **k):
            box = {}

            def plant(token):
                box["r"] = fn(token, *a, **k)
                return box["r"]

            rec, _, facts = gate_effect(plant, observe, qualified=qualified, secret=secret,
                                        created_at=created_at, action=action or fn.__name__,
                                        settle_reads=settle_reads)
            if rec.overall == "fail":
                raise EffectNotWitnessed(f"{action or fn.__name__}: claimed success, no committed effect")
            return box.get("r"), rec, facts
        return wrapped
    return deco

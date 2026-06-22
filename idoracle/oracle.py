"""Canary-write-IDOR oracle (v2): a black-box, status-code-agnostic, SOUND witness
for unauthorized cross-principal writes, emitting a signed verified-autonomy receipt.

Hardened against an adversarial soundness audit that broke v1. The baseline is now
established from an AUTHORIZED A-side READ-BACK of the stored value (never the token
the oracle sent, never the POST echo), and the probe is gated on create + read-back
success - so server-side normalization, non-writable fields, plant failures, and
ambient object disappearance become honest HOLDs, not false witnesses.

Protocol, per reference the tester can PLANT (create as principal A):
  1. As A, create the object with a fresh 128-bit CSPRNG token in EACH tester-writable
     field (`canary`, `title`). If create is not 2xx / has no id -> HOLD (inconclusive).
  2. As A, RE-READ (authorized GET). A field is CONFIRMED plantable iff its stored
     value equals exactly the token sent. If NO field is confirmed -> HOLD
     (provably_blind: nothing faithfully writable to witness on).
  3. As B, attempt to overwrite the CONFIRMED fields with fresh tokens.
  4. As A, RE-READ. WITNESS iff any confirmed field's value != its planted baseline.
     If the object is GONE -> HOLD (inconclusive: a PATCH-overwrite probe cannot
     attribute disappearance to B; unauthorized DELETE is out of envelope).

Soundness (narrow, audited): a change to a confirmed-round-tripping high-entropy
field, induced by B, that only A could authorize, IS by construction an authz
violation -> zero false positives on confirmed-plantable fields, modulo a 2^-128
token collision AND the precondition that B cannot READ the planted token. The
verdict reads ONLY re-read state, never B's HTTP status. Multi-field planting closes
the v1 sibling-field false negative (a write to `title` while `canary` is untouched
now fires). Blindness is declared in the receipt's negative-capability envelope.
"""

import json
import os
import secrets
import sys
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from receipt import (  # noqa: E402
    RECEIPT_SCHEMA, Receipt, hmac_verifier, hmac_signer, sha256_hex, sign_receipt)

SPINE_ID = "authz-canary/v0"
TOKEN_BYTES = 16  # 128-bit
CANARY_FIELDS = ["canary", "title"]

_OVERALL = {"witness": "fail", "clean": "pass",
            "provably_blind": "hold", "inconclusive": "hold"}
_DETAIL = {
    "witness": "unauthorized cross-principal write confirmed via canary read-back",
    "clean": "no unauthorized write to any confirmed-plantable field",
    "provably_blind": "no tester-plantable field; oracle asserts nothing here",
    "inconclusive": "could not establish a sound baseline / object vanished out-of-band",
}


def _negative_envelope():
    """Signed domain of validity: what this oracle covers, is blind to, and assumes."""
    return {
        "spine_version": SPINE_ID,
        "negative_envelope": [
            {"class": "write_idor:confirmed_planted_field", "status": "covered"},
            {"class": "write_idor:unplantable_or_unconfirmed_field", "status": "provably_blind"},
            {"class": "write_idor:other_verbs_PUT_DELETE_bulk", "status": "provably_blind"},
            {"class": "unauthorized_delete", "status": "provably_blind"},
            {"class": "transient_or_unechoed_state", "status": "provably_blind"},
            {"class": "read_idor", "status": "provably_blind"},
            {"class": "bfla_function_level", "status": "uncalibrated"},
            {"class": "mass_assignment", "status": "uncalibrated"},
        ],
        "soundness_preconditions": [
            "linearizable_read_your_writes_target",
            "stateless_per_request_principal_auth(header/bearer); cookie+CSRF uncalibrated",
            "B_cannot_read_the_planted_token(no read-IDOR / no state-echo) else 2^-128 void",
            "quiescent_test_tenant(no other writer mutates the object in-window)",
            "field_round_trips_exactly(confirmed via authorized A read-back before B acts)",
        ],
    }


def _http(base, method, path, principal, body=None, auth=None):
    data = json.dumps(body).encode("utf-8") if body is not None else None
    headers = dict(auth(principal)) if auth else {"X-Principal": principal}
    headers.setdefault("Content-Type", "application/json")     # auth maps a logical
    req = urllib.request.Request(base + path, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            raw = resp.read()
            return resp.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as e:
        try:
            raw = e.read()
            try:
                return e.code, (json.loads(raw) if raw else None)
            except ValueError:
                return e.code, None
        finally:
            e.close()
    except (urllib.error.URLError, OSError):
        return None, None


def _emit(facts, status, created_at, secret):
    """Construct + HMAC-sign a receipt over the canonical witness facts."""
    artifact = json.dumps(facts, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    overall = _OVERALL[status]
    rec = Receipt(
        schema=RECEIPT_SCHEMA,
        artifact_sha256=sha256_hex(artifact),
        artifact_len=len(artifact),
        overall=overall,
        lane="high-stakes",
        checks=[{"name": "canary-write-witness", "verdict": overall, "detail": _DETAIL[status]}],
        spine_id=SPINE_ID,
        created_at=created_at,
        assurance=_negative_envelope(),
    )
    sign_receipt(rec, hmac_signer(secret))
    return rec, artifact, facts


def _facts(collection, **kw):
    base = {"collection": collection, "note_id": None, "plantable_confirmed": False,
            "confirmed_fields": [], "confirmed_owner": None, "confirmed_shared": None,
            "b_http_status": None, "a_reread_status": None,
            "object_gone": False, "changed_fields": [], "witness": False,
            "asserted_bug": False, "verdict": "inconclusive"}
    base.update(kw)
    return base


def probe(base_url, collection, principal_a="A", principal_b="B", *,
          plantable=True, fields=None, create_extra=None, auth=None,
          confirm_shared=True, created_at, secret):
    """Probe one object reference. Returns (receipt, artifact_text, facts).

    `collection` is an opaque path; the oracle does not know the target's mode.
    `plantable=False` models a pre-existing object the tester cannot create.
    `create_extra` carries tester-set declared state (e.g. {"shared": True}) sent
    at plant time; the oracle does not interpret it, it is just a create field.
    `auth(principal) -> headers` makes the oracle target-agnostic (Bearer, cookie,
    etc.); default is the `X-Principal` header. `confirm_shared=False` is for targets
    with NO sharing model (no `shared` field to confirm) - treat every object as
    non-shared, i.e. the construction-sound A_owns cell.
    """
    fields = list(fields or CANARY_FIELDS)
    if not plantable:
        return _emit(_facts(collection, verdict="provably_blind"), "provably_blind",
                     created_at, secret)

    planted = {f: secrets.token_urlsafe(TOKEN_BYTES) for f in fields}
    planted_shared = bool((create_extra or {}).get("shared", False))
    body = dict(planted)
    body.update(create_extra or {})
    c_status, note = _http(base_url, "POST", collection, principal_a, body, auth=auth)
    nid = (note or {}).get("id")
    if c_status is None or not (200 <= c_status < 300) or nid is None:
        return _emit(_facts(collection, verdict="inconclusive", note_id=nid),
                     "inconclusive", created_at, secret)  # plant failed -> HOLD

    item = f"{collection}/{nid}"
    bl_status, baseline = _http(base_url, "GET", item, principal_a, auth=auth)
    if bl_status != 200 or baseline is None:
        return _emit(_facts(collection, verdict="inconclusive", note_id=nid,
                            a_reread_status=bl_status), "inconclusive", created_at, secret)

    # The CLASSIFYING fields (owner, shared) must be CONFIRMED from the read-back, not
    # trusted as tester assertions - else a server that reassigns ownership or ignores
    # the visibility flag silently flips the bug verdict. Same discipline as the canary.
    bl_owner = baseline.get("owner")
    bl_shared = baseline.get("shared") if confirm_shared else False
    if bl_owner != principal_a:                          # plant did not yield an A-owned object
        return _emit(_facts(collection, verdict="provably_blind", note_id=nid,
                            a_reread_status=bl_status, confirmed_owner=bl_owner),
                     "provably_blind", created_at, secret)
    if confirm_shared and baseline.get("shared") != planted_shared:  # visibility server-controlled
        return _emit(_facts(collection, verdict="provably_blind", note_id=nid,
                            a_reread_status=bl_status, confirmed_owner=bl_owner,
                            confirmed_shared=baseline.get("shared")), "provably_blind",
                     created_at, secret)

    confirmed = [f for f in fields if baseline.get(f) == planted[f]]
    if not confirmed:                                   # nothing faithfully writable
        return _emit(_facts(collection, verdict="provably_blind", note_id=nid,
                            a_reread_status=bl_status, confirmed_owner=bl_owner,
                            confirmed_shared=bl_shared), "provably_blind", created_at, secret)

    t_b = {f: secrets.token_urlsafe(TOKEN_BYTES) for f in confirmed}
    b_status, _ = _http(base_url, "PATCH", item, principal_b, t_b, auth=auth)

    rr_status, reread = _http(base_url, "GET", item, principal_a, auth=auth)
    gone = (rr_status == 404 or reread is None)
    if gone:                                            # cannot attribute -> HOLD
        return _emit(_facts(collection, verdict="inconclusive", note_id=nid,
                            plantable_confirmed=True, confirmed_fields=confirmed,
                            confirmed_owner=bl_owner, confirmed_shared=bl_shared,
                            b_http_status=b_status, a_reread_status=rr_status,
                            object_gone=True), "inconclusive", created_at, secret)

    if reread.get("owner") != bl_owner or (confirm_shared and reread.get("shared") != bl_shared):
        return _emit(_facts(collection, verdict="inconclusive", note_id=nid,  # class moved in-window
                            plantable_confirmed=True, confirmed_fields=confirmed,
                            confirmed_owner=bl_owner, confirmed_shared=bl_shared,
                            b_http_status=b_status, a_reread_status=rr_status),
                     "inconclusive", created_at, secret)

    changed = [f for f in confirmed if reread.get(f) != planted[f]]
    witness = bool(changed)
    facts = _facts(collection, note_id=nid, plantable_confirmed=True,
                   confirmed_fields=confirmed, confirmed_owner=bl_owner,
                   confirmed_shared=bl_shared, b_http_status=b_status,
                   a_reread_status=rr_status, object_gone=False, changed_fields=changed,
                   witness=witness, asserted_bug=witness,
                   verdict=("witness" if witness else "clean"))
    return _emit(facts, "witness" if witness else "clean", created_at, secret)


def discover_writable_fields(base_url, collection, *, principal="A", candidate_fields,
                             auth=None):
    """Find which candidate fields a target actually round-trips (the target profile an
    arbitrary app needs - the oracle must DISCOVER its writable fields, not assume
    `canary`/`title`). Plants each candidate as `principal`, reads back, keeps the ones
    stored verbatim. Returns [] if the object cannot be created/read."""
    planted = {f: secrets.token_urlsafe(TOKEN_BYTES) for f in candidate_fields}
    c_status, note = _http(base_url, "POST", collection, principal, planted, auth=auth)
    nid = (note or {}).get("id")
    if c_status is None or not (200 <= c_status < 300) or nid is None:
        return []
    bl_status, baseline = _http(base_url, "GET", f"{collection}/{nid}", principal, auth=auth)
    if bl_status != 200 or baseline is None:
        return []
    return [f for f in candidate_fields if baseline.get(f) == planted[f]]


def rederive_verdict(facts: dict) -> str:
    """Re-derive overall purely from the facts - the verdict-correctness check the
    generic offline verifier does NOT do (it only checks hash + signature)."""
    if not facts.get("plantable_confirmed"):
        return "hold"
    if facts.get("object_gone"):
        return "hold"
    return "fail" if facts.get("changed_fields") else "pass"


def verify_witness(receipt: Receipt, facts_text: str, secret: str) -> dict:
    """Full receipt check: artifact hash, HMAC signature, AND that `overall` is the
    verdict the facts actually imply (closes the 'signed assertion != correctness' gap)."""
    artifact_ok = sha256_hex(facts_text) == receipt.artifact_sha256
    sig_ok = bool(receipt.signature) and hmac_verifier(secret)(
        receipt.canonical().encode("utf-8"), receipt.signature)
    try:
        facts = json.loads(facts_text)
        expected = rederive_verdict(facts)
        consistent = (receipt.overall == expected
                      and bool(facts.get("changed_fields")) == bool(facts.get("witness"))
                      and facts.get("asserted_bug") == (receipt.overall == "fail"))
    except (ValueError, TypeError):
        expected, consistent = None, False
    return {"artifact_ok": artifact_ok, "signature_ok": sig_ok,
            "verdict_consistent": consistent, "expected_overall": expected,
            "ok": artifact_ok and sig_ok and consistent}

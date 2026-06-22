#!/usr/bin/env python3
"""Standalone ARES tool: sound write-IDOR/BOLA witness from a JSON recipe.

ARES discovers candidate access-control findings; this tool VALIDATES one soundly and
emits a signed verdict. Zero coupling to the ARES app package, stdlib only (mirrors the
backend/tools/verify_proof.py convention). The witness is the canary method: principal A
plants an object, principal B (the attacker) writes a fresh high-entropy token into it,
and an authorized observation view is re-read - a token observed in committed state is a
deterministic, status-code-agnostic proof of an unauthorized write (FP <= 2^-128). Absence
is INCONCLUSIVE, never a no-write claim.

Recipe (stdin or --recipe file): see authz_canary/recipes/*.json. Steps: auth (per
principal), plant (as A), locate (find the planted object's id), attack (B writes <CANARY>),
observe (re-read a committed-state view, durability re-read past a settle). Placeholders
<A.email> <B.email> <located.FIELD> <CANARY> are resolved at run time.

Exit 0 = sound witness (confirmed unauthorized write); 2 = no witness (clean/inconclusive);
1 = recipe/transport error. Prints the signed verdict JSON on stdout.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import secrets
import sys
import urllib.error
import urllib.request

TOOL = "ares/authz-witness/v0"


def _canon(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def _dig(obj, path):
    for k in path.split("."):
        if isinstance(obj, dict):
            obj = obj.get(k)
        else:
            return None
    return obj


def _http(base, method, path, headers, body=None):
    data = json.dumps(body).encode("utf-8") if body is not None else None
    h = dict(headers)
    h.setdefault("Content-Type", "application/json")
    req = urllib.request.Request(base + path, data=data, method=method, headers=h)
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            raw = resp.read()
            return resp.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as e:
        try:
            raw = e.read()
            return e.code, (json.loads(raw) if raw else None)
        except Exception:                                    # noqa: BLE001
            return e.code, None
    except (urllib.error.URLError, OSError):
        return None, None


def _resolve(value, ctx):
    if isinstance(value, str) and value.startswith("<") and value.endswith(">"):
        key = value[1:-1]
        if key == "CANARY":
            return ctx["canary"]
        if key.startswith("located."):
            return ctx["located"].get(key.split(".", 1)[1])
        if "." in key:                                       # <A.email>
            p, f = key.split(".", 1)
            return ctx["users"].get(p, {}).get(f)
    if isinstance(value, dict):
        return {k: _resolve(v, ctx) for k, v in value.items()}
    if isinstance(value, list):
        return [_resolve(v, ctx) for v in value]
    return value


def run(recipe, *, secret):
    base = recipe["base"]
    ctx = {"users": recipe["auth"]["users"], "canary": "CANARY_" + secrets.token_urlsafe(16),
           "located": {}, "tokens": {}}

    # auth: bearer login per principal
    for p, creds in recipe["auth"]["users"].items():
        s, d = _http(base, "POST", recipe["auth"]["login_path"], {},
                     {recipe["auth"].get("user_field", "email"): creds.get("email", creds.get("username")),
                      recipe["auth"].get("pass_field", "password"): creds["password"]})
        ctx["tokens"][p] = _dig(d or {}, recipe["auth"]["token_json_path"])

    def hdr(principal):
        tok = ctx["tokens"].get(principal)
        scheme = recipe["auth"].get("scheme", "Bearer ")
        return {"Authorization": scheme + tok} if tok else {}

    def step(spec):
        return _http(base, spec["method"], _resolve(spec["path"], ctx), hdr(spec["principal"]),
                     _resolve(spec.get("body"), ctx) if "body" in spec else None)

    plant_status, _ = step(recipe["plant"])

    loc = recipe["locate"]
    _, ld = step(loc)
    items = _dig(ld or {}, loc["collection_json_path"]) or []
    match = _resolve(loc.get("match", {}), ctx)
    found = [it for it in items if all(it.get(k) == v for k, v in match.items())]
    if found:
        ctx["located"] = found[-1]

    attack_status, _ = step(recipe["attack"])               # B writes <CANARY>

    obs = recipe["observe"]

    def observed():
        _, od = step(obs)
        rows = _dig(od or {}, obs["collection_json_path"]) or []
        return any(ctx["canary"] in str(r.get(obs["canary_in_field"]) or "") for r in rows)

    witness = bool(ctx["located"]) and all(observed() for _ in range(2))

    facts = {"tool": TOOL, "base": base, "plant_status": plant_status,
             "attack_status": attack_status, "located": bool(ctx["located"]),
             "witness": witness, "verdict": "witness" if witness else "inconclusive"}
    overall = "fail" if witness else "hold"
    claims = {
        "tool": TOOL, "overall": overall, "artifact_sha256": hashlib.sha256(_canon(facts)).hexdigest(),
        "facts": facts,
        "envelope": {"covered": "unauthorized write to the planted field, witnessed via a "
                                 "committed-state observation view (canary, status-code-agnostic)",
                     "preconditions": ["content-only observation model",
                                       "view reflects committed state (run the negative control "
                                       "to qualify it before trusting on a new target)",
                                       "durability re-read past the settle window"],
                     "prior_art": "mechanism: BACScan (Liu et al., CCS 2025); honeytokens (Spitzner)"}}
    sig = hmac.new(secret.encode(), _canon(claims), hashlib.sha256).hexdigest()
    return {"claims": claims, "signature": {"alg": "HMAC-SHA256", "sig": sig}}, witness


def main(argv=None):
    ap = argparse.ArgumentParser(description="Sound write-IDOR/BOLA witness from a recipe.")
    ap.add_argument("--recipe", help="recipe JSON file (default: stdin)")
    ap.add_argument("--secret", default=os.environ.get("ARES_WITNESS_HMAC", "ares-witness"))
    a = ap.parse_args(argv)
    recipe = json.load(open(a.recipe, encoding="utf-8")) if a.recipe else json.load(sys.stdin)
    try:
        verdict, witness = run(recipe, secret=a.secret)
    except (KeyError, TypeError, ValueError) as exc:
        sys.stderr.write(f"authz-witness: bad recipe/transport: {exc}\n")
        return 1
    print(json.dumps(verdict, indent=2))
    return 0 if witness else 2


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Offline receipt verifier - pure stdlib, no install, no network.

Proof, not promise: anyone can confirm a receipt themselves. Checks the artifact
hash, the (optional) HMAC signature, and prints the assurance the receipt carries
(per-class FN bounds + the negative capability envelope - what the check provably
cannot catch). Handles a bare receipt or a DSSE/in-toto envelope.

    python offline_verify.py receipt.json deliverable.txt [hmac_secret]
"""
import hashlib
import hmac
import json
import sys

r = json.load(open(sys.argv[1], encoding="utf-8"))
text = open(sys.argv[2], encoding="utf-8").read()
secret = sys.argv[3] if len(sys.argv) > 3 else None

if r.get("payloadType") == "application/vnd.in-toto+json" and "statement" in r:  # unwrap DSSE
    sig0 = (r.get("signatures") or [None])[0] or {}
    r = dict(r["statement"]["predicate"])
    r["signature"] = sig0

claims = {k: v for k, v in r.items() if k != "signature"}
canon = json.dumps(claims, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
artifact_ok = hashlib.sha256(text.encode("utf-8")).hexdigest() == r["artifact_sha256"]
sig = r.get("signature") or {}
sig_ok = bool(secret) and sig.get("alg") == "HMAC-SHA256" and hmac.compare_digest(
    hmac.new(secret.encode(), canon.encode("utf-8"), hashlib.sha256).hexdigest(), sig.get("sig", ""))

print("artifact_ok :", artifact_ok)
print("signature   :", "ok" if sig_ok else ("FAIL" if secret else "not checked"))
print("verdict     :", r.get("overall"), "| lane:", r.get("lane"))
print("assurance   :", json.dumps(r.get("assurance"), ensure_ascii=False))
sys.exit(0 if artifact_ok and (sig_ok or not secret) else 4)

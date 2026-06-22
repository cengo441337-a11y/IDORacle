#!/usr/bin/env python3
"""ARES-native standalone authz_witness tool (IDORacle fusion).

Standalone stdlib style matching verify_proof.py.
Recipe-driven. Signed verdict out.

Drop into backend/tools/ and register in native_tools.py
"""

import argparse
import json
import sys
import hashlib
import hmac
import time
import requests

DEMO_KEY = b"ares-idoracle-fusion-2026"

def sign_verdict(verdict):
    payload = json.dumps(verdict, sort_keys=True).encode()
    digest = hashlib.sha256(payload).hexdigest()
    sig = hmac.new(DEMO_KEY, digest.encode(), hashlib.sha256).hexdigest()
    verdict["receipt"] = {"sha256": digest, "hmac": sig}
    return json.dumps(verdict, indent=2)

def run_witness(recipe):
    target = recipe["target"]
    candidate = recipe["candidate"]
    base = target["base_url"]
    write_url = candidate["write_url"]
    view_url = candidate["view_url"]
    a_token = candidate["attacker_token"]
    o_token = candidate.get("owner_token", a_token)
    canary = f"canary-{int(time.time())}-{hashlib.sha256(b'r').hexdigest()[:8]}"
    
    headers = {"Authorization": f"Bearer {a_token}"}
    try:
        p = {**candidate.get("payload", {}), "name": canary}
        r = requests.put(f"{base}{write_url}", json=p, headers=headers, timeout=10)
        plant_ok = r.status_code in (200, 201, 204)
    except:
        plant_ok = False
    
    witnessed = False
    if plant_ok:
        try:
            ro = requests.get(f"{base}{view_url}", headers={"Authorization": f"Bearer {o_token}"}, timeout=10)
            witnessed = canary in (ro.text if ro.ok else "")
        except:
            pass
    
    return {
        "tool": "authz_witness",
        "version": "0.1-idoracle-fusion",
        "overall": "fail" if witnessed else "pass",
        "witness": witnessed,
        "plant_status": getattr(r, "status_code", 0) if "r" in locals() else 0,
        "canary": canary,
        "ts": time.time()
    }

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--recipe", required=True)
    args = ap.parse_args()
    with open(args.recipe) as f:
        recipe = json.load(f)
    v = run_witness(recipe)
    print(sign_verdict(v))
    sys.exit(0)

if __name__ == "__main__":
    main()

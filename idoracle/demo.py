"""Run every soundness scenario against the deterministic target and print the
result table, then show that a validly-signed receipt with a wrong verdict is
rejected by verdict re-derivation.

    python authz_canary/demo.py
"""

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.abspath(os.path.join(HERE, "..")))

import oracle  # noqa: E402
from target_app import make_server  # noqa: E402
from receipt import hmac_signer, sign_receipt  # noqa: E402

TS = "2026-06-22T00:00:00+00:00"
SECRET = "demo-secret"

ROWS = [
    ("secure", "denied, no write"),
    ("bola", "allowed cross-principal write"),
    ("decoy_200_noop", "200 but silent no-op"),
    ("decoy_403_wrote", "403 but wrote anyway"),
    ("sibling_write", "writes title, not canary"),
    ("normalize", "server lowercases canary"),
    ("readonly_canary", "canary not writable"),
    ("ghost", "object vanishes"),
]


def main():
    server, base, store = make_server()
    try:
        print("Canary-write-IDOR oracle v2 - soundness table "
              "(verdict tracks STATE, not status)\n")
        print(f"{'target behaviour':<30}{'B status':<10}{'changed':<14}{'receipt'}")
        print("-" * 66)
        for mode, label in ROWS:
            store.reset()
            rec, _, f = oracle.probe(base, f"/api/{mode}/notes", created_at=TS, secret=SECRET)
            changed = ",".join(f["changed_fields"]) or ("gone" if f["object_gone"] else "-")
            print(f"{label:<30}{str(f['b_http_status'] or '-'):<10}{changed:<14}{rec.overall}")
        rec_pb, _, _ = oracle.probe(base, "/api/secure/notes", plantable=False,
                                    created_at=TS, secret=SECRET)
        print(f"{'pre-existing (cannot plant)':<30}{'n/a':<10}{'-':<14}"
              f"{rec_pb.overall}  <- provably_blind")

        print("\nIntegrity - the verdict is re-derived from the signed facts, not trusted:")
        store.reset()
        rec, artifact, _ = oracle.probe(base, "/api/secure/notes", created_at=TS, secret=SECRET)
        print(f"  honest 'pass' receipt -> verify_witness ok="
              f"{oracle.verify_witness(rec, artifact, SECRET)['ok']}")
        forged = oracle.Receipt(**{k: v for k, v in rec.__dict__.items() if k != "signature"})
        forged.overall = "fail"
        sign_receipt(forged, hmac_signer(SECRET))
        res = oracle.verify_witness(forged, artifact, SECRET)
        print(f"  forged 'fail' (validly signed) -> signature_ok={res['signature_ok']} "
              f"but verdict_consistent={res['verdict_consistent']} -> ok={res['ok']}")
    finally:
        server.shutdown()


if __name__ == "__main__":
    main()

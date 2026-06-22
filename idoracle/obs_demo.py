"""Show the observability soundness self-test: which views qualify, and a foreign-object
write witnessed via a qualified view WITHOUT ever reading the object.

    python authz_canary/obs_demo.py
"""

import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.abspath(os.path.join(HERE, "..")))

import views  # noqa: E402
from obs_target import make_obs_server  # noqa: E402

TS = "2026-06-22T00:00:00+00:00"
SECRET = "obs-demo-secret"


def _api(base, method, path, principal="anon", body=None, q=None):
    url = base + path + (("?q=" + urllib.parse.quote(q)) if q is not None else "")
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=data, method=method,
                                 headers={"X-Principal": principal,
                                          "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read() or b"null")
    except urllib.error.HTTPError as e:
        try:
            return e.code, None
        finally:
            e.close()


def main():
    srv, base, _ = make_obs_server("bola")
    try:
        v = lambda name, path, kind: views.View(  # noqa: E731
            name, (lambda t: _api(base, "GET", path, "B", q=t)[1]["hit"]), kind)
        controls = dict(
            committer=lambda t: _api(base, "POST", "/notes", "A", {"canary": t}),
            dropper=lambda t: _api(base, "POST", "/control_drop", "B", {"canary": t}),
            alt_injectors=[lambda t: _api(base, "POST", "/feed", "B", {"canary": t})])

        print("Observability self-test - which views are SOUND to witness on?\n")
        print(f"{'view':<14}{'kind':<22}{'O3':<5}{'O2prime':<9}{'O4prime':<9}qualifies")
        print("-" * 70)
        for name, path, kind in [("search", "/search", "committed-state"),
                                 ("db_replica", "/db_replica", "greybox-db-replica"),
                                 ("oob", "/oob", "oob-webhook"),
                                 ("audit", "/audit", "attempt-derived"),
                                 ("search_plus", "/search_plus", "state+attacker-feed")]:
            ok, r = views.qualify_view(v(name, path, kind), **controls)
            print(f"{name:<14}{kind:<22}{str(r['O3_entropy_preserving']):<5}"
                  f"{str(r['O2_commit_gated']):<9}{str(r['O4_unique_causal_path']):<9}{ok}")

        # foreign-object witness via the qualified search view, no GET of the object
        _, note = _api(base, "POST", "/notes", "A", {"canary": "seed"})
        nid = note["id"]
        b_read = _api(base, "GET", f"/notes/{nid}", "B")[0]
        search = v("search", "/search", "committed-state")
        w = views.witness_via_view(
            search, lambda t: _api(base, "PATCH", f"/notes/{nid}", "B", {"canary": t})[0])
        print(f"\nForeign object (B cannot read it: GET -> {b_read}); B writes it on a BOLA app:")
        print(f"  witnessed via qualified 'search' view: {w['witness']}  "
              f"(verdict={w['verdict']}, B's PATCH status={w['b_http_status']})")
    finally:
        srv.shutdown()


if __name__ == "__main__":
    main()

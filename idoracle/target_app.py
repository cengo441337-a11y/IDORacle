"""Deterministic black-box target app for the canary-write-IDOR oracle proof.

stdlib http.server + in-memory store. Notes have two tester-writable fields
(`canary`, `title`) so the oracle's multi-field witness can be exercised. The
access mode lives in the URL the tester points the oracle at; the oracle never
receives it and only observes HTTP responses + its own authorized re-reads.

Modes (non-owner PATCH behaviour), chosen to attack the oracle's soundness:

  secure          -> 403, no write                         (must NOT fire)
  bola            -> 200, writes the sent fields           (MUST fire)
  decoy_200_noop  -> 200, no write                         (must NOT fire: silent 200)
  decoy_403_wrote -> 403, writes the sent fields           (MUST fire: 403 but wrote)
  sibling_write   -> 200, writes ONLY `title` (not canary) (MUST fire via title)
  ghost           -> 403, DELETES the object               (gone -> HOLD, never a write-witness)

Store transforms that attack the FALSE-POSITIVE surface (applied on EVERY store,
incl. the owner's own create):

  normalize       -> the server lower-cases the stored `canary`   (A-side normalization)
  readonly_canary -> the server ignores `canary`, stores a constant (non-writable field)

A sound oracle must (a) NOT fire on secure/decoy_200_noop/normalize/readonly_canary,
(b) fire on bola/decoy_403_wrote/sibling_write, (c) HOLD on ghost. No randomness or
wall-clock in the authorization path; the store resets to empty between runs.
"""

import json
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MODES = {"secure", "bola", "decoy_200_noop", "decoy_403_wrote", "sibling_write",
         "ghost", "normalize", "readonly_canary", "sharing",
         "ignore_shared", "reassign_owner", "flaky_acl"}
WRITE_ON_PATCH = {"bola", "decoy_403_wrote"}            # writes all sent fields
_COLL = re.compile(r"^/api/(\w+)/notes$")
_ITEM = re.compile(r"^/api/(\w+)/notes/(\d+)$")


def _store_value(mode, field, val):
    """How the server mangles a value at store time (the FP attack surface)."""
    if mode == "normalize" and field == "canary" and isinstance(val, str):
        return val.lower()
    if mode == "readonly_canary" and field == "canary":
        return "RO_SERVER_DEFAULT"
    return val


class Store:
    def __init__(self):
        self._lock = threading.Lock()
        self.reset()

    def reset(self):
        with self._lock:
            self._notes = {}
            self._next_id = 1

    def create(self, mode, owner, body):
        with self._lock:
            nid = self._next_id
            self._next_id += 1
            stored_owner = "B" if mode == "reassign_owner" else owner  # server-assigned ownership
            stored_shared = False if mode == "ignore_shared" else bool(body.get("shared", False))
            self._notes[nid] = {
                "id": nid, "owner": stored_owner, "mode": mode,
                "shared": stored_shared,  # declared visibility state (may be server-controlled)
                "canary": _store_value(mode, "canary", body.get("canary")),
                "title": _store_value(mode, "title", body.get("title")),
            }
            return dict(self._notes[nid])

    def read(self, nid):
        with self._lock:
            n = self._notes.get(nid)
            return dict(n) if n else None

    def _write_fields(self, n, body):
        for f in ("canary", "title"):
            if f in body:
                n[f] = _store_value(n["mode"], f, body[f])

    def patch(self, nid, principal, body):
        """Return http_status. State change is a pure function of (owner, mode)."""
        with self._lock:
            n = self._notes.get(nid)
            if n is None:
                return 404
            if principal == n["owner"]:                     # legitimate owner write
                self._write_fields(n, body)
                return 200
            mode = n["mode"]                                # non-owner: mode decides
            if mode in WRITE_ON_PATCH:
                self._write_fields(n, body)
                return 200 if mode == "bola" else 403
            if mode == "sibling_write":                     # writes ONLY title
                if "title" in body:
                    n["title"] = _store_value(mode, "title", body["title"])
                return 200
            if mode == "decoy_200_noop":
                return 200
            if mode == "flaky_acl":                         # per-object ACL: a hidden
                if nid % 2 == 0:                            # splitting dimension within
                    self._write_fields(n, body)             # one declared class (id parity)
                    return 200
                return 403
            if mode == "sharing":                           # B may write iff shared
                if n["shared"]:
                    self._write_fields(n, body)
                    return 200
                return 403
            if mode == "ghost":                             # vanishes (not a write)
                del self._notes[nid]
                return 403
            return 403                                      # secure / normalize / readonly_canary

    def delete(self, nid, principal):
        with self._lock:
            n = self._notes.get(nid)
            if n is None:
                return 404
            if principal == n["owner"] or n["mode"] == "bola":
                del self._notes[nid]
                return 200
            return 403


def make_handler(store):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_a):
            return

        def _send(self, code, body=None):
            payload = json.dumps(body).encode("utf-8") if body is not None else b""
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            if payload:
                self.wfile.write(payload)

        def _principal(self):
            return self.headers.get("X-Principal", "anon")

        def _body(self):
            n = int(self.headers.get("Content-Length", 0) or 0)
            if not n:
                return {}
            try:
                return json.loads(self.rfile.read(n) or b"{}")
            except ValueError:
                return {}

        def _view(self, note):
            return {"id": note["id"], "owner": note["owner"], "shared": note["shared"],
                    "canary": note["canary"], "title": note["title"]}

        def do_POST(self):
            m = _COLL.match(self.path)
            if not m or m.group(1) not in MODES:
                return self._send(404, {"error": "no route"})
            note = store.create(m.group(1), self._principal(), self._body())
            self._send(201, self._view(note))

        def do_GET(self):
            m = _ITEM.match(self.path)
            if not m:
                return self._send(404, {"error": "no route"})
            note = store.read(int(m.group(2)))
            if note is None:
                return self._send(404, {"error": "gone"})
            # reassign_owner grants A a tenant read so the canary still round-trips
            # while ownership is the server-assigned 'B' (the attack scenario).
            if self._principal() != note["owner"] and note["mode"] != "reassign_owner":
                return self._send(403, {"error": "forbidden"})
            self._send(200, self._view(note))

        def do_PATCH(self):
            m = _ITEM.match(self.path)
            if not m:
                return self._send(404, {"error": "no route"})
            self._send(store.patch(int(m.group(2)), self._principal(), self._body()),
                       {"ok": True})

        def do_DELETE(self):
            m = _ITEM.match(self.path)
            if not m:
                return self._send(404, {"error": "no route"})
            self._send(store.delete(int(m.group(2)), self._principal()), {"ok": True})

    return Handler


def make_server(host="127.0.0.1", port=0):
    """Start the target on an ephemeral port in a daemon thread.
    Returns (server, base_url, store)."""
    store = Store()
    server = ThreadingHTTPServer((host, port), make_handler(store))
    base_url = f"http://{host}:{server.server_address[1]}"
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, base_url, store

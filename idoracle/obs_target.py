"""Deterministic observation-surface target for the observability soundness self-test.

Models a SaaS app where the tester (principal B) cannot GET a foreign object owned by
A, but other authorized surfaces may reflect it. The surfaces are deliberately of
different KINDS so the soundness self-test can tell them apart:

  GET  /search?q=     committed-STATE view: hit iff q is in a committed note field
  GET  /audit?q=      ATTEMPT-derived view: hit iff q was in ANY attempted write body
                      (including rejected / dropped ones) -> the request-log trap
  GET  /feed?q=       directly attacker-WRITABLE view (an alternate causal path)
  POST /feed          write a token straight into the feed (no note commit)
  POST /control_drop  accepted (200) but NON-COMMITTING write via the real path
                      (the negative control: a genuine non-commit, NOT an early reject)
  POST /notes         create as the calling principal (becomes owner)
  PATCH /notes/{id}   write; COMMITS iff owner, or non-owner under mode 'bola';
                      the body token is recorded in the audit log either way

mode: 'secure' (non-owner write rejected, no commit) | 'bola' (non-owner write commits).
No randomness or wall-clock in the path; reset() restores an empty snapshot.
"""

import json
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

_ITEM = re.compile(r"^/notes/(\d+)$")


class ObsState:
    def __init__(self, mode):
        self.mode = mode
        self._lock = threading.Lock()
        self.reset()

    def reset(self):
        with self._lock:
            self.notes = {}
            self.audit = []          # every attempted write token (attempt-derived)
            self.feed = []           # tokens written directly to the feed (alt path)
            self.oob = []            # OOB callbacks fired on COMMIT (webhook listener)
            self._next = 1

    def _tokens(self, body):
        return [str(body[f]) for f in ("canary", "title") if body.get(f) is not None]

    def create(self, owner, body):
        with self._lock:
            nid = self._next
            self._next += 1
            self.audit.extend(self._tokens(body))
            self.oob.extend(self._tokens(body))          # create commits -> fires OOB
            self.notes[nid] = {"id": nid, "owner": owner,
                               "canary": body.get("canary"), "title": body.get("title")}
            return dict(self.notes[nid])

    def patch(self, nid, principal, body):
        with self._lock:
            self.audit.extend(self._tokens(body))        # recorded regardless of commit
            n = self.notes.get(nid)
            if n is None:
                return 404
            commits = (principal == n["owner"]) or (self.mode == "bola")
            if commits:
                for f in ("canary", "title"):
                    if f in body:
                        n[f] = body[f]
                self.oob.extend(self._tokens(body))       # commit -> fires OOB callback
                return 200
            return 403                                    # secure: rejected, no commit

    def control_drop(self, body):
        with self._lock:
            self.audit.extend(self._tokens(body))         # touches the attempt log...
            return 200                                    # ...but never commits (accept-drop)

    def feed_write(self, body):
        with self._lock:
            self.feed.extend(self._tokens(body))
            return 200

    def search(self, q):
        with self._lock:
            return any(q in (n.get("canary"), n.get("title")) for n in self.notes.values())

    def audit_has(self, q):
        with self._lock:
            return q in self.audit

    def feed_has(self, q):
        with self._lock:
            return q in self.feed

    def search_plus(self, q):
        # reflects committed state BUT is also fed by the attacker-writable feed:
        # passes the positive + negative control yet fails O4' (alternate causal path).
        return self.search(q) or self.feed_has(q)

    def oob_has(self, q):
        # grey-box / OOB channel: a callback fired only on a COMMITTED write.
        with self._lock:
            return q in self.oob


def make_handler(state):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_a):
            return

        def _send(self, code, body):
            payload = json.dumps(body).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
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

        def _q(self):
            return (parse_qs(urlparse(self.path).query).get("q", [""]) or [""])[0]

        def do_POST(self):
            path = urlparse(self.path).path
            if path == "/notes":
                note = state.create(self._principal(), self._body())
                return self._send(201, {"id": note["id"], "owner": note["owner"]})
            if path == "/feed":
                return self._send(state.feed_write(self._body()), {"ok": True})
            if path == "/control_drop":
                return self._send(state.control_drop(self._body()), {"ok": True})
            self._send(404, {"error": "no route"})

        def do_PATCH(self):
            m = _ITEM.match(urlparse(self.path).path)
            if not m:
                return self._send(404, {"error": "no route"})
            self._send(state.patch(int(m.group(1)), self._principal(), self._body()),
                       {"ok": True})

        def do_GET(self):
            path = urlparse(self.path).path
            if path == "/search":
                return self._send(200, {"hit": state.search(self._q())})
            if path == "/audit":
                return self._send(200, {"hit": state.audit_has(self._q())})
            if path == "/feed":
                return self._send(200, {"hit": state.feed_has(self._q())})
            if path == "/search_plus":
                return self._send(200, {"hit": state.search_plus(self._q())})
            if path == "/oob":                            # OOB webhook listener (commit-only)
                return self._send(200, {"hit": state.oob_has(self._q())})
            if path == "/db_replica":                     # grey-box: read the committed store
                return self._send(200, {"hit": state.search(self._q())})
            m = _ITEM.match(path)
            if m:
                n = state.notes.get(int(m.group(1)))
                if n is None:
                    return self._send(404, {"error": "gone"})
                if self._principal() != n["owner"]:
                    return self._send(403, {"error": "forbidden"})
                return self._send(200, n)
            self._send(404, {"error": "no route"})

    return Handler


def make_obs_server(mode="secure", host="127.0.0.1", port=0):
    state = ObsState(mode)
    server = ThreadingHTTPServer((host, port), make_handler(state))
    base_url = f"http://{host}:{server.server_address[1]}"
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, base_url, state

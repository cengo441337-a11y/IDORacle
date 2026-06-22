"""A deliberately DIFFERENTLY-SHAPED vulnerable target for the external-validity pilot.

The point: prove the oracle works against an app it was NOT co-designed with. Every
toy-specific assumption is changed on purpose:
  - auth is a Bearer token (Authorization: Bearer tokA|tokB), NOT the X-Principal header;
    no/invalid token -> 401 on everything.
  - the resource is /items with fields `secret` and `bio`, NOT /notes with canary/title.
  - there is NO sharing model and NO `shared` field.

mode: 'secure' (non-owner write -> 403, no commit) | 'bola' (non-owner write commits).
A sound oracle must HOLD here with its toy defaults (wrong auth, wrong fields) and only
witness once given the right target profile (Bearer auth + discovered fields).
"""

import json
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

_ITEM = re.compile(r"^/items/(\d+)$")
_TOKENS = {"tokA": "A", "tokB": "B"}        # Bearer token -> user
_FIELDS = ("secret", "bio")


class ExtState:
    def __init__(self, mode):
        self.mode = mode
        self._lock = threading.Lock()
        self.reset()

    def reset(self):
        with self._lock:
            self.items = {}
            self._next = 1

    def create(self, owner, body):
        with self._lock:
            iid = self._next
            self._next += 1
            self.items[iid] = {"id": iid, "owner": owner,
                               "secret": body.get("secret"), "bio": body.get("bio")}
            return dict(self.items[iid])

    def read(self, iid):
        with self._lock:
            it = self.items.get(iid)
            return dict(it) if it else None

    def patch(self, iid, principal, body):
        with self._lock:
            it = self.items.get(iid)
            if it is None:
                return 404
            commits = (principal == it["owner"]) or (self.mode == "bola")
            if commits:
                for f in _FIELDS:
                    if f in body:
                        it[f] = body[f]
                return 200
            return 403


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

        def _user(self):
            h = self.headers.get("Authorization", "")
            if h.startswith("Bearer "):
                return _TOKENS.get(h[7:])
            return None

        def _body(self):
            n = int(self.headers.get("Content-Length", 0) or 0)
            if not n:
                return {}
            try:
                return json.loads(self.rfile.read(n) or b"{}")
            except ValueError:
                return {}

        def do_POST(self):
            user = self._user()
            if user is None:
                return self._send(401, {"error": "unauthorized"})
            if self.path != "/items":
                return self._send(404, {"error": "no route"})
            it = state.create(user, self._body())
            self._send(201, {"id": it["id"], "owner": it["owner"]})

        def do_GET(self):
            user = self._user()
            if user is None:
                return self._send(401, {"error": "unauthorized"})
            m = _ITEM.match(self.path)
            if not m:
                return self._send(404, {"error": "no route"})
            it = state.read(int(m.group(1)))
            if it is None:
                return self._send(404, {"error": "gone"})
            if user != it["owner"]:
                return self._send(403, {"error": "forbidden"})
            self._send(200, it)

        def do_PATCH(self):
            user = self._user()
            if user is None:
                return self._send(401, {"error": "unauthorized"})
            m = _ITEM.match(self.path)
            if not m:
                return self._send(404, {"error": "no route"})
            self._send(state.patch(int(m.group(1)), user, self._body()), {"ok": True})

    return Handler


def make_ext_server(mode="secure", host="127.0.0.1", port=0):
    state = ExtState(mode)
    server = ThreadingHTTPServer((host, port), make_handler(state))
    base_url = f"http://{host}:{server.server_address[1]}"
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, base_url, state

"""Read-only public demo (FENRIR_DEMO_MODE=true): visitors can look at everything and change nothing.

- Every change is refused: any POST, PUT, PATCH or DELETE except signing in and out.
- No agents: the agent API (/api/v1), installer and agent downloads (/downloads, /install) and the remote-session
  relay (WebSockets) are closed, so nothing can be downloaded, enrolled or controlled.
- The only way to write is the demo loader, from inside the demo's own container: requests from the loopback
  address carrying X-Fenrir-Demo-Seed equal to FENRIR_DEMO_SEED_TOKEN. deploy/demo/reset.sh uses it to put the
  sample data back.
"""

from __future__ import annotations

import hmac
import json

READ_ONLY_MESSAGE = "This is a read-only demo: changes, agent downloads and remote sessions are turned off."
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
WRITE_ALLOWED = ("/api/console/auth/login", "/api/console/auth/logout")
CLOSED_PREFIXES = ("/api/v1/", "/downloads/", "/install/", "/legacy/")
LOOPBACK = {"127.0.0.1", "::1"}


class DemoGuard:
    def __init__(self, app, seed_token: str = "") -> None:
        self.app, self.seed_token = app, seed_token

    def _seeding(self, scope) -> bool:
        if not self.seed_token or (scope.get("client") or ("",))[0] not in LOOPBACK:
            return False
        supplied = dict(scope.get("headers") or []).get(b"x-fenrir-demo-seed", b"").decode("latin-1")
        return bool(supplied) and hmac.compare_digest(supplied, self.seed_token)

    async def __call__(self, scope, receive, send):
        kind = scope.get("type")
        if kind == "websocket":
            await send({"type": "websocket.close", "code": 1008})
            return
        if kind != "http":
            await self.app(scope, receive, send)
            return
        path, method = scope.get("path", ""), scope.get("method", "GET").upper()
        closed = path.startswith(CLOSED_PREFIXES) or (method not in SAFE_METHODS and path not in WRITE_ALLOWED)
        if closed and not self._seeding(scope):
            body = json.dumps({"detail": READ_ONLY_MESSAGE, "demo": True}).encode()
            await send({"type": "http.response.start", "status": 403,
                        "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())]})
            await send({"type": "http.response.body", "body": body})
            return
        await self.app(scope, receive, send)

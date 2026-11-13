"""The real client address behind a reverse proxy (Caddy in the HTTPS deployment).

Behind a proxy, every connection comes from the proxy, so sign-in records, the audit log and per-address rate limits
would all show the proxy's address. When a connection comes from an address in FENRIR_TRUSTED_PROXIES (addresses or
networks, comma-separated), the client is taken from X-Forwarded-For instead: the right-most address in it that is
not itself a trusted proxy. A connection from anywhere else keeps its own address, so a client cannot forge one by
sending the header itself.

Applied to HTTP and WebSocket requests before anything else runs, so request.client is right everywhere.
"""
from __future__ import annotations

import ipaddress
import os

Network = ipaddress.IPv4Network | ipaddress.IPv6Network


def parse(value: str) -> list[Network]:
    networks: list[Network] = []
    for part in (value or "").split(","):
        part = part.strip()
        if not part:
            continue
        try:
            networks.append(ipaddress.ip_network(part, strict=False))
        except ValueError:
            raise RuntimeError(f"FENRIR_TRUSTED_PROXIES has an invalid address or network: {part!r}") from None
    return networks


def _address(text: str):
    text = text.strip().strip('"')
    if text.startswith("[") and "]" in text:  # [2001:db8::1]:443
        text = text[1:text.index("]")]
    elif text.count(":") == 1:  # 203.0.113.9:51234
        text = text.split(":", 1)[0]
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return None
    return address.ipv4_mapped or address if isinstance(address, ipaddress.IPv6Address) else address


def trusted(address, networks: list[Network]) -> bool:
    return address is not None and any(address in network for network in networks)


def client_from(peer: str, forwarded_for: str, networks: list[Network]) -> str:
    """The client address for a connection from ``peer`` carrying this X-Forwarded-For."""
    if not networks or not trusted(_address(peer), networks) or not forwarded_for:
        return peer
    hops = [_address(part) for part in forwarded_for.split(",")]
    for hop in reversed(hops):
        if hop is None:
            return peer  # a malformed chain: do not guess
        if not trusted(hop, networks):
            return str(hop)
    return str(hops[0]) if hops and hops[0] is not None else peer


class TrustedProxyMiddleware:
    def __init__(self, app, networks: list[Network]) -> None:
        self.app, self.networks = app, networks

    async def __call__(self, scope, receive, send):
        if scope["type"] in ("http", "websocket") and self.networks and scope.get("client"):
            peer, port = scope["client"][0], scope["client"][1]
            forwarded = ""
            for name, value in scope.get("headers") or []:
                if name == b"x-forwarded-for":
                    forwarded = f"{forwarded},{value.decode('latin-1')}" if forwarded else value.decode("latin-1")
            client = client_from(peer, forwarded, self.networks)
            if client != peer:
                scope = {**scope, "client": (client, port)}
                # The proxy terminated TLS: keep the scheme the browser used, for redirects and secure cookies.
                for name, value in scope.get("headers") or []:
                    if name == b"x-forwarded-proto" and value in (b"https", b"http", b"wss", b"ws"):
                        proto = value.decode()
                        scope["scheme"] = ({"https": "wss", "http": "ws"}.get(proto, proto) if scope["type"] == "websocket"
                                           else {"wss": "https", "ws": "http"}.get(proto, proto))
        await self.app(scope, receive, send)


def from_environment() -> list[Network]:
    return parse(os.getenv("FENRIR_TRUSTED_PROXIES", ""))

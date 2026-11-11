"""Email security: the evidence behind a verdict, kept with each scanned message (``EmailScan.details``).

For a technician investigating a message, without opening it:

- **headers**: every header, in the order received (values capped, the whole set capped at 64 KB).
- **path**: the ``Received:`` chain, oldest hop first: from, by, IP, protocol, time, and the delay at each hop.
- **origin**: the IP that handed the message to Microsoft or to Fenrir's gateway, with its reverse DNS name, network
  (ASN and owner, from Team Cymru's free DNS service), country, whether it is private, and whether threat intel lists it.
- **addresses**: envelope sender, From, Sender, Reply-To, Return-Path, recipients, Message-ID, Date, mail client and
  the sending server's greeting name, with mismatches between them spelled out.
- **auth**: SPF, DKIM (signing domain, selector, algorithm), DMARC and composite authentication, and ARC if present.
- **links**: every link (up to 50, each up to 500 characters) with what is wrong with it: threat intel, lookalike,
  bare IP, shortener, or text that shows a different site.
- **attachments**: name, type, size, SHA-256.
- **delivery** (gateway): where it was handed on, when, how many attempts, and the receiving server's reply.

Lookups are cached for a day and time out after two seconds, so a slow DNS server never holds up mail.
"""
from __future__ import annotations

import ipaddress
import re
import time
from datetime import timezone
from email.utils import getaddresses, parsedate_to_datetime

from . import email_security

MAX_HEADER_BYTES = 64 * 1024
MAX_VALUE = 4000
MAX_LINKS = 50
_ip_cache: dict[str, tuple[float, dict]] = {}
IP_CACHE_SECONDS = 86400

RECEIVED = re.compile(
    r"(?:from\s+(?P<from>\S+)(?:\s+\((?P<from_detail>[^)]*)\))?)?\s*"
    r"(?:by\s+(?P<by>\S+)(?:\s+\([^)]*\))?)?\s*"
    r"(?:with\s+(?P<with>\S+))?", re.I | re.S)
IP_IN_TEXT = re.compile(r"\[?(?P<ip>(?:\d{1,3}\.){3}\d{1,3}|[0-9a-f]{0,4}(?::[0-9a-f]{0,4}){2,7})\]?", re.I)


# --------------------------------------------------------------------------- small helpers

def _public(ip: str) -> bool:
    try:
        address = ipaddress.ip_address(ip.strip("[]"))
    except ValueError:
        return False
    return address.is_global


def _valid_ip(ip: str) -> str | None:
    try:
        return str(ipaddress.ip_address(ip.strip("[]")))
    except ValueError:
        return None


def header_list(pairs) -> list[list[str]]:
    """[[name, value], ...] in order, each value capped, the whole set capped."""
    out, total = [], 0
    for name, value in pairs:
        value = re.sub(r"\s+", " ", str(value or "")).strip()[:MAX_VALUE]
        total += len(name) + len(value)
        if total > MAX_HEADER_BYTES:
            out.append(["…", f"{len(pairs) - len(out)} more headers not kept (size limit)"])
            break
        out.append([str(name), value])
    return out


def _all(headers: list[list[str]], name: str) -> list[str]:
    return [v for k, v in headers if k.lower() == name.lower()]


def _first(headers: list[list[str]], name: str) -> str:
    found = _all(headers, name)
    return found[0] if found else ""


# --------------------------------------------------------------------------- the delivery path

def path(headers: list[list[str]]) -> list[dict]:
    """The Received chain, oldest hop first, with the delay at each hop."""
    hops = []
    for value in reversed(_all(headers, "Received")):
        route, _, when = value.rpartition(";")
        match = RECEIVED.search(route) if route else None
        hop = {"from": "", "by": "", "with": "", "ip": "", "at": None, "raw": value[:600]}
        if match:
            hop.update({"from": (match.group("from") or "")[:200], "by": (match.group("by") or "")[:200],
                        "with": (match.group("with") or "")[:40]})
            detail = match.group("from_detail") or ""
            for candidate in IP_IN_TEXT.finditer(detail + " " + (match.group("from") or "")):
                ip = _valid_ip(candidate.group("ip"))
                if ip:
                    hop["ip"] = ip
                    break
        try:
            parsed = parsedate_to_datetime(when.strip()) if when.strip() else None
            hop["at"] = (parsed.astimezone(timezone.utc) if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)).isoformat() \
                if parsed else None
        except (TypeError, ValueError, IndexError):
            hop["at"] = None
        hops.append(hop)
    previous = None
    for hop in hops:
        hop["delaySeconds"] = None
        if hop["at"] and previous:
            try:
                from datetime import datetime

                hop["delaySeconds"] = max(0, int((datetime.fromisoformat(hop["at"]) - datetime.fromisoformat(previous)).total_seconds()))
            except ValueError:
                pass
        previous = hop["at"] or previous
    return hops[:30]


def originating_ip(headers: list[list[str]], hops: list[dict], peer: str = "") -> str:
    """The IP that handed the message over: the gateway's peer, Microsoft's connecting IP, or the first public hop."""
    if peer and _valid_ip(peer):
        return _valid_ip(peer) or ""
    forefront = _first(headers, "X-Forefront-Antispam-Report")
    match = re.search(r"\bCIP:([0-9a-fA-F.:]+)", forefront)
    if match and _valid_ip(match.group(1)):
        return _valid_ip(match.group(1)) or ""
    for name in ("X-MS-Exchange-Organization-OriginalClientIPAddress", "X-Originating-IP", "X-Sender-IP"):
        ip = _valid_ip(re.sub(r"[\[\]\s]", "", _first(headers, name)))
        if ip:
            return ip
    for hop in hops:
        if hop.get("ip") and _public(hop["ip"]):
            return hop["ip"]
    return ""


def ip_info(ip: str, bad_ips: set[str] | None = None) -> dict:
    """Reverse DNS, network (ASN and owner) and country for an IP, cached for a day."""
    if not ip:
        return {}
    cached = _ip_cache.get(ip)
    if cached and time.monotonic() - cached[0] < IP_CACHE_SECONDS:
        info = dict(cached[1])
    else:
        info = {"ip": ip, "public": _public(ip), "ptr": "", "asn": "", "network": "", "owner": "", "country": ""}
        if info["public"]:
            info.update(_lookups(ip))
        _ip_cache[ip] = (time.monotonic(), dict(info))
        if len(_ip_cache) > 20000:
            _ip_cache.clear()
    info["listed"] = bool(bad_ips and ip in bad_ips)
    return info


def _lookups(ip: str) -> dict:
    import dns.exception
    import dns.resolver
    import dns.reversename

    out = {}
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 2.0
    try:
        out["ptr"] = str(resolver.resolve(dns.reversename.from_address(ip), "PTR")[0]).rstrip(".")[:255]
    except (dns.exception.DNSException, OSError, ValueError):
        pass
    try:
        address = ipaddress.ip_address(ip)
        name = (".".join(reversed(ip.split("."))) + ".origin.asn.cymru.com" if address.version == 4 else
                ".".join(reversed(address.exploded.replace(":", ""))) + ".origin6.asn.cymru.com")
        fields = [f.strip() for f in b"".join(resolver.resolve(name, "TXT")[0].strings).decode().split("|")]
        out.update(asn=fields[0].split()[0] if fields and fields[0] else "", network=fields[1] if len(fields) > 1 else "",
                   country=fields[2] if len(fields) > 2 else "")
        if out.get("asn"):
            owner = [f.strip() for f in b"".join(resolver.resolve(f"AS{out['asn']}.asn.cymru.com", "TXT")[0].strings).decode().split("|")]
            out["owner"] = owner[-1][:200] if owner else ""
    except (dns.exception.DNSException, OSError, ValueError, IndexError):
        pass
    return out


# --------------------------------------------------------------------------- addresses and authentication

def _address(value: str) -> str:
    found = getaddresses([value]) if value else []
    return found[0][1].lower() if found and found[0][1] else ""


def addresses(headers: list[list[str]], envelope_from: str = "", recipients: list[str] | None = None, helo: str = "") -> dict:
    header_from = _address(_first(headers, "From"))
    return_path = _address(_first(headers, "Return-Path"))
    envelope = (envelope_from or return_path or "").lower()
    reply_to = [a for _, a in getaddresses(_all(headers, "Reply-To")) if a]
    out = {
        "envelopeFrom": envelope, "headerFrom": header_from, "headerFromName": getaddresses([_first(headers, "From")])[0][0][:200]
        if _first(headers, "From") else "", "sender": _address(_first(headers, "Sender")), "replyTo": [a.lower() for a in reply_to][:5],
        "returnPath": return_path, "to": [a.lower() for _, a in getaddresses(_all(headers, "To")) if a][:20],
        "cc": [a.lower() for _, a in getaddresses(_all(headers, "Cc")) if a][:20], "recipients": [r.lower() for r in (recipients or [])][:50],
        "messageId": _first(headers, "Message-ID")[:300], "date": _first(headers, "Date")[:100],
        "mailer": (_first(headers, "X-Mailer") or _first(headers, "User-Agent"))[:200], "helo": (helo or "")[:255],
    }
    notes = []
    domain = email_security.domain_of
    if envelope and header_from and email_security.registrable(domain(envelope)) != email_security.registrable(domain(header_from)):
        notes.append(f"The envelope sender ({envelope}) is from a different domain than the From address ({header_from}).")
    for reply in out["replyTo"]:
        if header_from and email_security.registrable(domain(reply)) != email_security.registrable(domain(header_from)):
            notes.append(f"Replies go to {reply}, a different domain from the sender.")
            break
    if out["sender"] and header_from and out["sender"] != header_from:
        notes.append(f"Sent on behalf of {header_from} by {out['sender']}.")
    out["notes"] = notes
    return out


def _tag(text: str, name: str) -> str:
    match = re.search(rf"(?:^|[;\s]){name}\s*=\s*([^;\s]+)", text, re.I)
    return match.group(1).strip() if match else ""


def authentication(headers: list[list[str]], gateway_auth: dict | None = None) -> dict:
    results = " ".join(_all(headers, "Authentication-Results"))
    signature = _first(headers, "DKIM-Signature")
    out = {
        "spf": (gateway_auth or {}).get("spf") or _tag(results, "spf"),
        "spfDomain": _tag(results, "smtp.mailfrom"),
        "spfDetail": (gateway_auth or {}).get("spfDetail", ""),
        "dkim": (gateway_auth or {}).get("dkim") or _tag(results, "dkim"),
        "dkimDomain": (gateway_auth or {}).get("dkimDomain") or _tag(signature, "d") or _tag(results, "header.d"),
        "dkimSelector": _tag(signature, "s"), "dkimAlgorithm": _tag(signature, "a"),
        "dmarc": (gateway_auth or {}).get("dmarc") or _tag(results, "dmarc"),
        "dmarcPolicy": (gateway_auth or {}).get("policy") or _tag(results, "action"),
        "dmarcRecord": (gateway_auth or {}).get("dmarcRecord", ""),
        "compauth": _tag(results, "compauth"), "compauthReason": _tag(results, "reason"),
        "arc": bool(_all(headers, "ARC-Seal")), "results": results[:2000],
    }
    return out


# --------------------------------------------------------------------------- links and the whole picture

def links(html: str, ctx: email_security.Context | None = None) -> list[dict]:
    urls, anchors = email_security.links(html)
    shown = {}
    for text, href in anchors:
        shown.setdefault(href, text)
    out = []
    for url in urls[:MAX_LINKS]:
        host = email_security._host(url)
        flags = []
        if ctx is not None:
            parts = host.split(".")
            if url.lower().rstrip("/") in ctx.bad_urls or any(".".join(parts[i:]) in ctx.bad_domains for i in range(len(parts) - 1)):
                flags.append("threat intel")
            if email_security.lookalike_of(host, email_security.BRANDS | ctx.own_domains):
                flags.append("lookalike")
        if email_security._is_ip(host):
            flags.append("bare IP")
        if email_security.registrable(host) in email_security.SHORTENERS:
            flags.append("shortener")
        text = (shown.get(url) or "").strip()
        text_host = email_security._host(text if text.lower().startswith("http") else "http://" + text) if \
            re.match(r"^(https?://|www\.)", text, re.I) else ""
        if text_host and host and email_security.registrable(text_host) != email_security.registrable(host):
            flags.append("text shows another site")
        out.append({"url": url[:500], "host": host[:255], "text": text[:200] if text and text != url else "", "flags": flags})
    return out


def build(*, headers: list[list[str]], html: str, attachments: list[dict], ctx: email_security.Context | None = None,
          bad_ips: set[str] | None = None, peer: str = "", helo: str = "", envelope_from: str = "",
          recipients: list[str] | None = None, gateway_auth: dict | None = None, size: int | None = None,
          tls: bool | None = None) -> dict:
    hops = path(headers)
    origin = originating_ip(headers, hops, peer)
    return {
        "headers": headers, "path": hops, "origin": ip_info(origin, bad_ips),
        "addresses": addresses(headers, envelope_from, recipients, helo), "auth": authentication(headers, gateway_auth),
        "links": links(html, ctx),
        "attachments": [{k: a.get(k) for k in ("name", "contentType", "size", "sha256") if a.get(k) is not None} for a in attachments][:20],
        "size": size, "tls": tls,
    }

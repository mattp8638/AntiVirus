"""Safe Microsoft 365 tenant, domain and email diagnostics, and a read-only Graph explorer (M365-32).

**Domain and email diagnostics** look only at public information:

* the domain's DNS records, read over DNS-over-HTTPS: MX, SPF (including its DNS-lookup count), DMARC, the
  Microsoft 365 DKIM selectors, autodiscover and MTA-STS;
* Microsoft's public OpenID configuration for the domain, to tell whether it belongs to a Microsoft tenant and which.

They need no connection and change nothing.

**The Graph explorer** sends one ``GET`` to Microsoft Graph through a customer's connection. It cannot be used to get
round the reviewed-action model:

* Only ``GET``. Writes go through the reviewed actions, which have previews, step-up and audit.
* Only paths under ``APPROVED`` directory, policy, device, report and security resources. Paths to people's content
  (mail, files, chats, calendars, contacts, notes, photos) and ``$batch`` are refused, even when they sit under an
  approved resource.
* Only the query options ``$select``, ``$filter``, ``$top`` (at most 100), ``$orderby``, ``$count``, ``$search`` and
  ``$expand``, with no further pages fetched automatically. A response is cut at ``MAX_BYTES``.
* The explorer needs the ``m365_admin`` permission. Every call is audited with the path, status and size, never the
  response body.
"""
from __future__ import annotations

import json
import re
from urllib.parse import parse_qsl, urlencode, urlparse

import httpx

from . import m365
from .models import M365Connection

DOH = "https://cloudflare-dns.com/dns-query"
DOMAIN = re.compile(r"^(?=.{4,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
APPROVED = ("/users", "/groups", "/organization", "/domains", "/subscribedSkus", "/devices", "/directoryRoles", "/roleManagement/directory",
            "/applications", "/servicePrincipals", "/identity/conditionalAccess", "/policies", "/deviceManagement/managedDevices",
            "/deviceManagement/deviceCompliancePolicies", "/deviceManagement/deviceConfigurations", "/reports", "/security/alerts_v2",
            "/security/incidents", "/security/secureScores", "/auditLogs", "/identityProtection", "/directory/deletedItems")
CONTENT = re.compile(r"(?i)/(messages|mailFolders|mailboxSettings|drive|drives|sites|chats|channels|onenote|calendar|calendars|events|"
                     r"contacts|contactFolders|photo|photos|insights|planner|todo|extensions|\$batch|\$value|content)(/|$|\?)")
QUERY_OPTIONS = {"$select", "$filter", "$top", "$orderby", "$count", "$search", "$expand"}
MAX_BYTES = 1_000_000


class ToolError(Exception):
    pass


# ---- domain and email diagnostics ----------------------------------------------------------------------------------

def _client() -> httpx.Client:
    return httpx.Client(timeout=10, follow_redirects=False)


def _dns(client, name: str, rtype: str) -> list[str]:
    r = client.get(DOH, params={"name": name, "type": rtype}, headers={"Accept": "application/dns-json"})
    r.raise_for_status()
    codes = {"MX": 15, "TXT": 16, "CNAME": 5}
    return [a.get("data", "").replace('" "', "").strip('"') for a in r.json().get("Answer") or [] if a.get("type") == codes[rtype]]


def _spf_lookups(record: str) -> int:
    return sum(1 for term in record.split() if re.match(r"(?i)^[+~?-]?(include:|a\b|a:|mx\b|mx:|ptr|exists:|redirect=)", term))


def domain_check(domain: str) -> dict:
    domain = domain.strip().lower().rstrip(".")
    if not DOMAIN.match(domain):
        raise ToolError("Enter a domain name such as contoso.com")
    checks = []

    def add(key, status, detail, records=None):
        checks.append({"check": key, "status": status, "detail": detail, "records": records or []})

    with _client() as client:
        try:
            mx = _dns(client, domain, "MX")
            if not mx:
                add("mx", "warn", "No MX records: the domain does not receive email")
            else:
                m365 = any("mail.protection.outlook.com" in r.lower() for r in mx)
                add("mx", "pass", "Mail goes to Microsoft 365 (Exchange Online Protection)" if m365 else "Mail goes to another service", mx)
            spf = [t for t in _dns(client, domain, "TXT") if t.lower().startswith("v=spf1")]
            if not spf:
                add("spf", "fail", "No SPF record: anyone can claim to send as this domain")
            elif len(spf) > 1:
                add("spf", "fail", "More than one SPF record: receivers treat SPF as broken", spf)
            else:
                lookups = _spf_lookups(spf[0])
                ending = spf[0].split()[-1].lower()
                status = "fail" if lookups > 10 else "warn" if ending in ("+all", "?all") or "all" not in ending else "pass"
                add("spf", status, f"{lookups} DNS lookups (limit 10); ends with {ending}", spf)
            dmarc = [t for t in _dns(client, f"_dmarc.{domain}", "TXT") if t.lower().startswith("v=dmarc1")]
            policy = next((p.split("=", 1)[1].strip().lower() for p in (dmarc[0].split(";") if dmarc else []) if p.strip().lower().startswith("p=")), "")
            if not dmarc:
                add("dmarc", "fail", "No DMARC record")
            else:
                add("dmarc", "pass" if policy in ("quarantine", "reject") else "warn", f"Policy p={policy or 'missing'}", dmarc)
            selectors = {s: _dns(client, f"{s}._domainkey.{domain}", "CNAME") for s in ("selector1", "selector2")}
            found = {s: v for s, v in selectors.items() if v}
            add("dkim", "pass" if len(found) == 2 else "warn" if found else "info",
                "Both Microsoft 365 DKIM selectors are published" if len(found) == 2 else
                "Microsoft 365 DKIM selectors are not (all) published; another provider may sign mail",
                [f"{s}: {v[0]}" for s, v in found.items()])
            auto = _dns(client, f"autodiscover.{domain}", "CNAME")
            add("autodiscover", "pass" if any("outlook.com" in a.lower() for a in auto) else "info",
                "Autodiscover points to Microsoft 365" if auto else "No autodiscover record", auto)
            sts = [t for t in _dns(client, f"_mta-sts.{domain}", "TXT") if t.lower().startswith("v=stsv1")]
            add("mta-sts", "pass" if sts else "info", "MTA-STS is published" if sts else "No MTA-STS: mail to this domain can be downgraded to plain text", sts)
        except (httpx.HTTPError, ValueError) as exc:
            add("dns", "error", f"DNS lookup failed: {type(exc).__name__}")
        try:
            r = client.get(f"https://login.microsoftonline.com/{domain}/v2.0/.well-known/openid-configuration")
            if r.status_code == 200:
                issuer = r.json().get("issuer", "")
                tid = next((p for p in issuer.split("/") if re.fullmatch(r"[0-9a-f-]{36}", p)), "")
                add("tenant", "info", f"The domain belongs to Microsoft tenant {tid}", [issuer])
            else:
                add("tenant", "info", "The domain is not registered with a Microsoft tenant")
        except (httpx.HTTPError, ValueError) as exc:
            add("tenant", "error", f"Microsoft lookup failed: {type(exc).__name__}")
    return {"domain": domain, "checks": checks}


# ---- Graph explorer ------------------------------------------------------------------------------------------------

def validate_path(raw: str) -> str:
    """The relative Graph path (with allowed query options), or ToolError saying why it is refused."""
    raw = raw.strip()
    if raw.lower().startswith("https://"):
        p = urlparse(raw)
        if p.netloc != "graph.microsoft.com" or not p.path.startswith(("/v1.0/", "/beta/")):
            raise ToolError("Only Microsoft Graph addresses are allowed")
        raw = p.path.split("/", 2)[2] and "/" + p.path.split("/", 2)[2] + (("?" + p.query) if p.query else "")
    if not raw.startswith("/") or ".." in raw or "\\" in raw or "@" in raw.split("?")[0] or len(raw) > 1000:
        raise ToolError("Enter a Graph path such as /users?$select=displayName")
    path, _, query = raw.partition("?")
    if CONTENT.search(path + "/"):
        raise ToolError("Paths to people's content (mail, files, chats, calendars, contacts) and $batch are not available in the explorer")
    if not any(path == a or path.startswith(a + "/") or path.startswith(a + "(") for a in APPROVED):
        raise ToolError("This resource is not on the explorer's approved list")
    params = parse_qsl(query, keep_blank_values=True)
    for key, value in params:
        if key not in QUERY_OPTIONS:
            raise ToolError(f"Query option {key} is not allowed")
        if key == "$top" and (not value.isdigit() or not 1 <= int(value) <= 100):
            raise ToolError("$top must be between 1 and 100")
    return path + (("?" + urlencode(params, safe="$,'() =:")) if params else "")


def explore(conn: M365Connection, raw_path: str) -> dict:
    path = validate_path(raw_path)
    with httpx.Client(timeout=20, follow_redirects=False) as client:
        token = m365.access_token(client, conn)
        headers = {"Authorization": "Bearer " + token}
        if "$search" in path or "$count" in path:
            headers["ConsistencyLevel"] = "eventual"
        r = client.get(m365.GRAPH + path, headers=headers)
    body = r.content[:MAX_BYTES]
    try:
        data = json.loads(body) if len(r.content) <= MAX_BYTES else None
    except ValueError:
        data = None
    out = {"path": path, "status": r.status_code, "bytes": len(r.content), "truncated": len(r.content) > MAX_BYTES,
           "nextPage": bool(isinstance(data, dict) and data.get("@odata.nextLink"))}
    if data is not None:
        if isinstance(data, dict):
            data.pop("@odata.nextLink", None)
        out["json"] = data
    else:
        out["text"] = body.decode("utf-8", "replace")
    return out

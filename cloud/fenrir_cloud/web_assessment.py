"""Safe web application assessment (VULN-08).

Fenrir assesses only sites on an external asset whose ownership the customer attested, and only that host. It does
not attack the site. Every request is a GET or HEAD. No form is submitted, no exploit payload is sent and no
password is guessed.

**Profiles.**

* ``passive``: crawls and reads what the site returns (headers, cookies, pages, robots.txt), and asks for a short
  list of well-known exposed files.
* ``standard``: passive, plus two harmless probes. One sends a random marker in a query parameter, to see whether it
  is echoed back unencoded. The other sends a made-up ``Origin`` header, to see whether CORS trusts any origin.

Either profile can be authenticated. A header such as ``Authorization`` or ``Cookie`` is sent with each request. It
is stored encrypted only until the run ends, and it is never logged or shown again.

**Limits.** The crawl stays on the same scheme, host and port. It follows at most ``max_pages`` pages to a depth of
``max_depth``. It respects robots.txt ``Disallow`` lines for all user agents, waits ``delay`` seconds between
requests and stops after ``budget`` seconds. Redirects are followed only to the same host. Before every request,
the host's addresses are checked to be public.

**Findings.**

* *Confirmed* when the response itself proves the finding, for example a header that is missing, a cookie flag that
  is missing, or an exposed file whose content matches its known signature.
* *Suspected* when it needs a person to confirm, for example an echoed marker, an old library version, or a stack
  trace.

Each finding keeps:

* the request that shows it;
* the response status and an excerpt;
* its OWASP Top 10 (2021) category.

Categories that were not tested, and the reason, are listed with the results.
"""
from __future__ import annotations

import logging
import re
import secrets
import time
from html.parser import HTMLParser
from time import monotonic
from urllib.parse import urldefrag, urljoin, urlparse

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import audit, crypto, netguard
from .models import ExternalAsset, WebAssessment, utcnow

log = logging.getLogger("fenrir.web_assessment")

USER_AGENT = "Fenrir-WebAssessment/1.0 (authorised owner assessment)"
LIMITS = {"max_pages": (50, 1, 200), "max_depth": (3, 0, 6), "delay": (0.2, 0.0, 5.0), "budget": (120, 10, 600)}
OWASP = {
    "A01": "Broken Access Control", "A02": "Cryptographic Failures", "A03": "Injection", "A04": "Insecure Design",
    "A05": "Security Misconfiguration", "A06": "Vulnerable and Outdated Components", "A07": "Identification and Authentication Failures",
    "A08": "Software and Data Integrity Failures", "A09": "Security Logging and Monitoring Failures", "A10": "Server-Side Request Forgery",
}
NOT_TESTED = {
    "A04": "Insecure design needs a review of how the application works; a scanner cannot judge it",
    "A09": "Logging and monitoring are not visible from outside the application",
    "A10": "Testing server-side request forgery means making the server fetch addresses an attacker chooses; not done by a safe profile",
}
# path -> (signature regex on the body, what it is, OWASP)
EXPOSED_FILES = {
    "/.git/HEAD": (r"^ref: refs/", "Git repository metadata", "A05"),
    "/.env": (r"(?m)^[A-Z][A-Z0-9_]{2,}=", "Environment file with settings (often secrets)", "A05"),
    "/.DS_Store": (r"^\x00\x00\x00\x01Bud1", "macOS folder metadata listing file names", "A05"),
    "/server-status": (r"Apache Server Status", "Apache server status page", "A05"),
    "/phpinfo.php": (r"phpinfo\(\)|PHP Version", "PHP configuration page", "A05"),
    "/.svn/entries": (r"^\d+\s*$|svn", "Subversion metadata", "A05"),
    "/backup.sql": (r"(?i)(CREATE TABLE|INSERT INTO)", "Database dump", "A01"),
}
SESSION_COOKIE = re.compile(r"(?i)sess|sid|auth|token|jwt|login")
OLD_LIBRARIES = [(re.compile(r"jquery[-.]?(1\.\d+|2\.\d+|3\.[0-4])(\.\d+)?(\.min)?\.js", re.I), "jQuery before 3.5 (known XSS issues)"),
                 (re.compile(r"angular(js)?[-.]?1\.[0-7]\.\d+", re.I), "AngularJS 1.x (end of life)"),
                 (re.compile(r"bootstrap[-.]?(2|3\.[0-3])\.\d+", re.I), "Bootstrap before 3.4 (known XSS issues)")]
STACK_TRACE = re.compile(r"Traceback \(most recent call last\)|at [\w.$]+\([\w]+\.java:\d+\)|Fatal error: .* on line \d+|"
                         r"Microsoft OLE DB|ORA-\d{5}|SQLSTATE\[", re.I)


class AssessmentError(Exception):
    pass


def limits(config: dict) -> dict:
    out = {}
    for key, (default, low, high) in LIMITS.items():
        value = config.get(key, default)
        if not isinstance(value, (int, float)) or not low <= value <= high:
            raise AssessmentError(f"{key} must be between {low} and {high}")
        out[key] = value
    return out


def check_target(db: Session, tenant_id: str, asset_id: str, url: str) -> ExternalAsset:
    asset = db.get(ExternalAsset, asset_id)
    if asset is None or asset.tenant_id != tenant_id:
        raise AssessmentError("Choose one of this customer's external assets")
    parts = urlparse(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise AssessmentError("Enter an http:// or https:// address")
    if parts.hostname.lower() != asset.target.lower().strip("[]"):
        raise AssessmentError(f"The address must be on {asset.target}, the asset whose ownership was attested")
    if parts.username or parts.password:
        raise AssessmentError("Do not put credentials in the address; use the authentication header instead")
    try:
        netguard.resolve_public(parts.hostname)
    except netguard.Blocked as exc:
        raise AssessmentError(str(exc)) from None
    except OSError:
        pass  # does not resolve now: the run will record the failure
    return asset


class _Links(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links, self.scripts, self.forms = [], [], []

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "a" and a.get("href"):
            self.links.append(a["href"])
        elif tag == "script" and a.get("src"):
            self.scripts.append({"src": a["src"], "integrity": bool(a.get("integrity"))})
        elif tag == "form":
            self.forms.append({"action": a.get("action") or "", "method": (a.get("method") or "get").lower(), "password": False})
        elif tag == "input" and (a.get("type") or "").lower() == "password" and self.forms:
            self.forms[-1]["password"] = True


def _client() -> httpx.Client:
    return httpx.Client(timeout=10, follow_redirects=False, headers={"User-Agent": USER_AGENT})


class _Run:
    def __init__(self, base: str, lim: dict, auth: dict | None, client: httpx.Client):
        self.base, self.lim, self.client, self.auth = base, lim, client, auth or {}
        p = urlparse(base)
        self.origin = (p.scheme, p.hostname, p.port)
        self.findings: list[dict] = []
        self.pages: list[dict] = []
        self.started = monotonic()
        self.disallow: list[str] = []
        self.requests = 0

    def out_of_time(self) -> bool:
        return monotonic() - self.started > self.lim["budget"]

    def same_origin(self, url: str) -> bool:
        p = urlparse(url)
        return (p.scheme, p.hostname, p.port) == self.origin

    def get(self, url: str, headers: dict | None = None, method: str = "GET") -> httpx.Response | None:
        if self.out_of_time():
            return None
        host = urlparse(url).hostname or ""
        netguard.guard_url_host(host)  # raises Blocked for a private or metadata address
        if self.requests:
            time.sleep(self.lim["delay"])
        self.requests += 1
        try:
            return self.client.request(method, url, headers={**self.auth, **(headers or {})})
        except httpx.HTTPError as exc:
            self.pages.append({"url": url, "error": type(exc).__name__})
            return None

    def add(self, key: str, title: str, owasp: str, status: str, url: str, response: httpx.Response | None, evidence: str,
            severity: str = "medium", advice: str = "") -> None:
        if any(f["key"] == key and f["url"] == url for f in self.findings):
            return
        self.findings.append({"key": key, "title": title, "owasp": owasp, "category": OWASP[owasp], "status": status, "severity": severity,
                              "url": url, "request": f"GET {url}", "responseStatus": response.status_code if response is not None else None,
                              "evidence": evidence[:300], "advice": advice, "observedAt": utcnow().isoformat() + "Z"})


def _robots(run: _Run) -> None:
    r = run.get(urljoin(run.base, "/robots.txt"))
    if r is None or r.status_code != 200:
        return
    applies = False
    for line in r.text.splitlines():
        line = line.split("#", 1)[0].strip()
        if line.lower().startswith("user-agent:"):
            applies = line.split(":", 1)[1].strip() == "*"
        elif applies and line.lower().startswith("disallow:"):
            path = line.split(":", 1)[1].strip()
            if path:
                run.disallow.append(path)


def _check_response(run: _Run, url: str, r: httpx.Response, first: bool) -> None:
    h = {k.lower(): v for k, v in r.headers.items()}
    https = url.startswith("https://")
    if first:
        missing = [name for name, header in (("Content-Security-Policy", "content-security-policy"),
                                              ("X-Content-Type-Options", "x-content-type-options"),
                                              ("Referrer-Policy", "referrer-policy")) if header not in h]
        if "x-frame-options" not in h and "frame-ancestors" not in h.get("content-security-policy", ""):
            missing.append("X-Frame-Options or CSP frame-ancestors")
        if missing:
            run.add("missing-headers", "Security headers missing", "A05", "confirmed", url, r, "Missing: " + ", ".join(missing), "low",
                    "Send these headers from the web server or application.")
        if https and "strict-transport-security" not in h:
            run.add("no-hsts", "HTTPS without Strict-Transport-Security", "A02", "confirmed", url, r, "No Strict-Transport-Security header",
                    "medium", "Send Strict-Transport-Security with a max-age of at least six months.")
        for header in ("server", "x-powered-by", "x-aspnet-version"):
            if re.search(r"\d+\.\d+", h.get(header, "")):
                run.add("version-banner", "Software versions disclosed in headers", "A05", "confirmed", url, r,
                        f"{header}: {h[header]}", "low", "Remove version numbers from response headers.")
    for cookie in r.headers.get_list("set-cookie"):
        name = cookie.split("=", 1)[0].strip()
        flags = cookie.lower()
        problems = []
        if https and "secure" not in flags:
            problems.append("Secure")
        if SESSION_COOKIE.search(name) and "httponly" not in flags:
            problems.append("HttpOnly")
        if "samesite" not in flags:
            problems.append("SameSite")
        if problems:
            run.add("cookie-flags:" + name, f"Cookie '{name}' without {', '.join(problems)}", "A07" if "HttpOnly" in problems else "A05",
                    "confirmed", url, r, cookie.split(";", 1)[0][:40] + "…; " + "; ".join(x.strip() for x in cookie.split(";")[1:]),
                    "medium" if "Secure" in problems or "HttpOnly" in problems else "low", "Set Secure, HttpOnly and SameSite on cookies.")
    ctype = h.get("content-type", "")
    if "text/html" in ctype:
        body = r.text[:500_000]
        if re.search(r"<title>Index of /", body, re.I):
            run.add("directory-listing", "Directory listing enabled", "A05", "confirmed", url, r, "Page title 'Index of /…'", "medium",
                    "Turn off directory listing.")
        trace = STACK_TRACE.search(body)
        if trace:
            run.add("stack-trace", "Error details shown to visitors", "A05", "suspected", url, r, trace.group(0), "medium",
                    "Show a generic error page and log the details instead.")


def _crawl(run: _Run) -> None:
    queue, seen = [(run.base, 0)], set()
    first = True
    while queue and len(run.pages) < run.lim["max_pages"] and not run.out_of_time():
        url, depth = queue.pop(0)
        url = urldefrag(url)[0]
        if url in seen or not run.same_origin(url):
            continue
        seen.add(url)
        path = urlparse(url).path or "/"
        if any(path.startswith(d) for d in run.disallow):
            run.pages.append({"url": url, "skipped": "robots.txt"})
            continue
        r = run.get(url)
        if r is None:
            continue
        if r.is_redirect:
            target = urljoin(url, r.headers.get("location", ""))
            run.pages.append({"url": url, "status": r.status_code, "redirect": target})
            if url == run.base and run.base.startswith("http://") and not target.startswith("https://"):
                run.add("no-https-redirect", "Plain HTTP is served without moving to HTTPS", "A02", "confirmed", url, r,
                        f"Redirects to {target}", "medium", "Redirect every plain-HTTP request to HTTPS.")
            if run.same_origin(target) or (url == run.base and urlparse(target).hostname == run.origin[1]):
                if not run.same_origin(target):  # http -> https on the same host: continue the crawl there
                    p = urlparse(target)
                    run.origin = (p.scheme, p.hostname, p.port)
                queue.insert(0, (target, depth))
            continue
        run.pages.append({"url": url, "status": r.status_code, "type": r.headers.get("content-type", "")[:60]})
        if first and run.base.startswith("http://") and r.status_code == 200:
            run.add("no-https-redirect", "Plain HTTP is served without moving to HTTPS", "A02", "confirmed", url, r,
                    "HTTP 200 over plain HTTP", "medium", "Redirect every plain-HTTP request to HTTPS.")
        _check_response(run, url, r, first)
        first = False
        if "text/html" not in r.headers.get("content-type", ""):
            continue
        parser = _Links()
        try:
            parser.feed(r.text[:500_000])
        except Exception:  # noqa: BLE001 - broken HTML is not a finding
            pass
        for s in parser.scripts:
            src = urljoin(url, s["src"])
            for pattern, what in OLD_LIBRARIES:
                if pattern.search(src):
                    run.add("old-library:" + what, f"Outdated library referenced: {what}", "A06", "suspected", url, r, src, "medium",
                            "Confirm the version in use and upgrade it.")
            if not run.same_origin(src) and not s["integrity"]:
                run.add("no-sri:" + urlparse(src).hostname, "Third-party script without Subresource Integrity", "A08", "confirmed", url, r,
                        src, "low", "Add an integrity attribute to scripts loaded from other sites, or host them yourself.")
        for f in parser.forms:
            action = urljoin(url, f["action"] or url)
            if f["password"] and (action.startswith("http://") or url.startswith("http://")):
                run.add("password-over-http", "Password form submitted over plain HTTP", "A02", "confirmed", url, r,
                        f"form action={action}", "high", "Serve and submit sign-in forms over HTTPS only.")
        if depth < run.lim["max_depth"]:
            for href in parser.links:
                target = urljoin(url, href)
                if run.same_origin(target) and target not in seen:
                    queue.append((target, depth + 1))


def _exposed_files(run: _Run) -> None:
    probe = run.get(urljoin(run.base, f"/fenrir-not-here-{secrets.token_hex(6)}"))
    soft404 = probe is not None and probe.status_code == 200  # the site answers 200 for everything
    for path, (signature, what, owasp) in EXPOSED_FILES.items():
        if run.out_of_time():
            return
        if any(path.startswith(d) for d in run.disallow):
            continue
        url = urljoin(run.base, path)
        r = run.get(url)
        if r is None or r.status_code != 200 or not r.content:
            continue
        text = r.content[:4096].decode("latin-1")
        if re.search(signature, text):
            run.add("exposed:" + path, f"Exposed: {what}", owasp, "confirmed", url, r, f"{path} returned content matching its signature",
                    "high", "Remove the file from the web root or block access to it.")
        elif not soft404:
            run.add("exposed:" + path, f"Possibly exposed: {what}", owasp, "suspected", url, r, f"{path} returned HTTP 200 ({len(r.content)} bytes)",
                    "medium", "Check what this address returns and remove it if it is real.")


def _active_probes(run: _Run) -> None:
    marker = "fnr" + secrets.token_hex(5)
    probe = f"{marker}<i>"
    url = run.base + ("&" if "?" in run.base else "?") + "fenrir_probe=" + probe
    r = run.get(url)
    if r is not None and probe in r.text:
        run.add("reflection", "Query parameter echoed back without encoding", "A03", "suspected", url, r,
                f"The marker {probe} came back unencoded", "medium", "Encode output; check this page for cross-site scripting.")
    origin = "https://fenrir-origin-check.invalid"
    r = run.get(run.base, headers={"Origin": origin})
    if r is not None:
        allow = r.headers.get("access-control-allow-origin", "")
        creds = r.headers.get("access-control-allow-credentials", "").lower() == "true"
        if allow == origin and creds:
            run.add("cors-any-origin", "CORS trusts any origin, with credentials", "A01", "confirmed", run.base, r,
                    f"Access-Control-Allow-Origin: {allow}; Access-Control-Allow-Credentials: true", "high",
                    "Allow only the origins that need access.")
        elif allow == origin or allow == "*":
            run.add("cors-wide", "CORS allows any origin", "A05", "confirmed", run.base, r, f"Access-Control-Allow-Origin: {allow}", "low",
                    "Allow only the origins that need access, unless the content is public.")


def execute(db: Session, row: WebAssessment) -> WebAssessment:
    lim = limits(row.config or {})
    auth = None
    if row.auth_envelope:
        auth = {row.config["authHeader"]: crypto.decrypt(row.auth_envelope, f"web-assessment:{row.id}")}
    row.status, row.started_at = "running", utcnow()
    db.commit()
    try:
        with _client() as client:
            run = _Run(row.url, lim, auth, client)
            _robots(run)
            _crawl(run)
            _exposed_files(run)
            if row.profile == "standard":
                _active_probes(run)
        untested = [{"owasp": k, "category": OWASP[k], "reason": v} for k, v in NOT_TESTED.items()]
        if row.profile == "passive":
            untested.append({"owasp": "A03", "category": OWASP["A03"], "reason": "The passive profile sends no probes"})
        if not auth:
            untested.append({"owasp": "A01", "category": OWASP["A01"],
                             "reason": "Not authenticated: pages behind sign-in and access between users were not tested"})
        untested.append({"owasp": "A07", "category": OWASP["A07"], "reason": "Password guessing and session handling attacks are never tried"})
        row.pages, row.findings, row.untested = run.pages, run.findings, untested
        row.summary = {"pages": sum(1 for p in run.pages if "status" in p), "requests": run.requests,
                       "confirmed": sum(1 for f in run.findings if f["status"] == "confirmed"),
                       "suspected": sum(1 for f in run.findings if f["status"] == "suspected"),
                       "stoppedByBudget": run.out_of_time(), "limits": lim, "robotsDisallow": run.disallow}
        row.status = "completed"
    except netguard.Blocked as exc:
        row.status, row.error = "failed", str(exc)[:500]
    except Exception as exc:  # noqa: BLE001
        log.exception("web assessment %s failed", row.id)
        row.status, row.error = "failed", f"{type(exc).__name__}: {str(exc)[:300]}"
    row.auth_envelope = None  # the credential is gone once the run ends
    row.finished_at = utcnow()
    audit.record(db, "system:web-assessment", "web_assessment.finished", row.id, row.tenant_id, status=row.status,
                 summary=row.summary, url=row.url)
    db.commit()
    return row


def tick(db: Session, limit: int = 2) -> int:
    """Run queued assessments (a couple per pass); a run left 'running' by a restart is marked failed."""
    stale = db.scalars(select(WebAssessment).where(WebAssessment.status == "running")).all()
    for row in stale:
        if row.started_at and (utcnow() - row.started_at).total_seconds() > 3600:
            row.status, row.error, row.auth_envelope, row.finished_at = "failed", "Interrupted (server restarted)", None, utcnow()
    db.commit()
    done = 0
    for row in db.scalars(select(WebAssessment).where(WebAssessment.status == "queued").order_by(WebAssessment.created_at).limit(limit)).all():
        execute(db, row)
        done += 1
    return done

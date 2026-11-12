"""Email security: Fenrir's own verdict on a message, next to Microsoft's.

``analyse()`` takes one message as Microsoft Graph returns it (headers, sender, body, attachment details) plus what
Fenrir knows about the customer (their domains and people, threat intel, senders seen before) and returns:

- **Microsoft's verdict**, read from the headers Microsoft stamps on every message it delivers
  (``X-Forefront-Antispam-Report``, ``X-Microsoft-Antispam``, ``Authentication-Results``): spam confidence (SCL), bulk
  (BCL), phishing (PCL), the category Microsoft gave it (CAT) and the SPF, DKIM, DMARC and composite authentication
  results. A message in Junk Email counts as at least spam.
- **Fenrir's verdict**: a score built from named checks, so every decision says why. Threat intel (abuse.ch URLhaus,
  ThreatFox, MalwareBazaar and your own indicators) on links and attachment hashes; dangerous and disguised
  attachments; failed sender authentication; lookalike domains of the customer's own domains and well-known brands;
  outsiders using a colleague's display name; links whose text names one site but go to another; links to bare IP
  addresses; Reply-To redirection; and the wording of credential and payment scams.
- **Features**: the same signals as numbers, kept for training a model later (no message content).

Nothing here talks to Microsoft or the database, so it can be tested on its own and reused by a mail gateway.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from html import unescape
from urllib.parse import urlparse

VERDICTS = ("clean", "suspicious", "phish", "malware")
MS_VERDICTS = ("unknown", "clean", "bulk", "spam", "phish", "malware")
FLAGGED = {"phish", "malware"}
SUSPICIOUS_AT, PHISH_AT, HIGH_AT = 25, 50, 80

FREE_MAIL = {"gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "hotmail.co.uk", "live.com", "live.co.uk",
             "msn.com", "yahoo.com", "yahoo.co.uk", "ymail.com", "icloud.com", "me.com", "aol.com", "proton.me",
             "protonmail.com", "gmx.com", "gmx.co.uk", "mail.com", "zoho.com", "yandex.com"}
# Brands most often impersonated in credential phishing: their real domains, for lookalike checks.
BRANDS = {"microsoft.com", "office.com", "office365.com", "outlook.com", "live.com", "sharepoint.com", "onedrive.com",
          "docusign.com", "docusign.net", "adobe.com", "dropbox.com", "paypal.com", "amazon.com", "amazon.co.uk",
          "apple.com", "google.com", "dhl.com", "fedex.com", "ups.com", "royalmail.com", "hmrc.gov.uk", "gov.uk",
          "barclays.co.uk", "hsbc.co.uk", "lloydsbank.co.uk", "natwest.com", "santander.co.uk", "xero.com",
          "quickbooks.com", "intuit.com", "linkedin.com", "wetransfer.com", "zoom.us"}
# Real domains of those brands that contain the brand's name (never lookalikes).
BRAND_OWNED = {"onmicrosoft.com", "microsoftonline.com", "microsoft365.com", "sharepointonline.com", "office.net",
               "windows.net", "azure.com", "msftauth.net", "amazonses.com", "amazonaws.com", "amazon.de", "amazon.fr",
               "docusign.eu", "paypal.co.uk", "googlemail.com", "googleusercontent.com", "appleid.apple.com",
               "linkedin.cn", "zoom.com", "xero.co.uk", "dropboxusercontent.com", "adobesign.com", "adobelogin.com",
               "outlook.office365.com", "dhl.co.uk", "dhl.de", "ups.co.uk", "fedex.co.uk"}
# Words scammers add to a brand name: paypal-secure.com, microsoftverify.net.
LURE_WORDS = ("secure", "login", "logon", "signin", "verify", "verification", "support", "account", "update", "billing",
              "auth", "helpdesk", "alert", "notice", "security", "service", "portal", "wallet", "refund", "invoice")
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "cutt.ly", "rebrand.ly", "buff.ly", "t.ly",
              "shorturl.at", "rb.gy", "tiny.cc"}
EXECUTABLE = {"exe", "scr", "com", "pif", "cpl", "msi", "msp", "bat", "cmd", "ps1", "psm1", "vbs", "vbe", "js", "jse",
              "wsf", "wsh", "hta", "jar", "lnk", "reg", "dll", "xll", "appx", "msix", "application", "gadget", "inf",
              "scf", "url", "iqy", "slk", "one", "chm"}
DISK_IMAGE = {"iso", "img", "vhd", "vhdx"}
WEB_PAGE = {"htm", "html", "shtml", "xhtml", "svg", "mht", "mhtml"}
MACRO_OFFICE = {"docm", "dotm", "xlsm", "xltm", "xlam", "pptm", "potm", "ppam", "sldm"}
DECOY = {"pdf", "doc", "docx", "xls", "xlsx", "jpg", "jpeg", "png", "txt", "rtf", "csv"}

PHRASES = [
    (r"verify (your|the) (account|identity|mailbox|email)", "asks you to verify your account"),
    (r"(password|mailbox|account) (will )?(expire|expires|expired|be (suspended|disabled|deleted|closed))", "says your account or password is about to stop working"),
    (r"unusual (sign[- ]?in|activity|login)", "warns of unusual sign-in activity"),
    (r"(confirm|update|validate) (your )?(payment|billing|bank) (details|information)", "asks you to update payment details"),
    (r"(bank|account|payment) details (have )?(changed|been updated)", "says bank details have changed"),
    (r"(wire|bank|urgent) transfer", "asks for a money transfer"),
    (r"gift ?cards?", "mentions gift cards"),
    (r"(overdue|outstanding|unpaid) invoice", "chases an overdue invoice"),
    (r"(shared|sent) (a |an )?(document|file|fax|voicemail) with you", "says a document or voicemail was shared with you"),
    (r"(urgent|immediate) (action|response|attention) required", "demands urgent action"),
    (r"(within|in) (24|48) hours", "sets a 24-48 hour deadline"),
    (r"(click|tap) here to (login|log in|sign in|verify|unlock|restore)", "asks you to click to sign in"),
    (r"are you (available|at your desk)", "opens like a CEO-fraud message"),
]
PHRASE_PATTERNS = [(re.compile(p, re.I), why) for p, why in PHRASES]
URL_PATTERN = re.compile(r"https?://[^\s\"'<>()\[\]]+", re.I)
ANCHOR_PATTERN = re.compile(r"<a\b[^>]*?href\s*=\s*([\"'])(.*?)\1[^>]*>(.*?)</a>", re.I | re.S)
TAG_PATTERN = re.compile(r"<[^>]+>")
HOMOGLYPHS = [("rn", "m"), ("vv", "w"), ("0", "o"), ("1", "l"), ("l", "i"), ("3", "e"), ("5", "s"), ("@", "a")]


@dataclass
class Context:
    """What Fenrir knows about the customer whose mailbox this is."""
    own_domains: set[str] = field(default_factory=set)          # the customer's verified domains
    people: dict[str, str] = field(default_factory=dict)        # normalised display name -> their own address
    bad_urls: set[str] = field(default_factory=set)              # threat-intel URLs (lower case)
    bad_domains: dict[str, str] = field(default_factory=dict)    # threat-intel domain -> category
    bad_hashes: dict[str, str] = field(default_factory=dict)     # threat-intel sha256 -> family/category
    allowed_domains: set[str] = field(default_factory=set)       # indicators marked "allow"
    known_senders: set[str] = field(default_factory=set)         # sender domains seen before at this customer
    allow_senders: set[str] = field(default_factory=set)         # customer allow list: addresses
    allow_sender_domains: set[str] = field(default_factory=set)  # customer allow list: domains
    block_senders: set[str] = field(default_factory=set)         # customer block list: addresses
    block_sender_domains: set[str] = field(default_factory=set)  # customer block list: domains
    model: object | None = None                                  # the learned model (email_model.py), when active
    policy: dict | None = None                                   # the customer's email policy (email_policy.py)


@dataclass
class Message:
    mailbox: str
    folder: str                          # inbox | junkemail
    sender_address: str
    sender_name: str
    reply_to: list[str]
    subject: str
    headers: dict[str, str]              # lower-case header name -> value (last wins)
    body_html: str
    attachments: list[dict]              # {name, contentType, size, sha256 (if read)}


# --------------------------------------------------------------------------- Microsoft's verdict

def _pairs(value: str) -> dict[str, str]:
    out = {}
    for part in (value or "").split(";"):
        if ":" in part:
            key, _, val = part.partition(":")
            out[key.strip().upper()] = val.strip()
    return out


def _auth_result(value: str, method: str) -> str:
    match = re.search(rf"\b{method}=([a-z]+)", value or "", re.I)
    return match.group(1).lower() if match else ""


def _int(value) -> int | None:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def microsoft_verdict(headers: dict[str, str], folder: str) -> dict:
    """Microsoft's own decision about the message, from the headers it added."""
    forefront = _pairs(headers.get("x-forefront-antispam-report", ""))
    antispam = _pairs(headers.get("x-microsoft-antispam", ""))
    auth = headers.get("authentication-results", "")
    details = {
        "scl": _int(forefront.get("SCL")), "bcl": _int(antispam.get("BCL")), "pcl": _int(antispam.get("PCL")),
        "sfv": forefront.get("SFV", ""), "cat": forefront.get("CAT", ""), "country": forefront.get("CTRY", ""),
        "spf": _auth_result(auth, "spf"), "dkim": _auth_result(auth, "dkim"), "dmarc": _auth_result(auth, "dmarc"),
        "compauth": _auth_result(auth, "compauth"),
        "dmarcAction": (re.search(r"\bdmarc=fail\s+action=([a-z]+)", auth, re.I).group(1).lower()
                        if re.search(r"\bdmarc=fail\s+action=([a-z]+)", auth, re.I) else ""),
    }
    cat, sfv, scl = details["cat"].upper(), details["sfv"].upper(), details["scl"]
    if not forefront and not antispam and not auth:
        verdict = "spam" if folder == "junkemail" else "unknown"
    elif cat in {"MALW", "AMP", "SAP"}:
        verdict = "malware"
    elif cat in {"PHSH", "HPHSH", "HPHISH", "SPOOF", "UIMP", "DIMP", "GIMP", "BIMP", "FTBP"}:
        verdict = "phish"
    elif cat in {"SPM", "HSPM"} or sfv == "SPM" or (scl is not None and scl >= 5):
        verdict = "spam"
    elif cat == "BULK" or (details["bcl"] or 0) >= 7:
        verdict = "bulk"
    elif folder == "junkemail":
        verdict = "spam"
    else:
        verdict = "clean"
    return {"verdict": verdict, **details}


# --------------------------------------------------------------------------- helpers

def domain_of(address: str) -> str:
    return address.rsplit("@", 1)[-1].strip().lower().rstrip(".") if "@" in (address or "") else ""


def registrable(host: str) -> str:
    """A rough registrable domain (last two labels, three for co.uk-style names)."""
    parts = [p for p in (host or "").lower().strip(".").split(".") if p]
    if len(parts) >= 3 and len(parts[-1]) == 2 and parts[-2] in {"co", "org", "gov", "ac", "com", "net", "ltd", "plc", "me"}:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _skeleton(text: str) -> str:
    text = text.lower()
    for a, b in HOMOGLYPHS:
        text = text.replace(a, b)
    return text


def _distance(a: str, b: str) -> int:
    if abs(len(a) - len(b)) > 2:
        return 3
    # Edit distance where swapping two neighbouring letters counts as one edit (micorsoft, docusing).
    rows = [list(range(len(b) + 1))] + [[i] + [0] * len(b) for i in range(1, len(a) + 1)]
    for i in range(1, len(a) + 1):
        for j in range(1, len(b) + 1):
            cost = a[i - 1] != b[j - 1]
            rows[i][j] = min(rows[i - 1][j] + 1, rows[i][j - 1] + 1, rows[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                rows[i][j] = min(rows[i][j], rows[i - 2][j - 2] + 1)
    return rows[-1][-1]


def lookalike_of(domain: str, targets: set[str]) -> str | None:
    """The real domain this one imitates (one or two letters off, or the same once look-alike letters are swapped)."""
    if not domain:
        return None
    mine = registrable(domain)
    if mine in BRAND_OWNED or domain.lower() in BRAND_OWNED:
        return None
    name = mine.split(".")[0]
    for target in targets:
        real = registrable(target)
        if mine == real:
            return None
    for target in targets:
        real = registrable(target)
        real_name = real.split(".")[0]
        if len(real_name) < 4:
            continue
        if _skeleton(name) == _skeleton(real_name) or (len(real_name) >= 7 and _distance(name, real_name) == 1) \
                or (len(real_name) >= 9 and _distance(name, real_name) == 2):
            return real
        # The real name inside a longer one with a lure word or hyphen: microsoft-support.com, paypalsecure.net
        if len(real_name) >= 5 and real_name in name and name != real_name and \
                ("-" in name or any(word in name.replace(real_name, "") for word in LURE_WORDS)):
            return real
    return None


def normalise_name(name: str) -> str:
    return re.sub(r"[^a-z ]", "", (name or "").lower()).strip()


def _host(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower().rstrip(".")
    except ValueError:
        return ""


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def _extension(name: str) -> tuple[str, str]:
    parts = (name or "").lower().strip().rsplit(".", 2)
    last = parts[-1] if len(parts) > 1 else ""
    before = parts[-2] if len(parts) > 2 else ""
    return last, before


def archive_members(name: str, payload: bytes) -> tuple[list[str], bool]:
    """(file names inside a .zip, True if any is password-protected). Other formats are not opened."""
    import io
    import zipfile

    if not payload or not (name or "").lower().endswith(".zip") and not payload.startswith(b"PK\x03\x04"):
        return [], False
    try:
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            infos = archive.infolist()[:200]
            return [i.filename[-200:] for i in infos if not i.is_dir()], any(i.flag_bits & 0x1 for i in infos)
    except (zipfile.BadZipFile, ValueError, OSError, RuntimeError):
        return [], False


def links(html: str) -> tuple[list[str], list[tuple[str, str]]]:
    """(every URL in the body, [(link text, href)] for anchors)."""
    text = unescape(html or "")
    anchors = []
    for _, href, inner in ANCHOR_PATTERN.findall(text):
        anchors.append((TAG_PATTERN.sub("", inner).strip(), href.strip()))
    urls = list(dict.fromkeys([href for _, href in anchors if href.lower().startswith(("http://", "https://"))]
                              + URL_PATTERN.findall(text)))
    return urls[:200], anchors[:200]


def plain_text(html: str) -> str:
    return re.sub(r"\s+", " ", TAG_PATTERN.sub(" ", unescape(html or "")))[:20000]


# --------------------------------------------------------------------------- Fenrir's verdict

def analyse(message: Message, ctx: Context) -> dict:
    reasons: list[dict] = []
    kinds: set[str] = set()

    def add(code: str, points: int, detail: str, kind: str = "phish") -> None:
        reasons.append({"code": code, "points": points, "detail": detail})
        if points > 0:
            kinds.add(kind)

    ms = microsoft_verdict(message.headers, message.folder)
    sender_domain = domain_of(message.sender_address)
    sender = (message.sender_address or "").lower()

    # The customer's own lists come first. Allow is only honoured when the sender is not obviously forged.
    forged = ms["dmarc"] == "fail" or ms["compauth"] == "fail"
    on_allow = sender in ctx.allow_senders or _in_domains(sender_domain, ctx.allow_sender_domains)
    if on_allow and not forged:
        return _result(ms, "clean", 0, [{"code": "list.allow", "points": 0,
                                         "detail": f"{sender or sender_domain} is on this customer's allow list"}],
                       {"codes": ["list.allow"]}, sender_domain, [])
    if sender in ctx.block_senders or _in_domains(sender_domain, ctx.block_sender_domains):
        add("list.block", 100, f"{sender or sender_domain} is on this customer's block list")
    own = {d.lower() for d in ctx.own_domains}
    external = sender_domain not in own
    urls, anchors = links(message.body_html)
    hosts = [h for h in (_host(u) for u in urls) if h]
    text = f"{message.subject} {plain_text(message.body_html)}"

    # Threat intel: links and attachments.
    intel_hits = 0
    for url in urls:
        host = _host(url)
        if registrable(host) in ctx.allowed_domains:
            continue
        hit = url.lower().rstrip("/") in ctx.bad_urls
        category = ""
        if not hit and host:
            parts = host.split(".")
            for i in range(len(parts) - 1):
                if ".".join(parts[i:]) in ctx.bad_domains:
                    hit, category = True, ctx.bad_domains[".".join(parts[i:])]
                    break
        if hit:
            intel_hits += 1
            if intel_hits <= 3:
                add("intel.url", 70, f"Links to {host}, listed in threat intelligence{f' ({category})' if category else ''}",
                    "malware" if category == "malware" else "phish")
    for attachment in message.attachments:
        sha = str(attachment.get("sha256") or "").lower()
        if sha and sha in ctx.bad_hashes:
            add("intel.attachment", 100, f"Attachment {attachment.get('name')} is known malware ({ctx.bad_hashes[sha]})", "malware")

    # Attachments that run code, hide code or carry a fake sign-in page.
    for attachment in message.attachments[:20]:
        name = str(attachment.get("name") or "")
        ext, before = _extension(name)
        if ext in EXECUTABLE:
            add("attachment.executable", 45, f"Attachment {name} is a program or script", "malware")
            if before in DECOY:
                add("attachment.double-extension", 30, f"{name} pretends to be a .{before} file", "malware")
        elif ext in DISK_IMAGE:
            add("attachment.disk-image", 40, f"Attachment {name} is a disk image, often used to slip past filters", "malware")
        elif ext in WEB_PAGE:
            add("attachment.web-page", 30, f"Attachment {name} is a web page, a common fake sign-in form")
        elif ext in MACRO_OFFICE:
            add("attachment.macro", 25, f"Attachment {name} is an Office file with macros", "malware")

    # Sender authentication.
    if ms["dmarc"] == "fail":
        add("auth.dmarc", 25, "The sender's domain failed DMARC: the message may be forged")
    if ms["spf"] in {"fail", "softfail"} and ms["dkim"] not in {"pass"}:
        add("auth.spf", 15, f"SPF {ms['spf']} with no valid DKIM signature")
    if ms["compauth"] == "fail":
        add("auth.compauth", 20, "Microsoft's composite authentication failed")
    if not external and (ms["dmarc"] == "fail" or ms["compauth"] == "fail" or ms["spf"] == "fail"):
        add("spoof.own-domain", 35, f"Claims to come from your own domain {sender_domain} but failed authentication")

    # Lookalike domains and impersonated people.
    imitated = lookalike_of(sender_domain, own) if external else None
    if imitated:
        add("lookalike.own", 50, f"Sender domain {sender_domain} imitates your domain {imitated}")
    else:
        brand = lookalike_of(sender_domain, BRANDS) if external else None
        if brand:
            add("lookalike.brand", 40, f"Sender domain {sender_domain} imitates {brand}")
    display = normalise_name(message.sender_name)
    if external and display and len(display) >= 5 and display in ctx.people:
        add("impersonation.colleague", 40,
            f"An outside address ({message.sender_address}) is using the name of {message.sender_name}, one of your people")
        if sender_domain in FREE_MAIL:
            add("impersonation.free-mail", 15, "…from a free email account")
    if external and re.search(r"\b(microsoft|office ?365|it support|helpdesk|help desk|administrator|mail ?admin)\b",
                              message.sender_name or "", re.I) and registrable(sender_domain) not in BRANDS:
        add("impersonation.service", 15, f"Display name '{message.sender_name}' suggests IT or Microsoft, from {sender_domain}")

    # Reply-To sends answers somewhere else.
    for reply in message.reply_to[:3]:
        reply_domain = domain_of(reply)
        if reply_domain and registrable(reply_domain) != registrable(sender_domain):
            add("reply-to.mismatch", 20 if reply_domain in FREE_MAIL else 10,
                f"Replies go to {reply_domain}, not the sender's domain {sender_domain}")
            break

    # Links.
    mismatched = 0
    for label, href in anchors:
        shown = _host(label) if label.lower().startswith(("http://", "https://", "www.")) else ""
        if label.lower().startswith("www."):
            shown = _host("http://" + label)
        target = _host(href)
        if shown and target and registrable(shown) != registrable(target) and registrable(target) not in ctx.allowed_domains:
            mismatched += 1
            if mismatched == 1:
                add("link.mismatch", 25, f"A link shows {shown} but goes to {target}")
    if any(_is_ip(h) for h in hosts):
        add("link.ip", 20, "Links to a bare IP address instead of a website name")
    if any(registrable(h) in SHORTENERS for h in hosts):
        add("link.shortener", 5, "Uses a link shortener, which hides where the link goes")
    for host in hosts:
        brand = lookalike_of(host, BRANDS | own)
        if brand and registrable(host) not in ctx.allowed_domains:
            add("link.lookalike", 35, f"Links to {host}, which imitates {brand}")
            break

    # Wording of credential, invoice and CEO-fraud scams.
    phrases = [why for pattern, why in PHRASE_PATTERNS if pattern.search(text)]
    if phrases:
        add("language.scam", min(30, 10 * len(phrases)), "Wording typical of scams: " + "; ".join(phrases[:3]))

    # New sender: only adds to other signals.
    first_contact = external and bool(ctx.known_senders) and sender_domain not in ctx.known_senders
    if first_contact and reasons:
        add("sender.first-contact", 5, f"First message from {sender_domain} to this customer")

    features = {
        "intel_url": intel_hits, "intel_attachment": int(any(r["code"] == "intel.attachment" for r in reasons)),
        "attachments": len(message.attachments), "url_count": len(urls), "link_mismatch": mismatched,
        "link_ip": int(any(_is_ip(h) for h in hosts)), "external": int(external), "free_mail": int(sender_domain in FREE_MAIL),
        "first_contact": int(first_contact), "scam_phrases": len(phrases),
        "spf_fail": int(ms["spf"] in {"fail", "softfail"}), "dkim_pass": int(ms["dkim"] == "pass"),
        "dmarc_fail": int(ms["dmarc"] == "fail"), "compauth_fail": int(ms["compauth"] == "fail"),
        "ms_scl": ms["scl"] if ms["scl"] is not None else -1, "ms_bcl": ms["bcl"] if ms["bcl"] is not None else -1,
        "codes": sorted({r["code"] for r in reasons}),
    }

    # The learned model (email_model.py) can only add evidence, and only when it has proved itself.
    model_score = None
    if ctx.model is not None:
        model_score = round(ctx.model.probability(features), 4)
        rules_score = sum(r["points"] for r in reasons)
        if model_score >= ctx.model.threshold and rules_score < PHISH_AT:
            add("model.learned", 30 if model_score >= 0.95 else 20,
                f"Looks like the phishing flagged here before ({round(model_score * 100)}% sure, model v{ctx.model.version})")

    score = max(0, min(100, sum(r["points"] for r in reasons)))
    if score >= PHISH_AT:
        verdict = "malware" if "malware" in kinds else "phish"
    elif score >= SUSPICIOUS_AT:
        verdict = "suspicious"
    else:
        verdict = "clean"
    if any(r["code"] == "intel.attachment" for r in reasons):
        verdict = "malware"

    if on_allow and forged:
        reasons.append({"code": "list.allow-ignored", "points": 0,
                        "detail": "On the allow list, but ignored because the sender failed authentication"})
    result = _result(ms, verdict, score, reasons, features, sender_domain, sorted({registrable(h) for h in hosts})[:30])
    result["model_score"] = model_score
    return result


def _in_domains(domain: str, domains: set[str]) -> bool:
    parts = (domain or "").split(".")
    return any(".".join(parts[i:]) in domains for i in range(len(parts) - 1))


def _result(ms: dict, verdict: str, score: int, reasons: list[dict], features: dict, sender_domain: str,
            link_domains: list[str]) -> dict:
    return {
        "microsoft": ms,
        "verdict": verdict,
        "score": score,
        "reasons": sorted(reasons, key=lambda r: -r["points"]),
        "features": features,
        "sender_domain": sender_domain,
        "link_domains": link_domains,
    }


def agreement(fenrir_verdict: str, microsoft: str) -> str:
    """both | fenrir_only | microsoft_only | neither (phish and malware count as flagged)."""
    fenrir_flagged, microsoft_flagged = fenrir_verdict in FLAGGED, microsoft in FLAGGED
    if fenrir_flagged and microsoft_flagged:
        return "both"
    if fenrir_flagged:
        return "fenrir_only"
    if microsoft_flagged:
        return "microsoft_only"
    return "neither"

import hashlib
import html
import re
from datetime import datetime
from email import policy
from email.parser import BytesParser, Parser
from email.utils import parseaddr
from typing import Dict, List, Optional
from urllib.parse import urlparse
from uuid import uuid4

from fastapi import APIRouter, File, HTTPException, UploadFile
from pydantic import BaseModel, EmailStr, Field

router = APIRouter()

CONNECTED_DOMAINS: Dict[str, dict] = {}
CAMPAIGNS: Dict[str, dict] = {}
EVENTS: List[dict] = []

URL_RE = re.compile(r"(?i)\bhttps?://[^\s<>\"']+")
IP_HOST_RE = re.compile(r"(?i)^https?://(?:\d{1,3}\.){3}\d{1,3}(?:[:/]|$)")
SHORTENER_RE = re.compile(r"(?i)\b(bit\.ly|tinyurl\.com|t\.co|goo\.gl|ow\.ly|is\.gd|buff\.ly|cutt\.ly|rebrand\.ly|lnkd\.in)\b")
SUSPICIOUS_ATTACHMENT_EXTENSIONS = {".exe", ".scr", ".js", ".jse", ".vbs", ".vbe", ".wsf", ".hta", ".bat", ".cmd", ".ps1", ".iso", ".img", ".lnk", ".one", ".html", ".htm", ".docm", ".xlsm", ".pptm"}
ARCHIVE_EXTENSIONS = {".zip", ".rar", ".7z", ".gz", ".tar"}
AUTH_HEADERS = ["authentication-results", "received-spf", "dkim-signature", "arc-authentication-results"]
SUSPICIOUS_TLDS = {"zip", "mov", "top", "xyz", "click", "work", "support", "country", "gq", "tk"}
EXECUTABLE_URL_EXTENSIONS = {".exe", ".scr", ".js", ".jse", ".vbs", ".hta", ".ps1", ".iso", ".img", ".lnk"}
BRAND_WORDS = {"microsoft", "office", "outlook", "onedrive", "sharepoint", "google", "dropbox", "docusign", "adobe", "paypal", "amazon", "apple", "bank"}
PHISHING_CONTEXTS = {
    "Reply-To domain differs from From domain": "replies would go somewhere other than the visible sender, which is often used to move the conversation to an attacker-controlled mailbox.",
    "Return-Path domain differs from From domain": "bounce handling points to a different domain than the visible sender, so the sending path needs verification.",
    "Sender domain differs from From domain": "the technical sender and the visible sender do not match, which may be legitimate for a platform but is also common in spoofing.",
    "SPF authentication issue": "the sending server was not authorised by the sender domain's SPF policy.",
    "DKIM authentication issue": "the message signature did not verify, so the message may have been altered or sent by an unauthorised system.",
    "DMARC authentication issue": "the sender failed domain-alignment policy, which is a strong phishing or spoofing indicator.",
    "SPF result not visible": "the copied headers do not show SPF status, so the original full headers are needed before trusting the sender.",
    "DKIM result not visible": "the copied headers do not show DKIM status, so the original full headers are needed before trusting the sender.",
    "DMARC result not visible": "the copied headers do not show DMARC status, so the original full headers are needed before trusting the sender.",
    "Social engineering pressure language": "the message is trying to create urgency around credentials, payments, account access, or sign-in activity.",
    "Suspicious URL pattern": "the message is trying to send the user to a link with a suspicious host, format, or destination.",
    "Visible link text does not match destination": "the link text shows one web address but actually points somewhere else.",
    "External link does not match sender domain": "the email sender and link destination are unrelated, which should be verified before clicking.",
    "HTML credential collection form": "the email contains a form or password input that could collect credentials directly from the message.",
    "Hidden or deceptive HTML content": "the email uses hidden styling or tiny text that can conceal content from the user while still affecting rendering or scanning.",
    "Risky attachment": "the attachment format can execute code, hide payloads, or deliver malware if opened.",
    "Double-extension attachment": "the attachment name is trying to look like a safer document while ending in a risky executable or script extension.",
}

class DomainConnectRequest(BaseModel):
    domain: str = Field(..., examples=["company.co.uk"])
    provider: str = Field("manual", examples=["m365", "google", "manual"])

class TemplateRequest(BaseModel):
    name: str
    subject: str
    pretext: str
    landing_message: str = "This was an authorised security awareness simulation."

class CampaignRequest(BaseModel):
    domain: str
    name: str
    template_name: str = "Security Awareness Check"
    subject: str = "Action required: security awareness check"
    recipients: List[EmailStr]
    scheduled_at: Optional[str] = None

class EventRequest(BaseModel):
    campaign_id: str
    recipient: EmailStr
    action: str

class EmailAnalysisRequest(BaseModel):
    raw_email: str = Field(..., description="Raw .eml content or copied email headers/body")
    source_name: Optional[str] = "pasted-email.eml"

DEFAULT_TEMPLATES = [
    {"name": "Password Reset Awareness", "subject": "Password reset required", "pretext": "Simulates a common credential-pressure lure without collecting credentials.", "landing_message": "This was a security awareness simulation. Never enter credentials from unexpected links."},
    {"name": "Invoice Review Awareness", "subject": "Invoice awaiting review", "pretext": "Simulates invoice-themed social engineering used in business email compromise.", "landing_message": "This was a simulation. Verify unexpected invoice requests through trusted channels."},
    {"name": "MFA Prompt Awareness", "subject": "Unusual sign-in activity detected", "pretext": "Simulates MFA fatigue/social engineering themes without credential collection.", "landing_message": "This was a simulation. Report unexpected MFA or sign-in prompts immediately."},
]

TEMPLATES: Dict[str, dict] = {template["name"]: template for template in DEFAULT_TEMPLATES}

def normalise_domain(domain: str) -> str:
    clean = domain.lower().strip().replace("https://", "").replace("http://", "").strip("/")
    if "@" in clean or not clean or "." not in clean:
        raise HTTPException(status_code=400, detail="Invalid domain")
    return clean

def domain_from_email(value: str) -> str:
    _, addr = parseaddr(value or "")
    if "@" not in addr:
        return ""
    return addr.rsplit("@", 1)[-1].lower()

def safe_ext(filename: str) -> str:
    name = filename.lower().strip()
    if "." not in name:
        return ""
    return "." + name.rsplit(".", 1)[-1]

def suffixes(filename: str) -> List[str]:
    return ["." + part for part in filename.lower().strip().split(".")[1:]]

def root_domain(domain: str) -> str:
    host = (domain or "").lower().strip(".")
    if not host or re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", host):
        return host
    labels = [part for part in host.split(".") if part]
    if len(labels) <= 2:
        return host
    return ".".join(labels[-2:])

def host_from_url(url: str) -> str:
    parsed = urlparse(url)
    return (parsed.hostname or "").lower().strip(".")

def display_url_host(text: str) -> str:
    match = URL_RE.search(html.unescape(text or ""))
    return host_from_url(match.group(0)) if match else ""

def strip_html(value: str) -> str:
    without_tags = re.sub(r"(?is)<(script|style).*?</\1>", " ", value or "")
    without_tags = re.sub(r"(?is)<[^>]+>", " ", without_tags)
    return html.unescape(re.sub(r"\s+", " ", without_tags)).strip()

def extract_html_link_mismatches(body: str) -> List[dict]:
    mismatches: List[dict] = []
    for href, label in re.findall(r"(?is)<a\b[^>]*href=[\"']([^\"']+)[\"'][^>]*>(.*?)</a>", body or ""):
        if not href.lower().startswith(("http://", "https://")):
            continue
        shown_host = display_url_host(strip_html(label))
        actual_host = host_from_url(href)
        if shown_host and actual_host and root_domain(shown_host) != root_domain(actual_host):
            mismatches.append({"shown_host": shown_host, "actual_host": actual_host, "href": href, "label": strip_html(label)[:240]})
    return mismatches

def html_form_indicators(body: str) -> dict:
    raw = body or ""
    return {
        "has_form": bool(re.search(r"(?is)<form\b", raw)),
        "has_password_input": bool(re.search(r"(?is)<input\b[^>]+type=[\"']?password", raw)),
        "hidden_content": bool(re.search(r"(?is)(display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0)", raw)),
    }

def enforce_internal(domain: str, recipients: List[str]):
    blocked = [r for r in recipients if not str(r).lower().endswith("@" + domain)]
    if blocked:
        raise HTTPException(status_code=403, detail={"message": "External recipients blocked", "blocked": blocked})

def log_event(campaign_id: str, recipient: str, action: str):
    EVENTS.append({"event_id": str(uuid4()), "campaign_id": campaign_id, "recipient": str(recipient), "action": action, "timestamp": datetime.utcnow().isoformat() + "Z"})

def extract_urls(text: str) -> List[dict]:
    found = []
    seen = set()
    for match in URL_RE.findall(text or ""):
        url = match.rstrip(".,);]}")
        if url in seen:
            continue
        seen.add(url)
        parsed = urlparse(url)
        host = (parsed.hostname or re.sub(r"(?i)^https?://", "", url).split("/", 1)[0].split(":", 1)[0]).lower()
        reasons = []
        severity = "low"
        if IP_HOST_RE.search(url):
            severity = "high"
            reasons.append("URL uses an IP address rather than a domain")
        if parsed.scheme == "http":
            severity = "medium" if severity == "low" else severity
            reasons.append("URL uses plain HTTP")
        if "@" in (parsed.netloc or ""):
            severity = "high"
            reasons.append("URL contains userinfo before the real host")
        if SHORTENER_RE.search(host):
            severity = "medium" if severity == "low" else severity
            reasons.append("URL uses a known link shortener")
        if "%40" in url.lower():
            severity = "medium" if severity == "low" else severity
            reasons.append("URL contains encoded @ token")
        if any(token in host for token in ["login", "secure", "verify", "account", "update"]):
            severity = "medium" if severity == "low" else severity
            reasons.append("URL host uses credential-pressure wording")
        if host.startswith("xn--") or ".xn--" in host:
            severity = "medium" if severity == "low" else severity
            reasons.append("URL host uses punycode")
        if host.rsplit(".", 1)[-1] in SUSPICIOUS_TLDS:
            severity = "medium" if severity == "low" else severity
            reasons.append("URL uses a commonly abused top-level domain")
        if safe_ext(parsed.path or "") in EXECUTABLE_URL_EXTENSIONS:
            severity = "high"
            reasons.append("URL path points to an executable or script-like file")
        found.append({"url": url, "host": host, "root_domain": root_domain(host), "scheme": parsed.scheme, "path": parsed.path, "severity": severity, "reason": "; ".join(reasons) or "URL observed for analyst review"})
    return found

def extract_body_and_attachments(message) -> tuple[str, List[dict]]:
    body_parts: List[str] = []
    attachments: List[dict] = []
    if message.is_multipart():
        parts = message.walk()
    else:
        parts = [message]
    for part in parts:
        content_disposition = str(part.get_content_disposition() or "")
        filename = part.get_filename()
        content_type = part.get_content_type()
        try:
            payload = part.get_payload(decode=True) or b""
        except Exception:
            payload = b""
        if filename or content_disposition == "attachment":
            name = filename or "unnamed"
            ext = safe_ext(name)
            all_suffixes = suffixes(name)
            severity = "high" if ext in SUSPICIOUS_ATTACHMENT_EXTENSIONS else "medium" if ext in ARCHIVE_EXTENSIONS else "low"
            reason = "Attachment observed"
            if ext in SUSPICIOUS_ATTACHMENT_EXTENSIONS:
                reason = "Attachment extension is commonly abused in phishing or malware delivery"
            elif ext in ARCHIVE_EXTENSIONS:
                reason = "Archive attachment may hide executable or scripted content"
            double_extension = len(all_suffixes) > 1 and ext in SUSPICIOUS_ATTACHMENT_EXTENSIONS
            if double_extension:
                severity = "high"
                reason = "Attachment uses a double extension that can disguise an executable or script"
            attachments.append({"filename": name, "content_type": content_type, "size_bytes": len(payload), "sha256": hashlib.sha256(payload).hexdigest() if payload else None, "extension": ext, "suffixes": all_suffixes, "double_extension": double_extension, "severity": severity, "reason": reason})
            continue
        if content_type in {"text/plain", "text/html"}:
            try:
                text = part.get_content()
                body_parts.append(str(text))
            except Exception:
                try:
                    body_parts.append(payload.decode("utf-8", errors="replace"))
                except Exception:
                    pass
    return "\n".join(body_parts), attachments

def auth_result_status(headers: Dict[str, str], token: str) -> str:
    haystack = "\n".join(str(value) for key, value in headers.items() if key.lower() in AUTH_HEADERS).lower()
    if not haystack:
        return "not_found"
    if f"{token}=pass" in haystack or f"{token} pass" in haystack:
        return "pass"
    if f"{token}=fail" in haystack or f"{token} fail" in haystack:
        return "fail"
    if f"{token}=softfail" in haystack or f"{token} softfail" in haystack:
        return "softfail"
    return "present_unknown"

def evidence_summary(evidence: dict) -> str:
    if not evidence:
        return "No compact evidence was available."
    for key in ["subject", "url", "href", "filename", "from", "reply_to", "return_path", "sender", "status"]:
        value = evidence.get(key)
        if value:
            return f"{key.replace('_', ' ').title()}: {str(value)[:260]}"
    return "; ".join(f"{key.replace('_', ' ').title()}: {str(value)[:120]}" for key, value in list(evidence.items())[:4])

def phishing_intent(title: str, reason: str) -> str:
    return PHISHING_CONTEXTS.get(title, reason or "the email contains behaviour that should be validated before the user clicks, replies, or opens files.")

def finding(title: str, severity: str, reason: str, evidence: dict, action: str) -> dict:
    checked = "Sentinel parsed the email headers, authentication results, body content, links, and attachments without executing active content."
    intent = phishing_intent(title, reason)
    compact = evidence_summary(evidence)
    return {
        "finding_id": "PHISH-" + hashlib.sha1(f"{title}{reason}{evidence}".encode("utf-8", errors="ignore")).hexdigest()[:12].upper(),
        "title": title,
        "severity": severity,
        "reason": reason,
        "evidence": evidence,
        "plain_english": f"{checked} It found: {title}. In plain English, {intent}",
        "what_was_checked": checked,
        "possible_intent": intent,
        "evidence_summary": compact,
        "analyst_next_step": action,
        "recommended_action": action,
    }

def analyse_message(message, source_name: str = "email.eml") -> dict:
    headers = {str(k).lower(): str(v) for k, v in message.items()}
    subject = str(message.get("subject", ""))
    from_header = str(message.get("from", ""))
    reply_to = str(message.get("reply-to", ""))
    return_path = str(message.get("return-path", ""))
    sender = str(message.get("sender", ""))
    body, attachments = extract_body_and_attachments(message)
    urls = extract_urls("\n".join([subject, body]))
    link_mismatches = extract_html_link_mismatches(body)
    html_indicators = html_form_indicators(body)
    findings: List[dict] = []

    from_domain = domain_from_email(from_header)
    reply_domain = domain_from_email(reply_to)
    return_domain = domain_from_email(return_path)
    sender_domain = domain_from_email(sender)
    if reply_domain and from_domain and reply_domain != from_domain:
        findings.append(finding("Reply-To domain differs from From domain", "medium", "Replies would go to a different domain than the visible sender.", {"from": from_header, "reply_to": reply_to}, "Verify the sender through a trusted channel before replying."))
    if return_domain and from_domain and return_domain != from_domain:
        findings.append(finding("Return-Path domain differs from From domain", "medium", "Bounce path differs from the visible sender domain.", {"from": from_header, "return_path": return_path}, "Review authentication results and sender legitimacy."))
    if sender_domain and from_domain and sender_domain != from_domain:
        findings.append(finding("Sender domain differs from From domain", "medium", "Sender header differs from the visible From domain.", {"from": from_header, "sender": sender}, "Confirm whether this is expected for the sending platform."))

    for token in ["spf", "dkim", "dmarc"]:
        status = auth_result_status(headers, token)
        if status in {"fail", "softfail"}:
            findings.append(finding(f"{token.upper()} authentication issue", "high" if token == "dmarc" else "medium", f"{token.upper()} returned {status}.", {"status": status}, "Treat the message as suspicious unless independently verified."))
        elif status == "not_found":
            findings.append(finding(f"{token.upper()} result not visible", "low", f"No {token.upper()} result was found in copied headers.", {"status": status}, "Analyse the original .eml with full headers where possible."))

    pressure_words = ["urgent", "immediately", "verify", "password", "invoice", "payment", "suspended", "locked", "mfa", "unusual sign-in"]
    if any(word in f"{subject} {body}".lower() for word in pressure_words):
        findings.append(finding("Social engineering pressure language", "medium", "Message contains urgency, credential, payment or account-pressure wording.", {"subject": subject}, "Pause and verify the request through a known-good channel."))

    sender_root = root_domain(from_domain)
    body_text = strip_html(body)
    credential_pressure = any(word in f"{subject} {body_text}".lower() for word in ["password", "mfa", "sign-in", "login", "verify", "account", "suspended", "locked"])
    for url in urls:
        if url.get("severity") in {"medium", "high"}:
            findings.append(finding("Suspicious URL pattern", url["severity"], url.get("reason", "URL requires review"), url, "Do not click until the destination has been validated."))
        if sender_root and url.get("root_domain") and url["root_domain"] != sender_root and credential_pressure:
            findings.append(finding("External link does not match sender domain", "medium", "Credential or account-pressure language points to a link outside the sender domain.", {"from_domain": from_domain, "sender_root": sender_root, "url": url["url"], "url_root": url["root_domain"]}, "Verify the URL through a known-good portal instead of using the email link."))
    for mismatch in link_mismatches:
        findings.append(finding("Visible link text does not match destination", "high", "The displayed link text and actual href point to different domains.", mismatch, "Do not click the link. Inspect the destination in a safe analysis workflow."))
    if html_indicators["has_form"] or html_indicators["has_password_input"]:
        findings.append(finding("HTML credential collection form", "high", "The email body contains a form or password field.", html_indicators, "Block or quarantine the message; users should not submit credentials inside email content."))
    if html_indicators["hidden_content"]:
        findings.append(finding("Hidden or deceptive HTML content", "medium", "The email body contains hidden or visually suppressed HTML content.", html_indicators, "Render and inspect the message safely before release."))
    for attachment in attachments:
        if attachment.get("severity") in {"medium", "high"}:
            findings.append(finding("Risky attachment", attachment["severity"], attachment.get("reason", "Attachment requires review"), attachment, "Do not open the attachment. Analyse the hash/content in a safe environment."))
        if attachment.get("double_extension"):
            findings.append(finding("Double-extension attachment", "high", "Attachment name uses multiple extensions and ends in a risky executable/script type.", attachment, "Quarantine the attachment and inspect it in a malware-safe workflow."))

    severity_order = {"low": 1, "medium": 2, "high": 3, "critical": 4}
    highest = "low" if findings else "informational"
    for item in findings:
        if severity_order.get(item["severity"], 0) > severity_order.get(highest, 0):
            highest = item["severity"]
    score = max(0, 100 - sum({"low": 5, "medium": 15, "high": 30, "critical": 45}.get(item["severity"], 5) for item in findings))
    verdict = "No obvious phishing indicators found"
    if highest == "high":
        verdict = "High-risk phishing indicators found"
    elif highest == "medium":
        verdict = "Suspicious phishing indicators require review"
    elif findings:
        verdict = "Low-risk indicators found"
    return {
        "status": "complete",
        "summary": {"verdict": verdict, "severity": highest, "risk_score": score, "finding_count": len(findings), "url_count": len(urls), "attachment_count": len(attachments)},
        "risk_score": score,
        "severity": highest,
        "headers": {"subject": subject, "from": from_header, "reply_to": reply_to, "return_path": return_path, "sender": sender, "date": str(message.get("date", "")), "message_id": str(message.get("message-id", ""))},
        "authentication": {"spf": auth_result_status(headers, "spf"), "dkim": auth_result_status(headers, "dkim"), "dmarc": auth_result_status(headers, "dmarc")},
        "urls": urls,
        "attachments": attachments,
        "html_indicators": html_indicators,
        "link_mismatches": link_mismatches,
        "findings": findings,
        "recommended_actions": ["Do not click links or open attachments until reviewed.", "Verify the sender using a trusted contact route.", "Check SPF/DKIM/DMARC from the original full headers.", "Submit suspicious URLs or attachment hashes to your defensive intelligence workflow."],
        "metadata": {"source_name": source_name, "analysed_at": datetime.utcnow().isoformat() + "Z"},
    }

@router.post("/analyse")
def analyse_email(req: EmailAnalysisRequest):
    message = Parser(policy=policy.default).parsestr(req.raw_email)
    return analyse_message(message, req.source_name or "pasted-email.eml")

@router.post("/analyse-upload")
async def analyse_upload(file: UploadFile = File(...)):
    content = await file.read()
    message = BytesParser(policy=policy.default).parsebytes(content)
    result = analyse_message(message, file.filename or "uploaded-email.eml")
    result["metadata"]["sha256"] = hashlib.sha256(content).hexdigest()
    result["metadata"]["size_bytes"] = len(content)
    return result

@router.post("/domain/connect")
def connect_domain(req: DomainConnectRequest):
    domain = normalise_domain(req.domain)
    CONNECTED_DOMAINS[domain] = {"domain": domain, "provider": req.provider, "connected_at": datetime.utcnow().isoformat() + "Z", "status": "connected", "enforcement": "internal-only recipients; no credential harvesting"}
    return CONNECTED_DOMAINS[domain]

@router.get("/domain/list")
def list_domains():
    return {"count": len(CONNECTED_DOMAINS), "domains": list(CONNECTED_DOMAINS.values())}

@router.get("/templates")
def list_templates():
    return {"count": len(TEMPLATES), "templates": list(TEMPLATES.values())}

@router.post("/templates")
def create_template(req: TemplateRequest):
    TEMPLATES[req.name] = req.model_dump()
    return {"status": "created", "template": TEMPLATES[req.name]}

@router.post("/campaign")
def create_campaign(req: CampaignRequest):
    domain = normalise_domain(req.domain)
    if domain not in CONNECTED_DOMAINS:
        raise HTTPException(status_code=403, detail="Domain must be connected before creating campaigns")
    enforce_internal(domain, [str(r) for r in req.recipients])
    campaign_id = str(uuid4())
    template = TEMPLATES.get(req.template_name, {"name": req.template_name, "subject": req.subject, "pretext": "Custom awareness campaign", "landing_message": "This was an authorised security awareness simulation."})
    CAMPAIGNS[campaign_id] = {"campaign_id": campaign_id, "name": req.name, "domain": domain, "template": template, "subject": req.subject or template.get("subject"), "recipients": [str(r) for r in req.recipients], "scheduled_at": req.scheduled_at, "created_at": datetime.utcnow().isoformat() + "Z", "status": "simulated_send_logged", "safety_controls": ["domain must be connected", "external recipients blocked", "no credential collection", "events are audit logged"]}
    for recipient in req.recipients:
        log_event(campaign_id, str(recipient), "sent")
    return CAMPAIGNS[campaign_id]

@router.get("/campaigns")
def list_campaigns():
    return {"count": len(CAMPAIGNS), "campaigns": list(CAMPAIGNS.values())}

@router.post("/event")
def record_event(req: EventRequest):
    if req.campaign_id not in CAMPAIGNS:
        raise HTTPException(status_code=404, detail="Campaign not found")
    if req.action not in ["opened", "clicked", "reported", "training_completed"]:
        raise HTTPException(status_code=400, detail="Invalid event action")
    campaign = CAMPAIGNS[req.campaign_id]
    enforce_internal(campaign["domain"], [str(req.recipient)])
    log_event(req.campaign_id, str(req.recipient), req.action)
    return {"status": "event recorded"}

@router.get("/campaign/{campaign_id}/results")
def campaign_results(campaign_id: str):
    if campaign_id not in CAMPAIGNS:
        raise HTTPException(status_code=404, detail="Campaign not found")
    campaign_events = [e for e in EVENTS if e["campaign_id"] == campaign_id]
    recipients = CAMPAIGNS[campaign_id]["recipients"]
    metrics = {"sent": len([e for e in campaign_events if e["action"] == "sent"]), "opened": len([e for e in campaign_events if e["action"] == "opened"]), "clicked": len([e for e in campaign_events if e["action"] == "clicked"]), "reported": len([e for e in campaign_events if e["action"] == "reported"]), "training_completed": len([e for e in campaign_events if e["action"] == "training_completed"]), "recipient_count": len(recipients)}
    metrics["click_rate"] = round((metrics["clicked"] / metrics["recipient_count"]) * 100, 2) if metrics["recipient_count"] else 0
    metrics["report_rate"] = round((metrics["reported"] / metrics["recipient_count"]) * 100, 2) if metrics["recipient_count"] else 0
    return {"campaign": CAMPAIGNS[campaign_id], "metrics": metrics, "events": campaign_events}

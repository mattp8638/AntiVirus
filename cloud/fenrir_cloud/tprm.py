"""Automated third-party risk management.

Each customer (and the MSP itself) keeps a register of the suppliers it relies on. For each one:

* Inherent risk comes from how critical the service is and what data the supplier can reach.
* A security questionnaire goes to the supplier as a single-use link (no account needed); answers are scored and weak
  answers become findings.
* An external posture scan of the supplier's domain checks email authentication (SPF, DMARC), HTTPS with HSTS, the
  TLS certificate, security.txt and publicly reported breaches (Have I Been Pwned's breach list).
* Residual risk = inherent risk reduced by the questionnaire and posture scores, giving a tier.
* Reviews fall due by criticality (critical every 6 months ... low every 3 years). When one is due Fenrir sends the
  questionnaire again and opens a ticket; expiring certificates and contracts open tickets too.
"""

from __future__ import annotations

import hashlib
import logging
import secrets
import socket
import ssl
from datetime import datetime, timedelta

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import audit, mailer, services
from .config import get_settings
from .models import Tenant, Vendor, VendorAssessment, utcnow

log = logging.getLogger("fenrir.tprm")

CRITICALITY = ("low", "medium", "high", "critical")
DATA_ACCESS = ("none", "internal", "personal", "special")
REVIEW_DAYS = {"critical": 182, "high": 365, "medium": 730, "low": 1095}
SCAN_EVERY = timedelta(days=7)
ASSESSMENT_DAYS = 21
DOCUMENT_WARNING = timedelta(days=30)
ANSWERS = {"yes": 1.0, "partial": 0.5, "no": 0.0}

QUESTIONS = [
    {"id": "gov-policy", "domain": "Governance", "weight": 2,
     "text": "Do you have a documented information security policy, approved by management and reviewed at least annually?"},
    {"id": "gov-cert", "domain": "Governance", "weight": 3,
     "text": "Do you hold a current independent certification or attestation (ISO/IEC 27001, SOC 2 Type II or Cyber Essentials Plus) covering the service you provide us?"},
    {"id": "acc-mfa", "domain": "Access control", "weight": 3,
     "text": "Is multi-factor authentication enforced for all staff access to systems holding our data, and for all administrative access?"},
    {"id": "acc-review", "domain": "Access control", "weight": 2,
     "text": "Are access rights reviewed at least quarterly and removed promptly when staff leave?"},
    {"id": "data-encrypt", "domain": "Data protection", "weight": 3,
     "text": "Is our data encrypted in transit (TLS 1.2 or later) and at rest?"},
    {"id": "data-location", "domain": "Data protection", "weight": 2,
     "text": "Is our data stored and processed only in the UK or EEA, or under an approved international transfer mechanism?"},
    {"id": "data-deletion", "domain": "Data protection", "weight": 1,
     "text": "Will you return or securely delete our data when the contract ends, and confirm it in writing?"},
    {"id": "ops-patch", "domain": "Operations", "weight": 2,
     "text": "Are critical and high-severity security patches applied within 14 days?"},
    {"id": "ops-pentest", "domain": "Operations", "weight": 2,
     "text": "Are your systems penetration tested by an independent party at least annually, with findings tracked to closure?"},
    {"id": "ops-monitoring", "domain": "Operations", "weight": 2,
     "text": "Do you run endpoint detection and response with security monitoring 24 hours a day?"},
    {"id": "res-backup", "domain": "Resilience", "weight": 2,
     "text": "Are backups taken at least daily, protected from tampering (offline or immutable) and restore-tested at least annually?"},
    {"id": "res-bcp", "domain": "Resilience", "weight": 2,
     "text": "Do you have a business continuity and disaster recovery plan that is tested at least annually?"},
    {"id": "ir-notify", "domain": "Incident response", "weight": 3,
     "text": "Do you have an incident response plan, and will you notify us within 24 hours of an incident affecting our data or service?"},
    {"id": "sc-subprocessors", "domain": "Supply chain", "weight": 2,
     "text": "Do you keep a list of the subprocessors that handle our data, and hold them to equivalent security terms?"},
    {"id": "people-training", "domain": "People", "weight": 1,
     "text": "Do all staff complete security awareness training at least annually, and are staff screened before employment?"},
]


# --------------------------------------------------------------------------- scoring


def inherent_risk(vendor: Vendor) -> int:
    criticality = {"low": 10, "medium": 25, "high": 40, "critical": 55}[vendor.criticality]
    data = {"none": 0, "internal": 15, "personal": 30, "special": 45}[vendor.data_access]
    return min(100, criticality + data)


def tier(score: int) -> str:
    return "critical" if score >= 65 else "high" if score >= 45 else "medium" if score >= 25 else "low"


def rescore(vendor: Vendor) -> None:
    """Residual risk: inherent risk reduced by what the questionnaire and the posture scan show (never below 20% of it)."""
    inherent = inherent_risk(vendor)
    parts = [(vendor.questionnaire_score, 0.7), (vendor.posture_score, 0.3)]
    known = [(s, w) for s, w in parts if s is not None]
    strength = sum(s * w for s, w in known) / sum(w for _, w in known) / 100 if known else 0.0
    vendor.risk_score = round(inherent * (1 - 0.8 * strength))
    vendor.risk_tier = tier(vendor.risk_score)


def score_answers(answers: dict) -> tuple[int | None, list[dict]]:
    total = weight = 0.0
    findings = []
    for q in QUESTIONS:
        answer = str((answers.get(q["id"]) or {}).get("answer") or "")
        if answer not in ANSWERS:
            continue  # "na" or unanswered
        total += q["weight"] * ANSWERS[answer]
        weight += q["weight"]
        if answer != "yes" and q["weight"] >= 2:
            findings.append({"question": q["id"], "domain": q["domain"], "text": q["text"], "answer": answer,
                             "comment": str((answers.get(q["id"]) or {}).get("comment") or "")[:1000],
                             "severity": "high" if answer == "no" and q["weight"] == 3 else "medium"})
    return (round(100 * total / weight) if weight else None), findings


def review_interval(vendor: Vendor) -> timedelta:
    return timedelta(days=REVIEW_DAYS[vendor.criticality])


def schedule_review(vendor: Vendor) -> None:
    base = vendor.last_assessed_at or vendor.created_at or utcnow()
    vendor.next_review_at = base + (review_interval(vendor) if vendor.last_assessed_at else timedelta(days=30))


# --------------------------------------------------------------------------- questionnaires


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def assessment_link(token: str) -> str:
    return f"{get_settings().public_base_url.rstrip('/')}/vendor-assessment/{token}"


def send_assessment(db: Session, vendor: Vendor, actor: str, recipient: str = "") -> tuple[VendorAssessment, str]:
    for open_one in db.execute(select(VendorAssessment).where(VendorAssessment.vendor_id == vendor.id,
                                                              VendorAssessment.status == "sent")).scalars():
        open_one.status = "cancelled"
    token = secrets.token_urlsafe(32)
    recipient = recipient or vendor.contact_email
    row = VendorAssessment(tenant_id=vendor.tenant_id, vendor_id=vendor.id, token_hash=_hash(token), recipient=recipient,
                           sent_by=actor, due_at=utcnow() + timedelta(days=ASSESSMENT_DAYS))
    db.add(row)
    db.flush()
    link = assessment_link(token)
    customer = db.get(Tenant, vendor.tenant_id)
    if recipient:
        try:
            mailer.send(recipient, f"Security questionnaire from {customer.name if customer else 'your customer'}",
                        f"Hello {vendor.contact_name or vendor.name},\n\n{customer.name if customer else 'Your customer'} reviews the security of "
                        f"the suppliers it relies on. Please answer {len(QUESTIONS)} short questions about {vendor.services or 'your service'} "
                        f"by {row.due_at.strftime('%d %B %Y')}:\n\n{link}\n\nThe link works once and needs no account.\n")
        except Exception as exc:  # noqa: BLE001 - the link is still returned to the console
            log.warning("could not email the questionnaire to %s: %s", recipient, exc)
    audit.record(db, actor, "tprm.assessment.sent", vendor.name, vendor.tenant_id, vendor=vendor.id, recipient=recipient)
    return row, link


def assessment_for_token(db: Session, token: str) -> VendorAssessment | None:
    row = db.execute(select(VendorAssessment).where(VendorAssessment.token_hash == _hash(token))).scalar_one_or_none()
    if row is not None and row.status == "sent" and row.due_at and utcnow() > row.due_at + timedelta(days=14):
        row.status = "expired"
    return row


def submit(db: Session, assessment: VendorAssessment, answers: dict) -> None:
    clean = {q["id"]: {"answer": str((answers.get(q["id"]) or {}).get("answer") or ""),
                       "comment": str((answers.get(q["id"]) or {}).get("comment") or "")[:1000]} for q in QUESTIONS}
    if any(v["answer"] not in (*ANSWERS, "na") for v in clean.values()):
        raise ValueError("Answer every question with yes, partial, no or not applicable")
    score, findings = score_answers(clean)
    now = utcnow()
    assessment.answers, assessment.score, assessment.findings = clean, score, findings
    assessment.status, assessment.completed_at = "completed", now
    vendor = db.get(Vendor, assessment.vendor_id)
    if vendor is not None:
        vendor.questionnaire_score, vendor.last_assessed_at = score, now
        rescore(vendor)
        schedule_review(vendor)
        vendor.review_ticket_id = None
        audit.record(db, f"vendor:{vendor.name}", "tprm.assessment.completed", vendor.name, vendor.tenant_id,
                     score=score, findings=len(findings), tier=vendor.risk_tier)


# --------------------------------------------------------------------------- external posture


def http_client() -> httpx.Client:
    return httpx.Client(timeout=10, follow_redirects=True, headers={"User-Agent": "Fenrir-TPRM/1.0"})


def tls_certificate(domain: str) -> dict:
    """The certificate the domain's HTTPS endpoint presents, verified against the system trust store."""
    context = ssl.create_default_context()
    try:
        with socket.create_connection((domain, 443), timeout=10) as raw, context.wrap_socket(raw, server_hostname=domain) as tls:
            cert = tls.getpeercert()
        expires = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
        return {"valid": True, "expiresAt": expires.isoformat() + "Z", "daysLeft": (expires - utcnow()).days}
    except ssl.SSLCertVerificationError as exc:
        return {"valid": False, "error": exc.verify_message or str(exc)}
    except (OSError, ValueError) as exc:
        return {"valid": False, "error": str(exc)[:200]}


def _txt(client: httpx.Client, name: str) -> list[str]:
    response = client.get("https://cloudflare-dns.com/dns-query", params={"name": name, "type": "TXT"},
                          headers={"Accept": "application/dns-json"})
    response.raise_for_status()
    return [a.get("data", "").replace('" "', "").strip('"') for a in response.json().get("Answer") or [] if a.get("type") == 16]


def resolves_publicly(domain: str) -> bool:
    """The scan runs from the Fenrir server, so it only looks at internet names that resolve to public addresses
    (never internal hosts, IP literals or cloud metadata)."""
    import ipaddress
    import re

    if not re.fullmatch(r"(?=.{4,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}", domain):
        return False
    try:
        addresses = {info[4][0] for info in socket.getaddrinfo(domain, 443, proto=socket.IPPROTO_TCP)}
    except OSError:
        return False
    return bool(addresses) and all(ipaddress.ip_address(a.split("%")[0]).is_global for a in addresses)


def scan(db: Session, vendor: Vendor) -> dict:
    """Check the vendor's domain from the outside and score it 0-100."""
    domain = vendor.domain.strip().lower()
    if not domain:
        raise ValueError("Add the vendor's domain to scan it")
    if not resolves_publicly(domain):
        raise ValueError(f"{domain} is not a public internet domain that resolves to public addresses")
    findings, checks, score = [], {}, 100
    with http_client() as client:
        try:
            spf = [t for t in _txt(client, domain) if t.lower().startswith("v=spf1")]
            dmarc = [t for t in _txt(client, f"_dmarc.{domain}") if t.lower().startswith("v=dmarc1")]
            policy = next((p.split("=", 1)[1].strip().lower() for p in (dmarc[0].split(";") if dmarc else []) if p.strip().lower().startswith("p=")), "")
            checks["spf"], checks["dmarc"] = bool(spf), policy or ("missing" if not dmarc else "none")
            if not spf:
                score -= 10
                findings.append("No SPF record: anyone can send email as this domain")
            if not dmarc:
                score -= 15
                findings.append("No DMARC record: spoofed email from this domain is not rejected")
            elif policy == "none":
                score -= 8
                findings.append("DMARC is monitor-only (p=none)")
        except (httpx.HTTPError, ValueError) as exc:
            checks["dns"] = f"lookup failed: {exc}"[:200]
        try:
            response = client.get(f"https://{domain}")
            checks["https"] = response.status_code < 500
            checks["hsts"] = "strict-transport-security" in response.headers
            if not checks["hsts"]:
                score -= 5
                findings.append("The website does not send HSTS")
        except httpx.HTTPError as exc:
            checks["https"] = False
            score -= 10
            findings.append(f"The website is not reachable over HTTPS ({type(exc).__name__})")
        try:
            response = client.get(f"https://{domain}/.well-known/security.txt")
            checks["securityTxt"] = response.status_code == 200 and "contact:" in response.text.lower()
        except httpx.HTTPError:
            checks["securityTxt"] = False
        if not checks.get("securityTxt"):
            score -= 2
            findings.append("No security.txt: there is no published way to report a vulnerability")
        try:
            response = client.get("https://haveibeenpwned.com/api/v3/breaches", params={"domain": domain})
            breaches = response.json() if response.status_code == 200 else []
            cutoff = (utcnow() - timedelta(days=3 * 365)).date().isoformat()
            recent = [b for b in breaches if str(b.get("BreachDate") or "") >= cutoff]
            checks["breaches"] = [{"name": b.get("Name"), "date": b.get("BreachDate"), "accounts": b.get("PwnCount"),
                                   "data": (b.get("DataClasses") or [])[:6]} for b in breaches[:10]]
            if recent:
                score -= min(45, 15 * len(recent))
                findings.append(f"{len(recent)} publicly reported breach(es) in the last 3 years: " + ", ".join(b.get("Name", "") for b in recent[:3]))
        except (httpx.HTTPError, ValueError):
            checks["breaches"] = None
    cert = tls_certificate(domain)
    checks["certificate"] = cert
    if not cert.get("valid"):
        score -= 25
        findings.append(f"The TLS certificate is not valid: {cert.get('error', '')}")
    elif cert.get("daysLeft", 999) < 14:
        score -= 10
        findings.append(f"The TLS certificate expires in {cert['daysLeft']} days")
    vendor.posture = {"checks": checks, "findings": findings, "scannedAt": utcnow().isoformat() + "Z"}
    vendor.posture_score = max(0, score)
    vendor.last_scanned_at = utcnow()
    rescore(vendor)
    return vendor.posture


# --------------------------------------------------------------------------- schedule and signal


def _documents_due(vendor: Vendor, now: datetime) -> list[dict]:
    due = []
    for doc in vendor.documents or []:
        try:
            expires = datetime.fromisoformat(str(doc.get("expiresAt") or "").rstrip("Z"))
        except ValueError:
            continue
        if expires - now <= DOCUMENT_WARNING and not doc.get("alertedAt"):
            due.append(doc)
    return due


def tick(db: Session) -> None:
    """Daily housekeeping: rescans, expired questionnaires, reviews falling due and expiring documents."""
    now = utcnow()
    for vendor in db.execute(select(Vendor).where(Vendor.status == "active")).scalars().all():
        try:
            if vendor.domain and (vendor.last_scanned_at is None or now - vendor.last_scanned_at > SCAN_EVERY):
                try:
                    scan(db, vendor)
                except ValueError as exc:
                    vendor.last_scanned_at, vendor.posture = now, {"error": str(exc), "scannedAt": now.isoformat() + "Z"}
            if vendor.next_review_at is None:
                schedule_review(vendor)
            if vendor.next_review_at <= now and not vendor.review_ticket_id:
                ticket = services.open_ticket(db, vendor.tenant_id, f"Supplier review due: {vendor.name}",
                                              f"{vendor.name} ({vendor.criticality} criticality, {vendor.data_access} data) is due for its "
                                              f"security review. Residual risk: {vendor.risk_tier}.", priority="P3", source="compliance")
                vendor.review_ticket_id = ticket.id
                if vendor.contact_email and ((db.get(Tenant, vendor.tenant_id).settings or {}).get("tprm") or {}).get("autoReassess", True):
                    send_assessment(db, vendor, "system:tprm")
            due = _documents_due(vendor, now)
            if due:
                services.open_ticket(db, vendor.tenant_id, f"Supplier documents expiring: {vendor.name}",
                                     "\n".join(f"{d.get('type', 'Document')}: {d.get('name', '')} expires {d.get('expiresAt')}" for d in due),
                                     priority="P3", source="compliance")
                stamp = now.isoformat() + "Z"
                vendor.documents = [{**d, "alertedAt": stamp} if d in due else d for d in vendor.documents]
            db.commit()
        except Exception as exc:  # noqa: BLE001 - keep going for the other vendors
            db.rollback()
            log.warning("supplier housekeeping failed for %s: %s", vendor.name, exc)
    for row in db.execute(select(VendorAssessment).where(VendorAssessment.status == "sent")).scalars():
        if row.due_at and now > row.due_at + timedelta(days=14):
            row.status = "expired"
    db.commit()


def signal(db: Session, tenant: Tenant) -> dict:
    """Third-party risk is under control when every high and critical supplier is assessed on schedule, none is
    critical residual risk, and no supplier document has expired."""
    vendors = db.execute(select(Vendor).where(Vendor.tenant_id == tenant.id, Vendor.status == "active")).scalars().all()
    if not vendors:
        return {"passed": None, "evidence": ["No suppliers are registered"]}
    now, problems = utcnow(), []
    for v in vendors:
        if v.criticality in ("high", "critical") and (not v.last_assessed_at or now - v.last_assessed_at > review_interval(v)):
            problems.append(f"{v.name}: {v.criticality} supplier not assessed on schedule")
        if v.risk_tier == "critical":
            problems.append(f"{v.name}: critical residual risk")
        for doc in v.documents or []:
            try:
                if datetime.fromisoformat(str(doc.get("expiresAt") or "").rstrip("Z")) < now:
                    problems.append(f"{v.name}: {doc.get('type', 'document')} expired")
            except ValueError:
                pass
    assessed = sum(1 for v in vendors if v.last_assessed_at)
    return {"passed": not problems, "evidence": [f"{len(vendors)} suppliers registered, {assessed} assessed"] + problems[:10]}


def view(vendor: Vendor) -> dict:
    return {"id": vendor.id, "tenantId": vendor.tenant_id, "name": vendor.name, "domain": vendor.domain, "services": vendor.services,
            "criticality": vendor.criticality, "dataAccess": vendor.data_access, "contactName": vendor.contact_name,
            "contactEmail": vendor.contact_email, "owner": vendor.owner, "status": vendor.status, "documents": vendor.documents or [],
            "posture": vendor.posture or {}, "postureScore": vendor.posture_score, "questionnaireScore": vendor.questionnaire_score,
            "inherentRisk": inherent_risk(vendor), "riskScore": vendor.risk_score, "riskTier": vendor.risk_tier, "notes": vendor.notes,
            "lastScannedAt": vendor.last_scanned_at.isoformat() + "Z" if vendor.last_scanned_at else None,
            "lastAssessedAt": vendor.last_assessed_at.isoformat() + "Z" if vendor.last_assessed_at else None,
            "nextReviewAt": vendor.next_review_at.isoformat() + "Z" if vendor.next_review_at else None,
            "reviewDue": bool(vendor.next_review_at and vendor.next_review_at <= utcnow())}

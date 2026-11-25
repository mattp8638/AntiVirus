"""Sandbox analysis of suspicious files, with approval and confidential-data controls (AV-15).

Fenrir does not run a sandbox. It sends samples to one the MSP licenses: a CAPE-compatible REST API (``/apiv2``),
self-hosted or hosted. **Without a configured provider nothing is submitted, and the page says so.** Provider access
is a stated dependency, not something Fenrir works around.

**Flow:** request → policy check → approval → sample collected → submitted → verdict → linked to the alert or incident.

1. **Request.** A file is requested from an alert or a quarantine record, by its SHA-256.
2. **Policy check** (customer setting ``sandbox``):

   * ``enabled`` must be on for the customer.
   * ``mode`` is ``hash`` (only look the hash up; never upload the file) or ``file`` (upload when the hash is unknown).
   * Paths matching ``neverSubmit`` (for example ``/HR/`` or ``Payroll``) are refused.
   * Files whose path the PII discovery scan reported are refused.
   * Documents (office files, PDF, email and archives) may hold customer data. They always need approval by a person
     other than the requester.
   * Executables and scripts can be approved automatically when ``autoApproveExecutables`` is on.

3. **Sample.** The agent uploads the file from quarantine only (``sample.collect``), after checking it against its
   recorded SHA-256. It is stored like other artifacts and audited.
4. **Submit and verdict.** The scheduler submits approved samples and polls the provider asynchronously. The verdict
   is one of ``malicious``, ``suspicious``, ``clean`` or ``unknown``, with score, signatures and network indicators.
   It is written to the incident timeline and the alert. A malicious verdict raises the alert's severity to high, or
   opens an alert when there was none.
"""
from __future__ import annotations

import re
from datetime import timedelta
from pathlib import PurePosixPath, PureWindowsPath

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import audit, crypto, netguard, services
from .models import (Alert, Device, DeviceArtifact, Incident, SandboxProvider, SandboxSubmission, Tenant, utcnow)

DOCUMENTS = {".doc", ".docx", ".docm", ".xls", ".xlsx", ".xlsm", ".ppt", ".pptx", ".pptm", ".pdf", ".rtf", ".odt", ".ods", ".csv",
             ".txt", ".eml", ".msg", ".zip", ".7z", ".rar"}
EXECUTABLES = {".exe", ".dll", ".scr", ".msi", ".ps1", ".vbs", ".js", ".jse", ".bat", ".cmd", ".hta", ".lnk", ".sh", ".elf", ".bin",
               ".dylib", ".app", ".jar", ".py", ""}
COLLECT_TIMEOUT = timedelta(hours=2)
ANALYSIS_TIMEOUT = timedelta(hours=6)
SHA = re.compile(r"^[0-9a-f]{64}$")


class SandboxError(Exception):
    pass


def settings(db: Session, tenant_id: str) -> dict:
    tenant = db.get(Tenant, tenant_id)
    return ((tenant.settings or {}) if tenant else {}).get("sandbox") or {}


def provider_for(db: Session, tenant_id: str) -> SandboxProvider | None:
    """The customer's own provider, else the MSP's (a parent tenant's)."""
    seen, tid = set(), tenant_id
    while tid and tid not in seen:
        seen.add(tid)
        p = db.scalars(select(SandboxProvider).where(SandboxProvider.tenant_id == tid)).first()
        if p:
            return p
        t = db.get(Tenant, tid)
        tid = t.parent_id if t else None
    return None


def _ext(name: str) -> str:
    base = PureWindowsPath(name).name if "\\" in name else PurePosixPath(name).name
    return ("." + base.rsplit(".", 1)[1].lower()) if "." in base else ""


def _pii_paths(db: Session, device_id: str | None) -> set[str]:
    """Files the device's PII discovery scans reported as holding personal data."""
    if not device_id:
        return set()
    from .models import DataDiscoveryScan

    scans = db.scalars(select(DataDiscoveryScan).where(DataDiscoveryScan.device_id == device_id, DataDiscoveryScan.status == "completed")).all()
    return {str(f.get("path", "")).lower() for s in scans for f in (s.files or []) if isinstance(f, dict)}


def request(db: Session, tenant_id: str, sha256: str, actor: str, *, filename: str = "", path: str = "", device_id: str | None = None,
            quarantine_record: str = "", alert_id: str | None = None, incident_id: str | None = None,
            email_scan_id: str | None = None) -> SandboxSubmission:
    sha256 = sha256.lower()
    if not SHA.match(sha256):
        raise SandboxError("A SHA-256 is needed")
    conf = settings(db, tenant_id)
    sub = SandboxSubmission(tenant_id=tenant_id, device_id=device_id, sha256=sha256, filename=filename[:300] or PurePosixPath(path).name,
                            path=path[:1000], quarantine_record=quarantine_record, alert_id=alert_id, incident_id=incident_id,
                            mode="hash" if conf.get("mode", "file") == "hash" else "file", requested_by=actor, email_scan_id=email_scan_id)
    db.add(sub)
    db.flush()

    def refuse(reason):
        sub.status, sub.reason = "refused", reason
        audit.record(db, actor, "sandbox.refused", sub.id, tenant_id, sha256=sha256, reason=reason)
        return sub

    if not conf.get("enabled"):
        return refuse("Sandbox submission is not turned on for this customer")
    provider = provider_for(db, tenant_id)
    if provider is None:
        return refuse("No sandbox provider is configured: a licensed sandbox (CAPE-compatible API) is required")
    sub.provider_id = provider.id
    lowered = (path or filename).lower()
    for pattern in conf.get("neverSubmit") or []:
        if pattern and pattern.lower() in lowered:
            return refuse(f"The path matches the customer's never-submit rule '{pattern}'")
    if lowered and lowered in _pii_paths(db, device_id):
        return refuse("PII discovery found personal data in this file; it is never sent outside")
    ext = _ext(filename or path)
    if sub.mode == "file" and not quarantine_record and not email_scan_id:
        sub.mode = "hash"  # no quarantined copy to send: look the hash up only
    if ext in DOCUMENTS:
        sub.reason = "Documents may hold customer data: a second person must approve"
    elif conf.get("autoApproveExecutables") and ext in EXECUTABLES:
        sub.status, sub.approved_by, sub.reason = "approved", "policy: executables approved automatically", ""
    else:
        sub.reason = "Waiting for approval"
    audit.record(db, actor, "sandbox.requested", sub.id, tenant_id, sha256=sha256, mode=sub.mode, status=sub.status, filename=sub.filename)
    return sub


def approve(db: Session, sub: SandboxSubmission, actor: str, approve_it: bool, note: str = "") -> SandboxSubmission:
    if sub.status != "awaiting_approval":
        raise SandboxError("This submission is not waiting for approval")
    if _ext(sub.filename or sub.path) in DOCUMENTS and actor.lower() == sub.requested_by.lower():
        raise SandboxError("A document must be approved by someone other than the person who requested it")
    sub.approved_by, sub.updated_at = actor, utcnow()
    sub.status, sub.reason = ("approved", note[:500]) if approve_it else ("rejected", note[:500] or "Rejected")
    audit.record(db, actor, "sandbox.approved" if approve_it else "sandbox.rejected", sub.id, sub.tenant_id, sha256=sub.sha256, note=note[:300])
    return sub


# ---- provider (CAPE-compatible REST API) ---------------------------------------------------------------------------

def _client() -> httpx.Client:
    return httpx.Client(timeout=60, follow_redirects=False)


def _headers(provider: SandboxProvider) -> dict:
    return {"Authorization": "Token " + crypto.decrypt(provider.credentials_envelope, f"sandbox:{provider.id}")}


def _guard(provider: SandboxProvider) -> None:
    host = httpx.URL(provider.base_url).host
    netguard.guard_url_host(host)


def lookup(provider: SandboxProvider, client, sha256: str) -> str | None:
    """A finished task for this hash, if the sandbox analysed it before."""
    r = client.get(f"{provider.base_url}/apiv2/tasks/search/sha256/{sha256}/", headers=_headers(provider))
    r.raise_for_status()
    tasks = [t for t in (r.json().get("data") or []) if isinstance(t, dict) and t.get("status") == "reported"]
    return str(tasks[0]["id"]) if tasks else None


def submit_file(provider: SandboxProvider, client, name: str, data: bytes) -> str:
    r = client.post(f"{provider.base_url}/apiv2/tasks/create/file/", headers=_headers(provider), files={"file": (name, data)})
    r.raise_for_status()
    body = r.json()
    if body.get("error"):
        raise SandboxError(f"The sandbox refused the file: {str(body.get('error_value') or body.get('error'))[:200]}")
    ids = (body.get("data") or {}).get("task_ids") or []
    if not ids:
        raise SandboxError("The sandbox returned no task")
    return str(ids[0])


def fetch_verdict(provider: SandboxProvider, client, task_id: str) -> dict | None:
    r = client.get(f"{provider.base_url}/apiv2/tasks/status/{task_id}/", headers=_headers(provider))
    r.raise_for_status()
    if r.json().get("data") != "reported":
        return None
    r = client.get(f"{provider.base_url}/apiv2/tasks/get/report/{task_id}/", headers=_headers(provider))
    r.raise_for_status()
    report = r.json()
    score = report.get("malscore")
    sigs = [{"name": s.get("name"), "severity": s.get("severity"), "description": (s.get("description") or "")[:300]}
            for s in report.get("signatures") or [] if isinstance(s, dict)][:50]
    network = report.get("network") or {}
    iocs = {"domains": sorted({d.get("domain") for d in network.get("domains") or [] if isinstance(d, dict) and d.get("domain")})[:50],
            "hosts": sorted({h if isinstance(h, str) else h.get("ip") for h in network.get("hosts") or [] if h})[:50]}
    verdict = "unknown" if score is None else "malicious" if score >= 7 else "suspicious" if score >= 4 else "clean"
    return {"verdict": verdict, "score": score, "signatures": sigs, "network": iocs}


# ---- progress ----------------------------------------------------------------------------------------------------------

def _artifact_bytes(db: Session, artifact_id: str) -> bytes:
    from .routers.artifacts import artifact_dir

    art = db.get(DeviceArtifact, artifact_id)
    if art is None:
        raise SandboxError("The uploaded sample is missing")
    return (artifact_dir() / art.storage_name).read_bytes()


def email_attachment(db: Session, scan_id: str, sha256: str) -> bytes:
    """The attachment with this SHA-256 from a message Fenrir's gateway holds in quarantine."""
    import hashlib
    from email import policy
    from email.parser import BytesParser

    from .models import EmailQuarantine

    held = db.scalars(select(EmailQuarantine).where(EmailQuarantine.scan_id == scan_id)).first()
    if held is None:
        raise SandboxError("The gateway no longer holds this message, so its attachment cannot be sent")
    message = BytesParser(policy=policy.default).parsebytes(crypto.decrypt_bytes(held.envelope, f"email-quarantine:{scan_id}"))
    for part in message.walk():
        if part.is_multipart():
            continue
        data = part.get_payload(decode=True) or b""
        if data and hashlib.sha256(data).hexdigest() == sha256:
            return data
    raise SandboxError("No attachment with that SHA-256 in the held message")


def request_email(db: Session, scan, sha256: str, actor: str) -> SandboxSubmission:
    """Submit one attachment of a scanned message. Gateway messages in quarantine can be uploaded; for mailbox messages
    only the hash is looked up (Fenrir does not keep a copy)."""
    att = next((a for a in scan.attachments or [] if str(a.get("sha256", "")).lower() == sha256.lower()), None)
    if att is None:
        raise SandboxError("That message has no attachment with this SHA-256")
    from .models import EmailQuarantine

    held = (scan.source or "graph") == "gateway" and db.scalars(select(EmailQuarantine).where(EmailQuarantine.scan_id == scan.id)).first()
    sub = request(db, scan.tenant_id, sha256, actor, filename=att.get("name") or "", email_scan_id=scan.id if held else None)
    if not held and sub.status != "refused":
        sub.mode, sub.reason = "hash", (sub.reason + "; " if sub.reason else "") + "only the hash is looked up (Fenrir keeps no copy of mailbox messages)"
    return sub


def _record_verdict(db: Session, sub: SandboxSubmission, result: dict) -> None:
    sub.status, sub.verdict, sub.score, sub.report, sub.updated_at = "completed", result["verdict"], result["score"], result, utcnow()
    text = (f"Sandbox verdict for {sub.filename or sub.sha256[:12]}: {result['verdict']}"
            + (f" (score {result['score']})" if result["score"] is not None else "")
            + (f"; signatures: {', '.join(s['name'] for s in result['signatures'][:5] if s.get('name'))}" if result["signatures"] else ""))
    alert = db.get(Alert, sub.alert_id) if sub.alert_id else None
    if alert is not None:
        alert.details = {**(alert.details or {}), "sandbox": {"submissionId": sub.id, "verdict": result["verdict"], "score": result["score"]}}
        if result["verdict"] == "malicious" and alert.severity not in ("high", "critical"):
            alert.severity = "high"
        sub.incident_id = sub.incident_id or alert.incident_id
    elif result["verdict"] == "malicious":
        db.add(Alert(tenant_id=sub.tenant_id, device_id=sub.device_id, rule_id="sandbox.malicious", title=text[:300], severity="high",
                     mitre=[], event_ids=[], details={"category": "malware", "source": "Sandbox", "sha256": sub.sha256, "submissionId": sub.id}))
    incident = db.get(Incident, sub.incident_id) if sub.incident_id else None
    if incident is not None:
        incident.timeline = (incident.timeline or []) + [{"at": utcnow().isoformat(), "kind": "sandbox", "text": text, "by": "sandbox",
                                                          "submissionId": sub.id}]
    audit.record(db, "system:sandbox", "sandbox.verdict", sub.id, sub.tenant_id, sha256=sub.sha256, verdict=result["verdict"], score=result["score"])


def advance(db: Session, sub: SandboxSubmission) -> None:
    provider = db.get(SandboxProvider, sub.provider_id)
    if provider is None:
        sub.status, sub.reason = "failed", "The sandbox provider was removed"
        return
    now = utcnow()
    try:
        _guard(provider)
        with _client() as client:
            if sub.status == "approved":
                task = lookup(provider, client, sub.sha256)
                if task:
                    sub.task_id, sub.status, sub.reason = task, "submitted", "Known to the sandbox: using its earlier analysis"
                elif sub.mode == "hash":
                    sub.status, sub.verdict, sub.reason = "completed", "unknown", "The sandbox has not seen this hash; the file was not sent (hash-only mode)"
                elif sub.email_scan_id:
                    data = email_attachment(db, sub.email_scan_id, sub.sha256)
                    sub.task_id = submit_file(provider, client, f"{sub.sha256}{_ext(sub.filename)}", data)
                    sub.status, sub.reason = "submitted", "Attachment sent from the gateway quarantine; waiting for the sandbox"
                    audit.record(db, "system:sandbox", "sandbox.submitted", sub.id, sub.tenant_id, sha256=sub.sha256, task=sub.task_id,
                                 provider=provider.name, source="email quarantine")
                else:
                    device = db.get(Device, sub.device_id) if sub.device_id else None
                    if device is None:
                        raise SandboxError("The device holding the sample is gone")
                    if (device.platform or "").lower() not in ("linux", "macos"):
                        sub.status, sub.verdict = "completed", "unknown"
                        sub.reason = ("The sandbox has not seen this hash, and Windows agents cannot upload quarantined samples yet; "
                                      "only the hash was looked up")
                        audit.record(db, "system:sandbox", "sandbox.hash_only", sub.id, sub.tenant_id, sha256=sub.sha256, reason="windows agent")
                        return
                    cmd = services.enqueue_command(db, device, "sample.collect", "system:sandbox",
                                                   payload={"recordId": sub.quarantine_record, "sha256": sub.sha256},
                                                   reason=f"Sandbox submission {sub.id}")
                    sub.command_id, sub.status, sub.reason = cmd.id, "collecting", "Collecting the sample from quarantine"
            elif sub.status == "collecting":
                art = db.scalars(select(DeviceArtifact).where(DeviceArtifact.command_id == sub.command_id)).first()
                if art is None:
                    if now - sub.updated_at > COLLECT_TIMEOUT:
                        sub.status, sub.reason = "failed", "The device did not upload the sample"
                    return
                if art.sha256 != sub.sha256:
                    sub.status, sub.reason = "failed", "The uploaded sample does not match the requested SHA-256"
                    return
                sub.artifact_id = art.id
                sub.task_id = submit_file(provider, client, f"{sub.sha256}{_ext(sub.filename)}", _artifact_bytes(db, art.id))
                sub.status, sub.reason = "submitted", "Waiting for the sandbox"
                audit.record(db, "system:sandbox", "sandbox.submitted", sub.id, sub.tenant_id, sha256=sub.sha256, task=sub.task_id,
                             provider=provider.name)
            elif sub.status == "submitted":
                result = fetch_verdict(provider, client, sub.task_id)
                if result is None:
                    if now - sub.updated_at > ANALYSIS_TIMEOUT:
                        sub.status, sub.reason = "failed", "The sandbox did not finish within six hours"
                    return
                _record_verdict(db, sub, result)
                return
        sub.updated_at = now
        provider.status, provider.last_error = "ok", ""
    except (httpx.HTTPError, ValueError, crypto.VaultError, netguard.Blocked) as exc:
        provider.status, provider.last_error = "error", f"{type(exc).__name__}: {str(exc)[:300]}"
    except SandboxError as exc:
        sub.status, sub.reason = "failed", str(exc)


def tick(db: Session) -> int:
    done = 0
    for sub in db.scalars(select(SandboxSubmission).where(SandboxSubmission.status.in_(("approved", "collecting", "submitted")))).all():
        advance(db, sub)
        db.commit()
        done += 1
    return done


def store_key(provider: SandboxProvider, key: str) -> None:
    if not key or len(key) > 500:
        raise SandboxError("Enter the sandbox API key")
    provider.credentials_envelope = crypto.encrypt(key, f"sandbox:{provider.id}")

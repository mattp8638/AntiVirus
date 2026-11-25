"""Microsoft Purview retention and sensitivity labels: inventory, templates, drift and reviewed deployment (M365-27).

**What Microsoft Graph allows, and so what Fenrir does.**

| Item | Read | Change | Source |
|---|---|---|---|
| Retention labels | yes | create | ``/security/labels/retentionLabels`` (needs ``RecordsManagement.ReadWrite.All``) |
| Sensitivity labels | yes | no | Graph beta ``/security/informationProtection/sensitivityLabels`` |
| DLP policies, retention policies, sensitive information types | no | no | not in Graph (Security & Compliance PowerShell) |

Anything Fenrir cannot read is shown as unavailable, with the reason. It is never shown as compliant.

**Drift.** A template lists the retention labels a tenant should have. Drift is any listed label that is missing, or
that exists with a different retention period, action or behaviour.

**Deployment** creates only missing labels. A label that exists but differs is reported for a person to resolve:
changing it could alter what already-labelled content keeps or deletes. Every deployment is a change that a second
person, not its requester, must approve before Fenrir makes it. Each label's result is recorded and audited.
"""
from __future__ import annotations

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import audit, m365
from .models import M365Connection, PurviewBaseline, PurviewChange, PurviewInventory, utcnow

RETENTION = "/security/labels/retentionLabels"
SENSITIVITY = "https://graph.microsoft.com/beta/security/informationProtection/sensitivityLabels"
NOT_IN_GRAPH = {"dlpPolicies": "DLP policies are not available in Microsoft Graph (Security & Compliance PowerShell only)",
                "retentionPolicies": "Retention policies are not available in Microsoft Graph (Security & Compliance PowerShell only)",
                "sensitiveInfoTypes": "Sensitive information types are not available in Microsoft Graph"}
ACTIONS = ("delete", "startDispositionReview", "relabel", "none")
BEHAVIOURS = ("doNotRetain", "retain", "retainAsRecord", "retainAsRegulatoryRecord")
FIELDS = ("retentionDurationDays", "actionAfterRetentionPeriod", "behaviorDuringRetentionPeriod", "retentionTrigger")


class PurviewError(Exception):
    pass


def validate_labels(labels: list[dict]) -> list[dict]:
    out, names = [], set()
    for raw in labels:
        name = str(raw.get("displayName") or "").strip()
        days = raw.get("retentionDurationDays")
        if not name or name.lower() in names:
            raise PurviewError("Each label needs a unique name")
        if not isinstance(days, int) or not 1 <= days <= 36500:
            raise PurviewError(f"{name}: the retention period must be 1 to 36500 days")
        action, behaviour = raw.get("actionAfterRetentionPeriod", "none"), raw.get("behaviorDuringRetentionPeriod", "retain")
        if action not in ACTIONS or behaviour not in BEHAVIOURS:
            raise PurviewError(f"{name}: unsupported action or behaviour")
        trigger = raw.get("retentionTrigger", "dateLabeled")
        if trigger not in ("dateLabeled", "dateCreated", "dateModified"):
            raise PurviewError(f"{name}: unsupported retention trigger")
        names.add(name.lower())
        out.append({"displayName": name, "retentionDurationDays": days, "actionAfterRetentionPeriod": action,
                    "behaviorDuringRetentionPeriod": behaviour, "retentionTrigger": trigger})
    return out


def _client() -> httpx.Client:
    return httpx.Client(timeout=20, follow_redirects=False)


def _normal(label: dict) -> dict:
    return {"displayName": label.get("displayName"), "retentionDurationDays": (label.get("retentionDuration") or {}).get("days"),
            "actionAfterRetentionPeriod": label.get("actionAfterRetentionPeriod"),
            "behaviorDuringRetentionPeriod": label.get("behaviorDuringRetentionPeriod"), "retentionTrigger": label.get("retentionTrigger"),
            "id": label.get("id")}


def _why(r: httpx.Response) -> str:
    if r.status_code in (401, 403):
        return "Microsoft denied access: grant RecordsManagement.Read.All / InformationProtectionPolicy.Read.All, and check the licence"
    return f"Microsoft answered HTTP {r.status_code}"


def inventory(db: Session, conn: M365Connection, actor: str) -> PurviewInventory:
    data: dict = {"retentionLabels": None, "sensitivityLabels": None, "unavailable": dict(NOT_IN_GRAPH)}
    with _client() as client:
        token = m365.access_token(client, conn)
        h = {"Authorization": "Bearer " + token}
        r = client.get(m365.GRAPH + RETENTION, headers=h)
        if r.status_code < 400:
            data["retentionLabels"] = [_normal(x) for x in r.json().get("value") or []]
        else:
            data["unavailable"]["retentionLabels"] = _why(r)
        r = client.get(SENSITIVITY, headers=h)
        if r.status_code < 400:
            data["sensitivityLabels"] = [{"id": x.get("id"), "name": x.get("name") or x.get("displayName"), "sensitivity": x.get("sensitivity"),
                                          "isActive": x.get("isActive", True), "parent": (x.get("parent") or {}).get("name")}
                                         for x in r.json().get("value") or []]
        else:
            data["unavailable"]["sensitivityLabels"] = _why(r) + " (beta API)"
    row = PurviewInventory(tenant_id=conn.tenant_id, connection_id=conn.id, data=data)
    db.add(row)
    db.flush()
    for old in db.scalars(select(PurviewInventory).where(PurviewInventory.connection_id == conn.id, PurviewInventory.id != row.id)).all():
        db.delete(old)
    audit.record(db, actor, "m365.purview_inventory", row.id, conn.tenant_id, retentionLabels=len(data["retentionLabels"] or []),
                 unavailable=sorted(data["unavailable"]))
    return row


def drift(baseline: PurviewBaseline, inv: PurviewInventory) -> dict:
    labels = inv.data.get("retentionLabels")
    if labels is None:
        return {"status": "unknown", "reason": inv.data["unavailable"].get("retentionLabels"), "items": []}
    have = {x["displayName"].lower(): x for x in labels}
    items = []
    for want in baseline.retention_labels:
        got = have.get(want["displayName"].lower())
        if got is None:
            items.append({"label": want["displayName"], "state": "missing", "differences": []})
            continue
        diffs = [{"field": f, "template": want[f], "tenant": got.get(f)} for f in FIELDS if got.get(f) != want[f]]
        items.append({"label": want["displayName"], "state": "different" if diffs else "matches", "differences": diffs})
    status = "matches" if all(i["state"] == "matches" for i in items) else "drifted"
    return {"status": status, "items": items}


def propose(db: Session, conn: M365Connection, baseline: PurviewBaseline, inv: PurviewInventory, actor: str) -> PurviewChange:
    d = drift(baseline, inv)
    if d["status"] == "unknown":
        raise PurviewError("Retention labels could not be read: " + str(d["reason"]))
    plan = []
    for item in d["items"]:
        want = next(w for w in baseline.retention_labels if w["displayName"] == item["label"])
        if item["state"] == "missing":
            plan.append({"label": item["label"], "action": "create", "body": want})
        elif item["state"] == "different":
            plan.append({"label": item["label"], "action": "review", "differences": item["differences"],
                         "reason": "The label exists with different settings; changing it could alter what labelled content keeps or deletes, so a person resolves it in Purview"})
    if not any(p["action"] == "create" for p in plan):
        raise PurviewError("Nothing to create: every template label exists" + (" (some differ and need a person)" if plan else ""))
    change = PurviewChange(tenant_id=conn.tenant_id, connection_id=conn.id, baseline_id=baseline.id, plan=plan, requested_by=actor)
    db.add(change)
    db.flush()
    audit.record(db, actor, "m365.purview_change_proposed", change.id, conn.tenant_id, creates=[p["label"] for p in plan if p["action"] == "create"])
    return change


def review(db: Session, change: PurviewChange, conn: M365Connection, approve: bool, note: str, actor: str) -> PurviewChange:
    if change.status != "proposed":
        raise PurviewError("This change has already been reviewed")
    if actor.lower() == change.requested_by.lower():
        raise PurviewError("A second person must review this change; you proposed it")
    change.reviewed_by, change.review_note, change.reviewed_at = actor, note[:1000], utcnow()
    if not approve:
        change.status = "rejected"
        audit.record(db, actor, "m365.purview_change_rejected", change.id, change.tenant_id, note=note[:300])
        return change
    results = []
    with _client() as client:
        token = m365.access_token(client, conn)
        h = {"Authorization": "Bearer " + token}
        for step in change.plan:
            if step["action"] != "create":
                results.append({"label": step["label"], "status": "left for a person"})
                continue
            b = step["body"]
            body = {"displayName": b["displayName"], "behaviorDuringRetentionPeriod": b["behaviorDuringRetentionPeriod"],
                    "actionAfterRetentionPeriod": b["actionAfterRetentionPeriod"], "retentionTrigger": b["retentionTrigger"],
                    "retentionDuration": {"@odata.type": "#microsoft.graph.security.retentionDurationInDays", "days": b["retentionDurationDays"]},
                    "defaultRecordBehavior": "startLocked" if b["behaviorDuringRetentionPeriod"].startswith("retainAs") else "startUnlocked"}
            try:
                r = client.post(m365.GRAPH + RETENTION, headers=h, json=body)
                results.append({"label": step["label"], "status": "created" if r.status_code < 400 else "failed",
                                **({} if r.status_code < 400 else {"message": _why(r)}), "id": (r.json() if r.content and r.status_code < 400 else {}).get("id")})
            except httpx.HTTPError as exc:
                results.append({"label": step["label"], "status": "unknown", "message": f"No answer ({type(exc).__name__}); check Purview"})
    change.results = results
    made = [x for x in results if x["status"] == "created"]
    wanted = [x for x in results if x["status"] != "left for a person"]
    change.status = "completed" if len(made) == len(wanted) else "failed" if not made else "partial"
    audit.record(db, actor, "m365.purview_change_applied", change.id, change.tenant_id, status=change.status,
                 results=[{k: x.get(k) for k in ("label", "status")} for x in results])
    return change

"""Microsoft 365 tenant configuration backup, comparison, change history and restore (M365-14).

Backup reads each supported resource through Microsoft Graph. It stores the objects as Microsoft returned them,
minus read-only fields, with a SHA-256 per object and of the whole snapshot. The names of the groups, users and named
locations those objects refer to are stored with them. A resource that cannot be read is recorded with the reason,
never treated as empty. A new snapshot is kept only when something changed; its ``changes`` lists what was added,
removed and changed since the previous one, field by field.

Comparison works between any two snapshots, including snapshots of different tenants. Before comparing, references
are replaced by names, so a policy that targets the group "Finance" matches in both tenants even though the group IDs
differ.

Restore is planned first, reading the target tenant live, and nothing is written while planning. For each chosen
object the plan says one of:

* ``create``: it is missing from the target;
* ``update``: it exists and differs, with the fields that differ;
* ``unchanged``;
* ``blocked``: it cannot be restored, with the reason.

References are translated by name: groups by display name, users by user principal name, named locations by
display name (a location restored in the same run is created first). A reference with no match blocks the object;
Fenrir never drops it silently. Conditional Access policies are written report-only unless the technician keeps
their state.

What Fenrir does not restore, and why, is in ``NOT_RESTORED`` and shown in the plan.
"""
from __future__ import annotations

import copy
import hashlib
import json
import logging
from datetime import timedelta
import re
from urllib.parse import quote

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import audit, m365
from .models import M365ConfigRestore, M365ConfigSnapshot, M365Connection, utcnow

log = logging.getLogger("fenrir.m365.config")

PLAN_VALID = timedelta(minutes=30)
SNAPSHOT_EVERY = timedelta(hours=24)
KEEP_FOR = timedelta(days=365)
MAX_REFERENCED_USERS = 500

# Restore order matters: named locations exist before the policies that use them.
RESOURCES: dict[str, dict] = {
    "namedLocations": {"title": "Named locations", "path": "/identity/conditionalAccess/namedLocations", "kind": "collection"},
    "conditionalAccess": {"title": "Conditional Access policies", "path": "/identity/conditionalAccess/policies", "kind": "collection"},
    "authorizationPolicy": {"title": "Authorization policy (user and guest defaults)", "path": "/policies/authorizationPolicy", "kind": "singleton",
                            "fields": ["allowInvitesFrom", "allowedToSignUpEmailBasedSubscriptions", "allowedToUseSSPR",
                                       "allowEmailVerifiedUsersToJoinOrganization", "blockMsolPowerShell", "guestUserRoleId",
                                       "defaultUserRolePermissions"]},
    "securityDefaults": {"title": "Security defaults", "path": "/policies/identitySecurityDefaultsEnforcementPolicy", "kind": "singleton",
                         "fields": ["isEnabled"]},
    "authenticationMethods": {"title": "Authentication methods policy", "path": "/policies/authenticationMethodsPolicy", "kind": "singleton",
                              "fields": []},
    "intuneCompliance": {"title": "Intune compliance policies", "path": "/deviceManagement/deviceCompliancePolicies", "kind": "collection"},
    "intuneConfiguration": {"title": "Intune configuration profiles", "path": "/deviceManagement/deviceConfigurations", "kind": "collection"},
}
NOT_RESTORED = {
    "authenticationMethods": "Each authentication method has its own configuration with group targets; Microsoft only accepts them "
                             "one method at a time. Fenrir backs them up and compares them but does not restore them yet.",
    "assignments": "Intune assignments (which groups get a policy) are not backed up; assign restored policies again.",
    "secrets": "Intune profiles holding encrypted values (Wi-Fi keys, VPN secrets, encrypted OMA-URI settings) cannot be read "
               "back from Microsoft, so they cannot be restored.",
}
READ_ONLY = {"id", "createdDateTime", "modifiedDateTime", "lastModifiedDateTime", "version", "templateId", "deletedDateTime",
             "@odata.context", "@odata.etag", "roleScopeTagIds", "supportsScopeTags", "deviceManagementApplicabilityRuleOsEdition",
             "deviceManagementApplicabilityRuleOsVersion", "deviceManagementApplicabilityRuleDeviceMode"}
SPECIAL_REFS = {"All", "None", "GuestsOrExternalUsers", "AllTrusted"}
SAFE_ID = re.compile(r"^[A-Za-z0-9-]{1,64}$")  # directory object IDs (GUIDs) go into a URL path


class ConfigError(Exception):
    pass


# ---- helpers -------------------------------------------------------------------------------------------------------

def _clean(obj: dict) -> dict:
    return {k: v for k, v in obj.items() if k not in READ_ONLY and not k.endswith("@odata.navigationLink")}


def _sha(value) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()


def _key(resource: str, obj: dict) -> str:
    return resource if RESOURCES[resource]["kind"] == "singleton" else str(obj.get("displayName") or obj.get("id") or "")


def _ca_refs(policy: dict) -> dict:
    """The group, user and location IDs a Conditional Access policy refers to."""
    cond = policy.get("conditions") or {}
    users, locations = cond.get("users") or {}, cond.get("locations") or {}
    return {"groups": [g for k in ("includeGroups", "excludeGroups") for g in users.get(k) or [] if g not in SPECIAL_REFS],
            "users": [u for k in ("includeUsers", "excludeUsers") for u in users.get(k) or [] if u not in SPECIAL_REFS],
            "locations": [x for k in ("includeLocations", "excludeLocations") for x in locations.get(k) or [] if x not in SPECIAL_REFS]}


def _map_ca(policy: dict, groups, users, locations) -> dict:
    """A copy of a policy with every reference passed through the three mapping functions."""
    out = copy.deepcopy(policy)
    cond = out.get("conditions") or {}
    u, loc = cond.get("users") or {}, cond.get("locations") or {}
    for k in ("includeGroups", "excludeGroups"):
        if k in u and u[k] is not None:
            u[k] = [g if g in SPECIAL_REFS else groups(g) for g in u[k]]
    for k in ("includeUsers", "excludeUsers"):
        if k in u and u[k] is not None:
            u[k] = [x if x in SPECIAL_REFS else users(x) for x in u[k]]
    for k in ("includeLocations", "excludeLocations"):
        if k in loc and loc[k] is not None:
            loc[k] = [x if x in SPECIAL_REFS else locations(x) for x in loc[k]]
    return out


def comparable(snapshot_refs: dict, resource: str, obj: dict) -> dict:
    """The object with IDs replaced by names, so tenants can be compared."""
    if resource != "conditionalAccess":
        return obj
    g, u, loc = snapshot_refs.get("groups", {}), snapshot_refs.get("users", {}), snapshot_refs.get("locations", {})
    mapped = _map_ca(obj, lambda x: "group:" + g.get(x, x), lambda x: "user:" + u.get(x, x), lambda x: "location:" + loc.get(x, x))
    for k in ("includeGroups", "excludeGroups", "includeUsers", "excludeUsers"):
        users = (mapped.get("conditions") or {}).get("users") or {}
        if isinstance(users.get(k), list):
            users[k] = sorted(users[k])
    return mapped


def _flatten(value, prefix="") -> dict:
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            out.update(_flatten(v, f"{prefix}.{k}" if prefix else k))
        return out or {prefix: {}}
    if isinstance(value, list) and value and all(isinstance(x, dict) for x in value):
        return {prefix: json.dumps(value, sort_keys=True)}
    return {prefix: value}


def field_diff(a: dict, b: dict) -> list[dict]:
    fa, fb = _flatten(a), _flatten(b)
    return [{"field": k, "before": fa.get(k), "after": fb.get(k)} for k in sorted(set(fa) | set(fb)) if fa.get(k) != fb.get(k)]


def diff(left: M365ConfigSnapshot, right: M365ConfigSnapshot) -> dict:
    """What changed from ``left`` to ``right``, per resource, by name."""
    out = {}
    for resource in RESOURCES:
        if resource in (left.errors or {}) or resource in (right.errors or {}):
            out[resource] = {"unavailable": (left.errors or {}).get(resource) or (right.errors or {}).get(resource)}
            continue
        a = {_key(resource, o): comparable(left.references or {}, resource, o) for o in (left.resources or {}).get(resource, [])}
        b = {_key(resource, o): comparable(right.references or {}, resource, o) for o in (right.resources or {}).get(resource, [])}
        changed = [{"name": k, "fields": field_diff(a[k], b[k])} for k in sorted(set(a) & set(b)) if a[k] != b[k]]
        added, removed = sorted(set(b) - set(a)), sorted(set(a) - set(b))
        if added or removed or changed:
            out[resource] = {"added": added, "removed": removed, "changed": changed}
    return out


# ---- backup --------------------------------------------------------------------------------------------------------

def _client() -> httpx.Client:
    return httpx.Client(timeout=30, follow_redirects=False)


def _read(client, token: str, resource: str) -> list[dict]:
    spec = RESOURCES[resource]
    if spec["kind"] == "collection":
        return [_clean(o) for o in m365.collect(client, m365.GRAPH + spec["path"], token)]
    r = client.get(m365.GRAPH + spec["path"], headers={"Authorization": "Bearer " + token})
    r.raise_for_status()
    body = _clean(r.json())
    if spec["fields"]:
        body = {k: body[k] for k in spec["fields"] if k in body}
    return [body]


def _why(exc: Exception) -> str:
    if isinstance(exc, httpx.HTTPStatusError):
        code = exc.response.status_code
        if code in (401, 403):
            return "Microsoft denied access: the connection lacks the permission (or licence) to read this"
        if code == 404:
            return "Not available in this tenant (feature or licence missing)"
        return f"Microsoft answered HTTP {code}"
    return f"{type(exc).__name__}: {str(exc)[:200]}"


def take(db: Session, connection: M365Connection, actor: str) -> tuple[M365ConfigSnapshot, bool]:
    """Back up the tenant's configuration. Returns (snapshot, created): an unchanged tenant returns the last one."""
    resources, errors, hashes = {}, {}, {}
    refs: dict[str, dict] = {"groups": {}, "users": {}, "locations": {}}
    with _client() as client:
        token = m365.access_token(client, connection)
        for resource in RESOURCES:
            try:
                rows = _read(client, token, resource)
            except (httpx.HTTPError, ValueError) as exc:
                errors[resource] = _why(exc)
                continue
            resources[resource] = sorted(rows, key=lambda o: _key(resource, o))
            hashes[resource] = {_key(resource, o): _sha(o) for o in rows}
        refs["locations"] = {o["id"]: o.get("displayName", "") for o in _raw_locations(client, token) if o.get("id")} \
            if "namedLocations" in resources else {}
        wanted = {"groups": set(), "users": set()}
        for policy in resources.get("conditionalAccess", []):
            r = _ca_refs(policy)
            wanted["groups"].update(r["groups"])
            wanted["users"].update(r["users"])
        refs["groups"] = _names(client, token, "groups", wanted["groups"], "displayName", errors)
        refs["users"] = _names(client, token, "users", list(wanted["users"])[:MAX_REFERENCED_USERS], "userPrincipalName", errors)
    digest = _sha({"resources": resources, "errors": errors})
    last = latest(db, connection.id)
    if last is not None and last.digest == digest:
        last.checked_at = utcnow()
        return last, False
    snap = M365ConfigSnapshot(tenant_id=connection.tenant_id, connection_id=connection.id, resources=resources, references=refs,
                              hashes=hashes, errors=errors, digest=digest, taken_by=actor)
    snap.changes = diff(last, snap) if last is not None else {"first": True}
    db.add(snap)
    db.flush()
    audit.record(db, actor, "m365.config_backup", snap.id, connection.tenant_id, connectionId=connection.id, digest=digest,
                 unavailable=sorted(errors), changed=sorted(snap.changes) if last is not None else "first")
    return snap, True


def _raw_locations(client, token) -> list[dict]:
    return m365.collect(client, m365.GRAPH + RESOURCES["namedLocations"]["path"], token)


def _names(client, token, kind: str, ids, field: str, errors: dict) -> dict:
    out = {}
    for ident in ids:
        if not SAFE_ID.match(str(ident)):
            continue
        r = client.get(m365.GRAPH + f"/{kind}/{ident}?$select=id,{field}", headers={"Authorization": "Bearer " + token})
        if r.status_code == 404:
            out[ident] = f"(deleted {kind[:-1]} {ident})"
            continue
        if r.status_code >= 400:
            errors.setdefault("references", f"Could not read some referenced {kind} (HTTP {r.status_code})")
            continue
        out[ident] = r.json().get(field) or ident
    return out


def latest(db: Session, connection_id: str) -> M365ConfigSnapshot | None:
    return db.scalars(select(M365ConfigSnapshot).where(M365ConfigSnapshot.connection_id == connection_id)
                      .order_by(M365ConfigSnapshot.taken_at.desc())).first()


def verify(snapshot: M365ConfigSnapshot) -> bool:
    return snapshot.digest == _sha({"resources": snapshot.resources, "errors": snapshot.errors})


# ---- restore -------------------------------------------------------------------------------------------------------

def _target_state(client, token) -> dict:
    groups = {g.get("displayName"): g["id"] for g in m365.collect(client, m365.GRAPH + "/groups?$select=id,displayName", token)
              if g.get("displayName")}
    locations = {x.get("displayName"): x["id"] for x in _raw_locations(client, token) if x.get("displayName")}
    return {"groups": groups, "locations": locations}


def _user_id(client, token, upn: str) -> str | None:
    r = client.get(m365.GRAPH + "/users/" + quote(upn, safe="@") + "?$select=id", headers={"Authorization": "Bearer " + token})
    return r.json().get("id") if r.status_code == 200 else None


def _encrypted(profile: dict) -> bool:
    text = json.dumps(profile)
    return '"isEncrypted": true' in text or "secretReferenceValueId" in text or '"preSharedKey"' in text


def plan(db: Session, snapshot: M365ConfigSnapshot, target: M365Connection, selection: list[dict], options: dict, actor: str) -> M365ConfigRestore:
    """selection: [{"resource": ..., "name": ...}]. Reads the target tenant; writes nothing to Microsoft."""
    if not verify(snapshot):
        raise ConfigError("This snapshot does not match its SHA-256; it will not be restored")
    keep_state = bool(options.get("keepState"))
    chosen = {(s.get("resource"), s.get("name")) for s in selection}
    if not chosen:
        raise ConfigError("Choose what to restore")
    restoring_locations = {n for r, n in chosen if r == "namedLocations"}
    refs = snapshot.references or {}
    steps = []
    with _client() as client:
        token = m365.access_token(client, target)
        state = _target_state(client, token)
        live: dict[str, dict] = {}
        for resource in RESOURCES:
            if resource in {r for r, _ in chosen}:
                try:
                    live[resource] = {_key(resource, o): o for o in (_read_raw(client, token, resource))}
                except (httpx.HTTPError, ValueError) as exc:
                    live[resource] = {"__error__": _why(exc)}
        for resource in RESOURCES:
            for obj in (snapshot.resources or {}).get(resource, []):
                name = _key(resource, obj)
                if (resource, name) not in chosen:
                    continue
                chosen.discard((resource, name))
                step = {"resource": resource, "name": name, "action": "", "reasons": [], "translations": [], "body": None,
                        "targetId": None, "fields": []}
                steps.append(step)
                if resource in NOT_RESTORED:
                    step.update(action="blocked", reasons=[NOT_RESTORED[resource]])
                    continue
                if "__error__" in live.get(resource, {}):
                    step.update(action="blocked", reasons=["Could not read the target tenant: " + live[resource]["__error__"]])
                    continue
                body = copy.deepcopy(obj)
                if resource == "intuneConfiguration" and _encrypted(body):
                    step.update(action="blocked", reasons=[NOT_RESTORED["secrets"]])
                    continue
                if resource == "conditionalAccess":
                    body = _translate_ca(client, token, body, refs, state, restoring_locations, step)
                    if step["reasons"]:
                        step["action"] = "blocked"
                        continue
                    if not keep_state and body.get("state") == "enabled":
                        body["state"] = "enabledForReportingButNotEnforced"
                        step["translations"].append("Written as report-only (keep state was not chosen)")
                current = live.get(resource, {}).get(name)
                if RESOURCES[resource]["kind"] == "singleton":
                    current_cmp = {k: (current or {}).get(k) for k in body}
                    changes = field_diff(current_cmp, body)
                    step.update(action="update" if changes else "unchanged", fields=changes, body=body)
                    continue
                if current is None:
                    step.update(action="create", body=body)
                else:
                    cmp_current = {k: v for k, v in _clean(current).items() if k in body or k == "@odata.type"}
                    changes = field_diff(_strip_ids(cmp_current), _strip_ids(body))
                    step.update(action="update" if changes else "unchanged", fields=changes, body=body, targetId=current.get("id"))
                if resource.startswith("intune"):
                    step["translations"].append(NOT_RESTORED["assignments"])
    for resource, name in sorted(chosen, key=str):
        steps.append({"resource": resource, "name": name, "action": "blocked", "reasons": ["Not in this snapshot"], "translations": [],
                      "body": None, "targetId": None, "fields": []})
    restore = M365ConfigRestore(tenant_id=target.tenant_id, connection_id=target.id, snapshot_id=snapshot.id, plan=steps,
                                options={"keepState": keep_state}, created_by=actor)
    db.add(restore)
    db.flush()
    audit.record(db, actor, "m365.config_restore_planned", restore.id, target.tenant_id, snapshotId=snapshot.id,
                 fromTenant=snapshot.tenant_id, actions={a: sum(1 for s in steps if s["action"] == a) for a in
                                                         ("create", "update", "unchanged", "blocked")})
    return restore


def _strip_ids(obj: dict) -> dict:
    return {k: v for k, v in obj.items() if k not in ("id",)}


def _read_raw(client, token, resource: str) -> list[dict]:
    spec = RESOURCES[resource]
    if spec["kind"] == "collection":
        return m365.collect(client, m365.GRAPH + spec["path"], token)
    r = client.get(m365.GRAPH + spec["path"], headers={"Authorization": "Bearer " + token})
    r.raise_for_status()
    return [r.json()]


def _translate_ca(client, token, policy: dict, refs: dict, state: dict, restoring_locations: set, step: dict) -> dict:
    groups, users, locations = refs.get("groups", {}), refs.get("users", {}), refs.get("locations", {})

    def group(gid):
        name = groups.get(gid)
        new = state["groups"].get(name) if name else None
        if new is None:
            step["reasons"].append(f"Group '{name or gid}' does not exist in the target tenant")
            return gid
        if new != gid:
            step["translations"].append(f"Group '{name}': {gid} → {new}")
        return new

    def user(uid):
        upn = users.get(uid)
        new = _user_id(client, token, upn) if upn and "@" in upn else None
        if new is None:
            step["reasons"].append(f"User '{upn or uid}' does not exist in the target tenant")
            return uid
        if new != uid:
            step["translations"].append(f"User '{upn}': {uid} → {new}")
        return new

    def location(lid):
        name = locations.get(lid)
        new = state["locations"].get(name) if name else None
        if new is None and name in restoring_locations:
            step["translations"].append(f"Named location '{name}' is restored first in this run")
            return {"$location": name}
        if new is None:
            step["reasons"].append(f"Named location '{name or lid}' does not exist in the target tenant; restore it too")
            return lid
        if new != lid:
            step["translations"].append(f"Named location '{name}': {lid} → {new}")
        return new

    return _map_ca(policy, group, user, location)


def _resolve_pending(value, created_locations: dict):
    if isinstance(value, dict):
        if set(value) == {"$location"}:
            if value["$location"] not in created_locations:
                raise ConfigError(f"Named location '{value['$location']}' was not created, so this policy cannot refer to it")
            return created_locations[value["$location"]]
        return {k: _resolve_pending(v, created_locations) for k, v in value.items()}
    if isinstance(value, list):
        return [_resolve_pending(v, created_locations) for v in value]
    return value


def execute(db: Session, restore: M365ConfigRestore, target: M365Connection, actor: str) -> M365ConfigRestore:
    if restore.status != "planned":
        raise ConfigError("This restore has already run; plan it again")
    if restore.created_at < utcnow() - PLAN_VALID:
        raise ConfigError("The plan is more than 30 minutes old; plan it again so it reflects the tenant now")
    restore.status, restore.executed_by, restore.executed_at = "running", actor, utcnow()
    db.commit()  # durable boundary: a crash from here leaves the restore 'running' for a person to check
    results, created_locations = [], {}
    with _client() as client:
        token = m365.access_token(client, target)
        headers = {"Authorization": "Bearer " + token}
        for step in restore.plan:
            outcome = {"resource": step["resource"], "name": step["name"], "action": step["action"]}
            if step["action"] in ("blocked", "unchanged"):
                outcome["status"] = "skipped"
                results.append(outcome)
                continue
            spec = RESOURCES[step["resource"]]
            try:
                body = _resolve_pending(step["body"], created_locations)
                if spec["kind"] == "singleton":
                    r = client.patch(m365.GRAPH + spec["path"], headers=headers, json=body)
                elif step["action"] == "create":
                    if step["resource"] == "intuneCompliance" and "scheduledActionsForRule" not in body:
                        body["scheduledActionsForRule"] = [{"ruleName": "PasswordRequired", "scheduledActionConfigurations": [
                            {"actionType": "block", "gracePeriodHours": 0, "notificationTemplateId": "", "notificationMessageCCList": []}]}]
                    r = client.post(m365.GRAPH + spec["path"], headers=headers, json=body)
                else:
                    r = client.patch(m365.GRAPH + spec["path"] + "/" + str(step["targetId"]), headers=headers, json=body)
                if r.status_code >= 400:
                    outcome.update(status="failed", message=f"Microsoft answered HTTP {r.status_code}" + _said(r))
                else:
                    outcome["status"] = "succeeded"
                    new_id = (r.json() if r.content else {}).get("id") or step.get("targetId")
                    outcome["id"] = new_id
                    if step["resource"] == "namedLocations" and new_id:
                        created_locations[step["name"]] = new_id
            except ConfigError as exc:
                outcome.update(status="failed", message=str(exc))
            except httpx.HTTPError as exc:
                outcome.update(status="unknown", message=f"No answer from Microsoft ({type(exc).__name__}); check the tenant")
            results.append(outcome)
    restore.results = results
    writes = [r for r in results if r["status"] != "skipped"]
    ok = [r for r in writes if r["status"] == "succeeded"]
    restore.status = "completed" if len(ok) == len(writes) else ("failed" if not ok else "partial")
    audit.record(db, actor, "m365.config_restored", restore.id, target.tenant_id, status=restore.status,
                 results=[{k: r.get(k) for k in ("resource", "name", "action", "status")} for r in results])
    db.commit()
    return restore


def _said(response: httpx.Response) -> str:
    try:
        err = response.json().get("error") or {}
        text = ": ".join(str(x) for x in (err.get("code"), err.get("message")) if x)
    except (ValueError, AttributeError):
        text = ""
    return f" ({text[:300]})" if text else ""


# ---- schedule ------------------------------------------------------------------------------------------------------

def tick(db: Session, limit: int = 20) -> int:
    """Daily backup of each working connection, a few per hourly pass; old snapshots past KEEP_FOR are removed
    (the newest one of each connection is always kept)."""
    done = 0
    for conn in db.scalars(select(M365Connection)).all():
        if done >= limit:
            break
        if conn.status in ("error", "disconnected", "revoked"):
            continue
        last = latest(db, conn.id)
        if last is not None and (last.checked_at or last.taken_at) > utcnow() - SNAPSHOT_EVERY:
            continue
        try:
            take(db, conn, "system:m365-config-backup")
            db.commit()
            done += 1
        except Exception as exc:  # noqa: BLE001 - one tenant must not stop the others
            db.rollback()
            log.warning("configuration backup of %s failed: %s", conn.id, exc)
    cutoff = utcnow() - KEEP_FOR
    for snap in db.scalars(select(M365ConfigSnapshot).where(M365ConfigSnapshot.taken_at < cutoff)).all():
        if latest(db, snap.connection_id).id != snap.id:
            db.delete(snap)
    db.commit()
    return done

"""Conditional Access simulation and gap analysis (M365-15).

Fenrir works out, from the Conditional Access policies and named locations in a configuration backup (M365-14), which
policies would apply to a sign-in and what they would require. The result is a **model**. No sign-in is made, nothing
is sent to the tenant, and the outcome is labelled ``modelled`` everywhere it is shown.

Each run keeps its inputs: the scenarios, the snapshot and its SHA-256. Each result carries a confidence rating:

* ``high``: every condition of every policy involved was evaluated.
* ``medium``: a policy uses a condition Fenrir cannot evaluate from configuration alone, such as a device filter,
  authentication context or insider risk. That policy is listed as uncertain.
* ``low``: the scenario depends on group membership Fenrir was not given.

The gap analysis runs a fixed set of scenarios that a sound baseline should cover:

* members signing in from outside trusted locations;
* administrators;
* legacy authentication;
* guests;
* registering security information;
* risky sign-ins.

Each scenario passes or is a gap, with the reason.
"""
from __future__ import annotations

import ipaddress

from sqlalchemy.orm import Session

from . import audit, m365_config
from .models import M365CaSimulation, M365ConfigSnapshot

GLOBAL_ADMIN = "62e90394-69f5-4237-9190-012177145e10"
SECURITY_ADMIN = "194ae4cb-b126-40b2-bd5b-6091b380977d"
STRONG = {"block", "mfa", "authenticationStrength"}
UNSUPPORTED = {"devices": "device filter", "authenticationFlows": "authentication flows", "insiderRiskLevels": "insider risk",
               "servicePrincipalRiskLevels": "workload identity risk", "clientApplications": "workload identities"}

# Scenario fields: user {kind: member|guest, roles: [templateId], groups: [id], id}, app (All|Office365|appId),
# userAction, clientApp (browser|mobileAppsAndDesktopClients|exchangeActiveSync|other), platform, ip, country,
# signInRisk, userRisk (none|low|medium|high).
GAP_SCENARIOS = [
    {"key": "member-untrusted", "title": "A member signs in to Office 365 in a browser from outside trusted locations",
     "expect": "mfa", "user": {"kind": "member"}, "app": "Office365", "clientApp": "browser", "platform": "windows", "ip": "203.0.113.50"},
    {"key": "admin", "title": "A Global Administrator signs in to any app", "expect": "mfa",
     "user": {"kind": "member", "roles": [GLOBAL_ADMIN]}, "app": "All", "clientApp": "browser", "platform": "windows", "ip": "203.0.113.50"},
    {"key": "legacy-auth", "title": "Someone uses legacy authentication (IMAP, POP, SMTP AUTH, older Office clients)", "expect": "block",
     "user": {"kind": "member"}, "app": "Office365", "clientApp": "other", "platform": "windows", "ip": "203.0.113.50"},
    {"key": "activesync", "title": "A phone connects with Exchange ActiveSync basic authentication", "expect": "block",
     "user": {"kind": "member"}, "app": "Office365", "clientApp": "exchangeActiveSync", "platform": "android", "ip": "203.0.113.50"},
    {"key": "guest", "title": "A guest signs in", "expect": "mfa",
     "user": {"kind": "guest"}, "app": "All", "clientApp": "browser", "platform": "macOS", "ip": "203.0.113.50"},
    {"key": "security-info", "title": "A member registers security information (MFA methods) from outside trusted locations",
     "expect": "mfa", "user": {"kind": "member"}, "app": None, "userAction": "urn:user:registersecurityinfo", "clientApp": "browser",
     "platform": "windows", "ip": "203.0.113.50"},
    {"key": "risky-signin", "title": "A sign-in Microsoft rates high risk", "expect": "mfa",
     "user": {"kind": "member"}, "app": "All", "clientApp": "browser", "platform": "windows", "ip": "203.0.113.50", "signInRisk": "high"},
]


def _in_location(loc_ids: list, scenario: dict, locations: dict) -> tuple[bool, bool]:
    """(matches, certain) for a list of location IDs / All / AllTrusted against the scenario's IP or country."""
    ip, country = scenario.get("ip"), scenario.get("country")
    certain = True
    for lid in loc_ids or []:
        if lid == "All":
            return True, True
        loc = locations.get(lid)
        if lid == "AllTrusted":
            hit = any(_loc_match(x, ip, country)[0] for x in locations.values() if x.get("isTrusted"))
            if hit:
                return True, True
            continue
        if loc is None:
            certain = False
            continue
        hit, sure = _loc_match(loc, ip, country)
        certain = certain and sure
        if hit:
            return True, sure
    return False, certain


def _loc_match(loc: dict, ip, country) -> tuple[bool, bool]:
    if "ipRanges" in loc:
        if not ip:
            return False, False
        try:
            addr = ipaddress.ip_address(ip)
            return any(addr in ipaddress.ip_network(r.get("cidrAddress"), strict=False) for r in loc.get("ipRanges") or []
                       if r.get("cidrAddress")), True
        except ValueError:
            return False, False
    if "countriesAndRegions" in loc:
        if not country:
            return False, False
        return country.upper() in [c.upper() for c in loc.get("countriesAndRegions") or []], True
    return False, False


def applies(policy: dict, s: dict, locations: dict) -> tuple[bool, list[str], list[str]]:
    """(applies, why, uncertain conditions)."""
    c = policy.get("conditions") or {}
    why, unsure = [], []
    u = c.get("users") or {}
    user = s.get("user") or {}
    uid, groups, roles = user.get("id"), set(user.get("groups") or []), set(user.get("roles") or [])
    guest = user.get("kind") == "guest"
    incl_users = u.get("includeUsers") or []
    included = ("All" in incl_users or (uid and uid in incl_users) or (guest and "GuestsOrExternalUsers" in incl_users)
                or bool(groups & set(u.get("includeGroups") or [])) or bool(roles & set(u.get("includeRoles") or []))
                or (guest and bool(u.get("includeGuestsOrExternalUsers"))))
    if not included:
        if (u.get("includeGroups") and "groups" not in user):
            unsure.append("group membership not given")
        return False, ["the user is not in the policy's users"], unsure
    excluded = ((uid and uid in (u.get("excludeUsers") or [])) or bool(groups & set(u.get("excludeGroups") or []))
                or bool(roles & set(u.get("excludeRoles") or [])) or (guest and ("GuestsOrExternalUsers" in (u.get("excludeUsers") or [])
                                                                                or bool(u.get("excludeGuestsOrExternalUsers")))))
    if excluded:
        return False, ["the user is excluded"], unsure
    if u.get("excludeGroups") and "groups" not in user:
        unsure.append("group membership not given (the policy excludes groups)")
    a = c.get("applications") or {}
    if s.get("userAction"):
        if s["userAction"] not in (a.get("includeUserActions") or []):
            return False, ["the policy does not cover this user action"], unsure
    else:
        if a.get("includeUserActions") and not a.get("includeApplications"):
            return False, ["the policy covers user actions only"], unsure
        apps = a.get("includeApplications") or []
        app = s.get("app") or "All"
        if not ("All" in apps or app in apps or (app == "All" and apps)):
            return False, ["the policy does not cover this app"], unsure
        if app in (a.get("excludeApplications") or []):
            return False, ["the app is excluded"], unsure
        if a.get("excludeApplications") and app == "All":
            unsure.append("some apps are excluded")
        if a.get("includeAuthenticationContextClassReferences"):
            unsure.append("authentication context")
    types = c.get("clientAppTypes") or ["all"]
    if "all" not in types and s.get("clientApp") not in types:
        return False, ["the policy does not cover this client app"], unsure
    p = c.get("platforms") or {}
    if p.get("includePlatforms"):
        if not ("all" in p["includePlatforms"] or s.get("platform") in p["includePlatforms"]):
            return False, ["the policy does not cover this platform"], unsure
        if s.get("platform") in (p.get("excludePlatforms") or []):
            return False, ["the platform is excluded"], unsure
    loc = c.get("locations") or {}
    if loc.get("includeLocations"):
        hit, sure = _in_location(loc["includeLocations"], s, locations)
        if not sure:
            unsure.append("a named location could not be evaluated")
        if not hit:
            return False, ["the sign-in is not from an included location"], unsure
    if loc.get("excludeLocations"):
        hit, sure = _in_location(loc["excludeLocations"], s, locations)
        if not sure:
            unsure.append("a named location could not be evaluated")
        if hit:
            return False, ["the sign-in is from an excluded (for example trusted) location"], unsure
    for field, key in (("signInRiskLevels", "signInRisk"), ("userRiskLevels", "userRisk")):
        levels = c.get(field) or []
        if levels and (s.get(key) or "none") not in levels:
            return False, [f"the {key} level is not covered"], unsure
    for field, label in UNSUPPORTED.items():
        if c.get(field):
            unsure.append(label)
    why.append("all conditions match")
    return True, why, unsure


def _requirement(policy: dict) -> dict:
    g = policy.get("grantControls") or {}
    controls = list(g.get("builtInControls") or [])
    if g.get("authenticationStrength"):
        controls.append("authenticationStrength")
    if g.get("termsOfUse"):
        controls.append("termsOfUse")
    return {"operator": g.get("operator") or "OR", "controls": controls}


def evaluate(scenario: dict, policies: list[dict], locations: dict) -> dict:
    enforced, report_only, uncertain, skipped = [], [], [], []
    for pol in policies:
        state = pol.get("state")
        if state == "disabled":
            continue
        hit, why, unsure = applies(pol, scenario, locations)
        entry = {"policy": pol.get("displayName"), "state": state, "requires": _requirement(pol), "why": why, "uncertain": unsure}
        if unsure:
            uncertain.append(entry)
        if not hit:
            skipped.append(entry)
            continue
        (enforced if state == "enabled" else report_only).append(entry)
    controls = [e["requires"] for e in enforced]
    if any("block" in r["controls"] for r in controls):
        outcome = "blocked"
    elif controls:
        outcome = "allowed with conditions"
    else:
        outcome = "allowed without conditions"
    requirements = [r for r in controls if r["controls"]]
    strong = outcome == "blocked" or any(set(r["controls"]) & STRONG and (r["operator"] == "AND" or set(r["controls"]) <= STRONG)
                                         for r in requirements)
    user = scenario.get("user") or {}
    group_dependent = any(pol.get("conditions", {}).get("users", {}).get("includeGroups") for pol in policies if pol.get("state") != "disabled")
    confidence = "high"
    if uncertain:
        confidence = "medium"
    if group_dependent and "groups" not in user:
        confidence = "low"
    return {"outcome": outcome, "modelled": True, "requirements": requirements, "mfaOrBlock": strong,
            "applied": enforced, "reportOnly": report_only, "notApplied": skipped, "uncertain": uncertain, "confidence": confidence}


def _verdict(scenario: dict, result: dict) -> tuple[str, str]:
    expect = scenario.get("expect")
    if expect == "block":
        if result["outcome"] == "blocked":
            return "pass", "Blocked"
        if result["reportOnly"] and any("block" in e["requires"]["controls"] for e in result["reportOnly"]):
            return "gap", "Only a report-only policy would block this; turn it on"
        return "gap", "Nothing blocks this"
    if result["mfaOrBlock"]:
        return "pass", "MFA (or stronger) is required" if result["outcome"] != "blocked" else "Blocked"
    if result["reportOnly"] and any(set(e["requires"]["controls"]) & STRONG for e in result["reportOnly"]):
        return "gap", "Only a report-only policy would require MFA; turn it on"
    if result["outcome"] == "allowed with conditions":
        return "gap", "Allowed with conditions that can be met without MFA (an OR choice includes a weaker control)"
    return "gap", "No policy requires MFA"


def _inputs(snapshot: M365ConfigSnapshot) -> tuple[list[dict], dict]:
    res = snapshot.resources or {}
    if "conditionalAccess" not in res:
        raise ValueError("This backup has no Conditional Access policies"
                         + (f" ({snapshot.errors['conditionalAccess']})" if "conditionalAccess" in (snapshot.errors or {}) else ""))
    locations_by_name = {loc.get("displayName"): loc for loc in res.get("namedLocations", [])}
    ids = (snapshot.references or {}).get("locations", {})
    locations = {lid: locations_by_name[name] for lid, name in ids.items() if name in locations_by_name}
    return res["conditionalAccess"], locations


def run(db: Session, snapshot: M365ConfigSnapshot, scenarios: list[dict] | None, actor: str) -> M365CaSimulation:
    if not m365_config.verify(snapshot):
        raise ValueError("The configuration backup does not match its SHA-256")
    policies, locations = _inputs(snapshot)
    kind = "what-if" if scenarios else "gap-analysis"
    scenarios = scenarios or GAP_SCENARIOS
    results = []
    for s in scenarios:
        r = evaluate(s, policies, locations)
        if s.get("expect"):
            r["verdict"], r["reason"] = _verdict(s, r)
        results.append({"scenario": s.get("key") or s.get("title") or "scenario", "title": s.get("title", ""), **r})
    gaps = [r["scenario"] for r in results if r.get("verdict") == "gap"]
    summary = {"kind": "modelled", "scenarios": len(results), "gaps": gaps, "policies": len(policies),
               "confidence": min((r["confidence"] for r in results), key=["low", "medium", "high"].index, default="high")}
    sim = M365CaSimulation(tenant_id=snapshot.tenant_id, connection_id=snapshot.connection_id, snapshot_id=snapshot.id,
                           snapshot_digest=snapshot.digest, kind=kind, scenarios=scenarios, results=results, summary=summary, created_by=actor)
    db.add(sim)
    db.flush()
    audit.record(db, actor, "m365.ca_simulated", sim.id, snapshot.tenant_id, kind=kind, snapshotId=snapshot.id, gaps=gaps)
    return sim

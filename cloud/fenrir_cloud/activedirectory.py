"""Active Directory: what the domain controllers' agents report, turned into a per-domain view and findings.

Sources:
* the system profile every Windows agent sends (``role``: workstation / server / domain-controller, installed
  server roles; ``auditPolicy``; and on DCs ``activeDirectory``: domain, DCs, FSMO, privileged groups, risky
  accounts, password policy, LAPS, GPOs, trusts);
* live ``ad.*`` events from the DC agent's Security-log monitor (rules in rules/sigma/active_directory.yml).

Several DCs of one domain each report the same directory; the freshest snapshot wins and every DC is listed.
"""
from __future__ import annotations

from datetime import datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import presence
from .models import Alert, Device, DeviceProfile, Event, utcnow

ROLE_LABELS = {"domain-controller": "Domain controller", "server": "Server", "workstation": "Workstation"}
# Audit subcategories the AD detections depend on (GUIDs are locale-independent).
AUDIT_NEEDS = {
    "{0CCE9237-69AE-11D9-BED3-505054503030}": ("Security Group Management", "success", "privileged group changes"),
    "{0CCE9235-69AE-11D9-BED3-505054503030}": ("User Account Management", "success", "account creation, resets and lockouts"),
    "{0CCE9242-69AE-11D9-BED3-505054503030}": ("Kerberos Authentication Service", "both", "password spraying and AS-REP roasting"),
    "{0CCE9240-69AE-11D9-BED3-505054503030}": ("Kerberos Service Ticket Operations", "success", "Kerberoasting"),
    "{0CCE923F-69AE-11D9-BED3-505054503030}": ("Credential Validation", "failure", "NTLM password spraying"),
    "{0CCE923B-69AE-11D9-BED3-505054503030}": ("Directory Service Access", "success", "DCSync"),
    "{0CCE923C-69AE-11D9-BED3-505054503030}": ("Directory Service Changes", "success", "AdminSDHolder, delegation and GPO changes"),
}
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def role_from_profile(profile: dict) -> dict:
    """Device summary fields for lists and filters: kind, label, domain role, roles and workloads."""
    role = profile.get("role") if isinstance(profile.get("role"), dict) else {}
    kind = role.get("kind") if role.get("kind") in ROLE_LABELS else None
    if kind is None:
        name = str((profile.get("os") or {}).get("name") or "")
        kind = "server" if "server" in name.lower() else "workstation" if name else None
    if kind is None:
        return {}
    out = {"role": kind, "roleLabel": ROLE_LABELS[kind]}
    if role.get("domainRole"):
        out["domainRole"] = str(role["domainRole"])[:60]
    roles = [str(r)[:80] for r in (role.get("serverRoles") or []) if r][:40]
    workloads = [str(w)[:80] for w in (role.get("workloads") or []) if w][:40]
    if roles:
        out["serverRoles"] = roles
    if workloads:
        out["workloads"] = workloads
    return out


def _days(value) -> int | None:
    return int(value) if isinstance(value, (int, float)) and not isinstance(value, bool) else None


def _names(rows, key="sam") -> list[str]:
    return [str(r.get(key) or r.get("name") or "") for r in rows or [] if isinstance(r, dict)]


def assess(ad: dict, audit: list | None, dc_devices: int) -> list[dict]:
    """Security findings for one domain, most severe first. Each says what was found, why it matters and the fix."""
    findings: list[dict] = []

    def add(fid, severity, title, detail, fix, affected=None, mitre=None):
        findings.append({"id": fid, "severity": severity, "title": title, "detail": detail, "fix": fix,
                         "affected": [a for a in (affected or []) if a][:100], "count": len(affected or []), "mitre": mitre or []})

    risky = ad.get("risky") or {}
    groups = {g.get("label"): g for g in ad.get("privilegedGroups") or [] if isinstance(g, dict)}

    krbtgt_age = _days((ad.get("krbtgt") or {}).get("passwordAgeDays"))
    if krbtgt_age is not None and krbtgt_age > 180:
        add("krbtgt-old", "high" if krbtgt_age > 365 else "medium", f"krbtgt password is {krbtgt_age} days old",
            "Anyone who ever obtained the krbtgt hash can still forge Golden Tickets until it is changed twice.",
            "Reset the krbtgt password twice, at least 10 hours apart (Microsoft's New-KrbtgtKeys.ps1). Repeat every 180 days.",
            mitre=["T1558.001"])

    roast = [r for r in risky.get("kerberoastable") or [] if isinstance(r, dict)]
    if roast:
        privileged = [r for r in roast if r.get("privileged")]
        add("kerberoastable", "high" if privileged else "medium",
            f"{len(roast)} user account(s) with a service principal name (Kerberoastable)"
            + (f", {len(privileged)} privileged" if privileged else ""),
            "Any domain user can request a ticket for these accounts and crack the password offline.",
            "Use group Managed Service Accounts, or give each account a 25+ character random password and enable AES only "
            "(msDS-SupportedEncryptionTypes = 24). Remove SPNs that are no longer used.",
            _names(privileged) + _names([r for r in roast if not r.get("privileged")]), ["T1558.003"])

    if risky.get("asrepRoastable"):
        add("asrep", "high", f"{len(risky['asrepRoastable'])} account(s) do not require Kerberos pre-authentication",
            "Anyone on the network can request a ticket for these accounts and crack it offline (AS-REP roasting).",
            "Clear \"Do not require Kerberos preauthentication\" on each account.", _names(risky["asrepRoastable"]), ["T1558.004"])

    if risky.get("passwordNotRequired"):
        add("pwd-not-required", "high", f"{len(risky['passwordNotRequired'])} enabled account(s) may have an empty password",
            "PASSWD_NOTREQD lets the account have a blank password regardless of policy.",
            "Run Set-ADUser <name> -PasswordNotRequired $false and set a password.", _names(risky["passwordNotRequired"]), ["T1078.002"])

    if risky.get("reversibleEncryption"):
        add("reversible", "high", f"{len(risky['reversibleEncryption'])} account(s) store passwords with reversible encryption",
            "Their plain-text passwords can be recovered from the directory.",
            "Turn off \"Store password using reversible encryption\" and have the users change their passwords.",
            _names(risky["reversibleEncryption"]), ["T1003.006"])

    domain_admins = groups.get("Domain Admins") or {}
    if (domain_admins.get("memberCount") or 0) > 5:
        add("too-many-das", "medium", f"Domain Admins has {domain_admins['memberCount']} members",
            "Every Domain Admin is a full-domain compromise if their account or any machine they sign in to is breached.",
            "Keep Domain Admins to two or three named break-glass and tier-0 accounts; delegate everyday tasks with narrower groups.",
            _names(domain_admins.get("members")), ["T1078.002"])
    for label in ("Enterprise Admins", "Schema Admins"):
        group = groups.get(label) or {}
        if (group.get("memberCount") or 0) > 1:
            add(f"{label.lower().replace(' ', '-')}-members", "medium", f"{label} has {group['memberCount']} members",
                f"{label} should be empty except while forest-level changes are being made.",
                f"Remove members from {label} and add them back only for the change window.", _names(group.get("members")))
    for label in ("Account Operators", "Server Operators", "Print Operators", "Backup Operators", "DnsAdmins"):
        group = groups.get(label) or {}
        if group.get("memberCount"):
            add(f"{label.lower().replace(' ', '-')}-used", "medium", f"{label} has {group['memberCount']} member(s)",
                f"{label} members can take over domain controllers (for example by loading code or reading the NTDS.dit).",
                f"Empty {label}; grant the specific rights needed through delegation instead.", _names(group.get("members")),
                ["T1078.002"])

    if risky.get("privilegedPasswordNeverExpires"):
        add("priv-never-expires", "medium", f"{len(risky['privilegedPasswordNeverExpires'])} privileged account(s) have passwords that never expire",
            "A leaked admin password stays valid forever.",
            "Clear \"Password never expires\" or use a fine-grained policy with a long, rotated password.",
            _names(risky["privilegedPasswordNeverExpires"]))
    if risky.get("privilegedStale"):
        add("priv-stale", "medium", f"{len(risky['privilegedStale'])} privileged account(s) not used in 90 days",
            "Unused admin accounts are easy to take over unnoticed.", "Disable them or remove them from privileged groups.",
            _names(risky["privilegedStale"]))
    if risky.get("privilegedOldPassword"):
        add("priv-old-password", "low", f"{len(risky['privilegedOldPassword'])} privileged account(s) with a password older than a year",
            "Old admin passwords are more likely to be in a breach or a cracked-hash list.", "Rotate the passwords.",
            _names(risky["privilegedOldPassword"]))
    if risky.get("unconstrainedDelegation"):
        add("unconstrained", "high", f"{len(risky['unconstrainedDelegation'])} non-DC object(s) trusted for unconstrained delegation",
            "Anyone who controls these machines can capture the Kerberos tickets of every user that connects, including admins.",
            "Switch them to constrained or resource-based delegation, and add admins to Protected Users.",
            _names(risky["unconstrainedDelegation"]), ["T1558"])
    if risky.get("resourceBasedDelegation"):
        add("rbcd", "low", f"{len(risky['resourceBasedDelegation'])} computer(s) with resource-based constrained delegation",
            "Legitimate for some services; also a common persistence technique.", "Confirm each entry is expected.",
            _names(risky["resourceBasedDelegation"]), ["T1134"])
    if risky.get("sidHistory"):
        add("sid-history", "medium", f"{len(risky['sidHistory'])} account(s) carry SID history",
            "SID history left over from migrations can grant hidden privileges.", "Remove SID history once migrations are finished.",
            _names(risky["sidHistory"]), ["T1134.005"])
    if risky.get("adminCountOrphans"):
        add("admincount", "low", f"{len(risky['adminCountOrphans'])} account(s) still marked adminCount=1 but no longer privileged",
            "These keep the locked-down privileged permissions and are often forgotten former admins.",
            "Clear adminCount and re-enable permission inheritance on each account.", _names(risky["adminCountOrphans"]))
    stale_users = _days(risky.get("staleUsers")) or 0
    if stale_users >= 10:
        add("stale-users", "low", f"{stale_users} enabled user accounts not used in 90 days",
            "Dormant accounts are a common way in after a password leak.", "Disable accounts of leavers and review the rest.")
    if risky.get("unsupportedOs"):
        add("unsupported-os", "medium", f"{len(risky['unsupportedOs'])} computer(s) running an unsupported Windows version",
            "They no longer get security updates.", "Upgrade or isolate them.", _names(risky["unsupportedOs"], "name"))

    policy = ad.get("passwordPolicy") or {}
    min_length = _days(policy.get("minLength"))
    if min_length is not None and min_length < 12:
        add("pwd-length", "medium" if min_length < 8 else "low", f"Minimum password length is {min_length}",
            "Short passwords are guessed or cracked quickly.",
            "Set the Default Domain Policy minimum length to 14 (or 12 with MFA), or use a fine-grained policy.")
    if policy.get("lockoutThreshold") == 0:
        add("no-lockout", "medium", "Accounts never lock out after failed sign-ins",
            "Unlimited guessing makes password spraying and brute force easy.",
            "Set an account lockout threshold of 10 with a 15-minute lockout.", mitre=["T1110"])
    if policy.get("complexity") is False and (min_length or 0) < 14:
        add("no-complexity", "low", "Password complexity is off", "Simple passwords are allowed.",
            "Turn on complexity, or require 14+ character passphrases.")
    if policy.get("reversibleEncryption"):
        add("policy-reversible", "high", "The domain password policy stores passwords with reversible encryption",
            "Every user's plain-text password can be recovered from the directory.", "Turn off reversible encryption in the Default Domain Policy.")

    admin = ad.get("builtinAdministrator") or {}
    admin_age = _days(admin.get("passwordAgeDays"))
    if admin.get("enabled") and admin_age is not None and admin_age > 365:
        add("builtin-admin", "medium", f"The built-in Administrator account is enabled with a {admin_age}-day-old password",
            "It cannot be locked out, which makes it a favourite target.", "Disable it, or give it a long random password kept in a vault.")
    if ad.get("guestEnabled"):
        add("guest", "high", "The domain Guest account is enabled", "Anyone can sign in without a password.", "Disable the Guest account.")
    counts = ad.get("counts") or {}
    if counts.get("protectedUsers") == 0 and (domain_admins.get("memberCount") or 0) > 0:
        add("protected-users", "low", "No accounts are in Protected Users",
            "Protected Users stops admins' credentials being cached or delegated.",
            "Add the Domain Admins' named accounts (not service accounts) to Protected Users.")
    laps = ad.get("laps") or {}
    eligible = _days(laps.get("eligibleComputers")) or 0
    covered = _days(laps.get("coveredComputers")) or 0
    if eligible and not laps.get("legacySchema") and not laps.get("windowsSchema"):
        add("no-laps", "medium", "LAPS is not deployed",
            "Local administrator passwords are probably the same on many machines, so one compromise spreads.",
            "Deploy Windows LAPS (built into Windows since April 2023), or use Fenrir's local admin rotation.")
    elif eligible and covered < eligible * 0.9:
        add("laps-coverage", "low", f"LAPS manages {covered} of {eligible} computers",
            "Computers outside LAPS keep a static local administrator password.", "Apply the LAPS GPO to every computer OU.")
    if ad.get("recycleBin") is False:
        add("recycle-bin", "low", "The AD Recycle Bin is off", "Deleted users, groups and OUs cannot be restored with their attributes.",
            "Enable-ADOptionalFeature 'Recycle Bin Feature' -Scope ForestOrConfigurationSet -Target <forest>.")
    mode = str((ad.get("domain") or {}).get("mode") or "")
    if any(old in mode for old in ("2003", "2008", "2012")):
        add("functional-level", "low", f"Domain functional level is {mode}",
            "Older levels miss protections such as Protected Users and Kerberos armoring.", "Raise the functional level once all DCs are 2016 or later.")
    for trust in ad.get("trusts") or []:
        if isinstance(trust, dict) and trust.get("sidFilteringQuarantined") is False and str(trust.get("direction")) in ("Bidirectional", "Inbound") \
                and "External" in str(trust.get("type")):
            add(f"trust-{trust.get('name')}", "medium", f"External trust {trust.get('name')} without SID filtering",
                "The trusted domain could inject privileged SIDs.", "Enable SID filtering (netdom trust /quarantine:yes).")

    if audit is not None:
        by_guid = {str(a.get("guid") or "").upper(): a for a in audit if isinstance(a, dict)}
        missing = []
        for guid, (name, need, purpose) in AUDIT_NEEDS.items():
            row = by_guid.get(guid)
            ok = row is not None and (row.get("success") if need == "success" else row.get("failure") if need == "failure"
                                      else row.get("success") and row.get("failure"))
            if not ok:
                missing.append(f"{name} ({'success and failure' if need == 'both' else need}) - needed for {purpose}")
        if missing:
            add("audit-policy", "medium", f"{len(missing)} audit setting(s) Fenrir needs on the domain controllers are off",
                "Without them the domain controllers never write the events these detections read.",
                "Set them in the Default Domain Controllers Policy under Advanced Audit Policy Configuration, then gpupdate.", missing)

    listed = len(ad.get("domainControllers") or [])
    if listed and dc_devices < listed:
        add("dc-coverage", "high" if dc_devices == 0 else "medium", f"Fenrir is on {dc_devices} of {listed} domain controllers",
            "Attacks against a DC without the agent are invisible: each DC only logs what it handles.",
            "Install the Fenrir agent on every domain controller.")
    findings.sort(key=lambda f: (SEVERITY_ORDER.get(f["severity"], 9), f["title"]))
    return findings


def score(findings: list[dict]) -> int:
    """0-100, higher is healthier."""
    weights = {"critical": 25, "high": 12, "medium": 5, "low": 1}
    return max(0, 100 - sum(weights.get(f["severity"], 0) for f in findings))


def _dc_profiles(db: Session, tenant_ids: list[str]):
    rows = db.execute(select(Device, DeviceProfile).join(DeviceProfile, DeviceProfile.device_id == Device.id)
                      .where(Device.tenant_id.in_(tenant_ids))).all()
    for device, profile in rows:
        data = profile.profile or {}
        if ((data.get("role") or {}).get("kind") == "domain-controller") or isinstance(data.get("activeDirectory"), dict):
            yield device, profile, data


def domains(db: Session, tenant_ids: list[str]) -> list[dict]:
    """One entry per (tenant, AD domain) with the freshest snapshot and every DC that reports it."""
    grouped: dict[tuple[str, str], dict] = {}
    for device, profile, data in _dc_profiles(db, tenant_ids):
        ad = data.get("activeDirectory") if isinstance(data.get("activeDirectory"), dict) else None
        name = str(((ad or {}).get("domain") or {}).get("dnsName") or (data.get("role") or {}).get("domain") or "unknown").lower()
        entry = grouped.setdefault((device.tenant_id, name), {"tenantId": device.tenant_id, "domain": name, "snapshot": None,
                                                              "snapshotAt": None, "auditPolicy": None, "agents": []})
        online = presence.is_up(device)
        entry["agents"].append({"deviceId": device.id, "hostname": device.hostname, "online": online,
                                "lastSeen": device.last_seen_at.isoformat() + "Z" if device.last_seen_at else None,
                                "profileAt": profile.collected_at.isoformat() + "Z" if profile.collected_at else None,
                                "snapshot": ad is not None})
        if ad is not None and (entry["snapshotAt"] is None or (profile.collected_at and profile.collected_at > entry["snapshotAt"])):
            entry["snapshot"], entry["snapshotAt"], entry["auditPolicy"] = ad, profile.collected_at, data.get("auditPolicy")
    out = []
    for entry in grouped.values():
        ad = entry["snapshot"] or {}
        findings = assess(ad, entry["auditPolicy"], len(entry["agents"])) if ad else []
        entry["findings"] = findings
        entry["score"] = score(findings) if ad else None
        entry["snapshotAt"] = entry["snapshotAt"].isoformat() + "Z" if isinstance(entry["snapshotAt"], datetime) else None
        out.append(entry)
    return sorted(out, key=lambda e: (e["tenantId"], e["domain"]))


def recent_activity(db: Session, tenant_id: str, device_ids: list[str], days: int = 7, limit: int = 300) -> list[dict]:
    if not device_ids:
        return []
    since = utcnow() - timedelta(days=days)
    rows = db.execute(select(Event).where(Event.tenant_id == tenant_id, Event.device_id.in_(device_ids), Event.event_type.like("ad.%"),
                                          ~Event.event_type.like("ad.monitor.%"), Event.occurred_at >= since)
                      .order_by(Event.occurred_at.desc()).limit(limit)).scalars().all()
    keep = ("TargetUserName", "SubjectUserName", "MemberName", "memberDisplay", "privilegedGroup", "ServiceName", "IpAddress",
            "Workstation", "ObjectDN", "AttributeLDAPDisplayName", "domainController", "knownSyncAccount", "EventID")
    return [{"id": e.id, "at": e.occurred_at.isoformat() + "Z", "type": e.event_type, "summary": e.summary,
             "fields": {k: (e.fields or {}).get(k) for k in keep if (e.fields or {}).get(k) not in (None, "", "-")}} for e in rows]


def alerts(db: Session, tenant_id: str, device_ids: list[str], limit: int = 100) -> list[dict]:
    if not device_ids:
        return []
    rows = db.execute(select(Alert).where(Alert.tenant_id == tenant_id, Alert.device_id.in_(device_ids), Alert.rule_id.like("fenrir-ad-%"))
                      .order_by(Alert.created_at.desc()).limit(limit)).scalars().all()
    return [{"id": a.id, "title": a.title, "severity": a.severity, "status": a.status, "createdAt": a.created_at.isoformat() + "Z",
             "ruleId": a.rule_id, "mitre": a.mitre} for a in rows]

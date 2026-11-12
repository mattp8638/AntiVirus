"""Email security policies: what happens to each message, decided the way Microsoft Defender and Exchange do it.

A **policy set** is one document with five parts, kept for a scope: the MSP (a default for every customer) or one
customer (overrides the default). Every save is a new, numbered **version** with its author and comment; nothing is
ever edited in place, so any earlier version can be compared and restored.

- ``antispam``: score thresholds and an action per classification (bulk, spam, suspicious, phish, high-confidence
  phish), Microsoft's bulk level threshold, a subject prefix for tagged mail.
- ``antiphish``: impersonation protection (the customer's people, extra protected names and domains), lookalike
  sensitivity, honouring the sender's DMARC policy, a first-contact tag, and actions for each.
- ``antimalware``: blocked file types (editable), looking inside archives, password-protected archives, macros,
  zero-hour re-checks, and the action.
- ``connection`` (gateway): IP addresses and ranges always allowed or always blocked.
- ``rules``: mail flow rules like Exchange transport rules: conditions and exceptions, actions, priority, "stop
  processing more rules", and an audit mode that records what the rule would do without doing it.

Evaluation (``decide``), first match wins at each step and every step is recorded in the decision's trail:

1. Connection filter (gateway): blocked IP -> reject; allowed IP -> skip spam and phish checks.
2. Mail flow rules, in priority order.
3. Allow/block lists (the customer's and the MSP's).
4. Anti-malware: blocked file types (including inside archives), password-protected archives, macros, and the
   engine's malware findings (threat intel, ClamAV).
5. Anti-phishing: spoofing (failed DMARC on a domain with a quarantine/reject policy), impersonation, lookalikes.
6. Anti-spam: Fenrir's score bands and Microsoft's own spam and bulk verdicts.

Actions: ``deliver``, ``tag`` (subject prefix at the gateway, Outlook category in mailboxes), ``junk``,
``quarantine``, ``reject`` (gateway; in mailboxes it quarantines). ``bypass`` (rules only) skips spam and phishing
checks but never malware ones.
"""
from __future__ import annotations

import copy
import ipaddress
import re

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from . import email_security

ACTIONS = ("deliver", "tag", "junk", "quarantine", "reject")
CLASSES = ("malware", "highphish", "phish", "spoof", "impersonation", "suspicious", "spam", "bulk", "clean")
SEVERITY = {a: i for i, a in enumerate(ACTIONS)}  # a stronger action wins when rules and policies both apply

DEFAULT_BLOCKED_TYPES = sorted({*email_security.EXECUTABLE, *email_security.DISK_IMAGE, "ace", "arj", "cab", "lzh",
                                "uue", "xz", "z", "msc", "mst", "hlp", "ins", "isp", "jnlp", "ksh", "mde", "mdb",
                                "nsh", "ops", "pcd", "prg", "sct", "shb", "shs", "vb", "vxd", "ws", "wsc"})
ARCHIVES = {"zip", "7z", "rar", "gz", "tar", "tgz", "bz2", "xz", "cab", "iso", "img"}

PRESETS: dict[str, dict] = {
    "standard": {
        "antispam": {"suspiciousScore": 25, "phishScore": 50, "highPhishScore": 80, "bulkThreshold": 7,
                     "actions": {"bulk": "junk", "spam": "junk", "suspicious": "tag", "phish": "quarantine",
                                 "highphish": "quarantine"},
                     "subjectPrefix": "[Suspicious]"},
        "antiphish": {"protectPeople": True, "protectedNames": [], "protectedDomains": [], "lookalike": "standard",
                      "honourDmarc": True, "firstContactTag": True,
                      "actions": {"impersonation": "quarantine", "spoof": "quarantine"}},
        "antimalware": {"blockedTypes": DEFAULT_BLOCKED_TYPES, "scanArchives": True, "encryptedArchives": "quarantine",
                        "macros": "tag", "zeroHour": True, "action": "quarantine"},
        "connection": {"ipAllow": [], "ipBlock": []},
        "quarantine": {"userRelease": ["spam", "bulk", "suspicious"], "keepContent": "flagged"},
        "rules": [],
    },
}
PRESETS["strict"] = copy.deepcopy(PRESETS["standard"])
PRESETS["strict"]["antispam"].update(suspiciousScore=20, phishScore=40, highPhishScore=70, bulkThreshold=5,
                                     actions={"bulk": "quarantine", "spam": "quarantine", "suspicious": "junk",
                                              "phish": "quarantine", "highphish": "quarantine"})
PRESETS["strict"]["antiphish"].update(lookalike="strict", actions={"impersonation": "quarantine", "spoof": "quarantine"})
PRESETS["strict"]["antimalware"].update(macros="quarantine")
PRESETS["strict"]["quarantine"]["userRelease"] = ["bulk"]

RULE_FIELDS = {
    "sender": "Sender address", "senderDomain": "Sender domain", "recipient": "Recipient address",
    "recipientDomain": "Recipient domain", "subject": "Subject", "body": "Body text", "header": "Header (Name: value)",
    "attachmentName": "Attachment name", "attachmentType": "Attachment file type", "hasAttachment": "Has an attachment",
    "senderIp": "Sending IP address", "country": "Sending country (2 letters)", "sizeKb": "Message size (KB)",
    "spf": "SPF result", "dkim": "DKIM result", "dmarc": "DMARC result", "score": "Fenrir score",
    "verdict": "Fenrir verdict", "external": "From outside the organisation", "linkDomain": "Link goes to domain",
    "replyToDomain": "Reply-To domain",
}
OPERATORS = ("is", "isNot", "contains", "notContains", "startsWith", "endsWith", "matches", "in", "greaterThan",
             "lessThan", "inRange", "isTrue", "isFalse")
RULE_ACTIONS = ("quarantine", "reject", "junk", "deliver", "bypass", "tag", "addHeader", "addCategory", "score", "notify")
MAX_RULES = 200


class PolicyError(ValueError):
    pass


# --------------------------------------------------------------------------- validation

def _ip_or_range(value: str) -> str:
    try:
        return str(ipaddress.ip_network(value.strip(), strict=False))
    except ValueError:
        raise PolicyError(f"'{value}' is not an IP address or range (like 203.0.113.0/24)") from None


def _action(value, allowed=ACTIONS, where="") -> str:
    if value not in allowed:
        raise PolicyError(f"{where}: the action must be one of {', '.join(allowed)}")
    return value


def validate(document: dict) -> dict:
    """A clean copy of a policy document, with defaults filled in. Raises PolicyError explaining what is wrong."""
    if not isinstance(document, dict):
        raise PolicyError("The policy must be an object")
    base = copy.deepcopy(PRESETS["standard"])
    out: dict = {}
    spam = {**base["antispam"], **(document.get("antispam") or {})}
    for key, low, high in (("suspiciousScore", 1, 99), ("phishScore", 1, 100), ("highPhishScore", 1, 100), ("bulkThreshold", 1, 9)):
        try:
            spam[key] = int(spam[key])
        except (TypeError, ValueError):
            raise PolicyError(f"Anti-spam: {key} must be a number") from None
        if not low <= spam[key] <= high:
            raise PolicyError(f"Anti-spam: {key} must be between {low} and {high}")
    if not spam["suspiciousScore"] < spam["phishScore"] <= spam["highPhishScore"]:
        raise PolicyError("Anti-spam: the suspicious score must be below the phish score, and that at or below high confidence")
    spam["actions"] = {k: _action((spam.get("actions") or {}).get(k, base["antispam"]["actions"][k]), where=f"Anti-spam {k}")
                       for k in base["antispam"]["actions"]}
    spam["subjectPrefix"] = str(spam.get("subjectPrefix") or "")[:40]
    out["antispam"] = {k: spam[k] for k in base["antispam"]}

    phish = {**base["antiphish"], **(document.get("antiphish") or {})}
    phish["protectPeople"], phish["honourDmarc"], phish["firstContactTag"] = (bool(phish["protectPeople"]), bool(phish["honourDmarc"]),
                                                                              bool(phish["firstContactTag"]))
    phish["protectedNames"] = [str(n).strip()[:120] for n in phish.get("protectedNames") or [] if str(n).strip()][:500]
    phish["protectedDomains"] = [str(d).strip().lower().lstrip("@")[:253] for d in phish.get("protectedDomains") or [] if str(d).strip()][:500]
    if phish["lookalike"] not in ("off", "standard", "strict"):
        raise PolicyError("Anti-phishing: lookalike sensitivity must be off, standard or strict")
    phish["actions"] = {k: _action((phish.get("actions") or {}).get(k, base["antiphish"]["actions"][k]), where=f"Anti-phishing {k}")
                        for k in base["antiphish"]["actions"]}
    out["antiphish"] = {k: phish[k] for k in base["antiphish"]}

    malware = {**base["antimalware"], **(document.get("antimalware") or {})}
    types = malware.get("blockedTypes")
    if not isinstance(types, list):
        raise PolicyError("Anti-malware: blocked file types must be a list")
    malware["blockedTypes"] = sorted({re.sub(r"[^a-z0-9]", "", str(t).lower().lstrip(".")) for t in types} - {""})[:500]
    malware["scanArchives"], malware["zeroHour"] = bool(malware["scanArchives"]), bool(malware["zeroHour"])
    malware["action"] = _action(malware["action"], ("quarantine", "reject"), "Anti-malware")
    malware["encryptedArchives"] = _action(malware["encryptedArchives"], ("deliver", "tag", "junk", "quarantine", "reject"),
                                           "Anti-malware password-protected archives")
    malware["macros"] = _action(malware["macros"], ("deliver", "tag", "junk", "quarantine", "reject"), "Anti-malware macros")
    out["antimalware"] = {k: malware[k] for k in base["antimalware"]}

    connection = {**base["connection"], **(document.get("connection") or {})}
    out["connection"] = {"ipAllow": [_ip_or_range(v) for v in connection.get("ipAllow") or []][:1000],
                         "ipBlock": [_ip_or_range(v) for v in connection.get("ipBlock") or []][:1000]}

    quarantine = {**base["quarantine"], **(document.get("quarantine") or {})}
    quarantine["userRelease"] = [c for c in quarantine.get("userRelease") or [] if c in CLASSES and c != "malware"]
    if quarantine.get("keepContent") not in ("none", "flagged", "all"):
        raise PolicyError("Quarantine: keep message content must be none, flagged or all")
    out["quarantine"] = {k: quarantine[k] for k in base["quarantine"]}

    rules = document.get("rules") or []
    if not isinstance(rules, list) or len(rules) > MAX_RULES:
        raise PolicyError(f"Rules must be a list of at most {MAX_RULES}")
    out["rules"] = [_rule(r, i) for i, r in enumerate(rules)]
    out["rules"].sort(key=lambda r: r["priority"])
    return out


def _condition(c: dict, where: str) -> dict:
    field, op = str(c.get("field") or ""), str(c.get("operator") or "")
    if field not in RULE_FIELDS:
        raise PolicyError(f"{where}: unknown condition '{field}'")
    if op not in OPERATORS:
        raise PolicyError(f"{where}: unknown operator '{op}'")
    value = c.get("value", "")
    if op == "in":
        value = [str(v).strip()[:320] for v in (value if isinstance(value, list) else str(value).split(",")) if str(v).strip()][:500]
    elif op == "inRange":
        value = [_ip_or_range(v) for v in (value if isinstance(value, list) else str(value).split(",")) if str(v).strip()][:200]
    elif op == "matches":
        value = str(value)[:300]
        if re.search(r"\(\?[^:)]|\\[1-9]|(\+|\*|\})\s*(\+|\*|\{)|\([^)]*[+*}][^)]*\)\s*[+*{]", value):
            raise PolicyError(f"{where}: that pattern uses features not allowed in rules (back-references, nested repeats)")
        try:
            re.compile(value)
        except re.error as exc:
            raise PolicyError(f"{where}: the pattern is not valid ({exc})") from None
    elif op in ("greaterThan", "lessThan"):
        try:
            value = float(value)
        except (TypeError, ValueError):
            raise PolicyError(f"{where}: '{field}' needs a number") from None
    elif op in ("isTrue", "isFalse"):
        value = ""
    else:
        value = str(value).strip()[:500]
    return {"field": field, "operator": op, "value": value}


def _rule(r: dict, index: int) -> dict:
    if not isinstance(r, dict):
        raise PolicyError(f"Rule {index + 1} must be an object")
    name = str(r.get("name") or "").strip()[:120] or f"Rule {index + 1}"
    where = f"Rule '{name}'"
    conditions = [_condition(c, where) for c in r.get("conditions") or []][:30]
    if not conditions:
        raise PolicyError(f"{where}: add at least one condition")
    exceptions = [_condition(c, where + " (exception)") for c in r.get("exceptions") or []][:30]
    actions = []
    for a in r.get("actions") or []:
        kind = str((a or {}).get("type") or "")
        if kind not in RULE_ACTIONS:
            raise PolicyError(f"{where}: unknown action '{kind}'")
        value = (a or {}).get("value", "")
        if kind == "score":
            try:
                value = max(-100, min(100, int(value)))
            except (TypeError, ValueError):
                raise PolicyError(f"{where}: the score change must be a whole number") from None
        elif kind == "addHeader":
            value = str(value)[:300]
            if not re.match(r"^X-[A-Za-z0-9-]{1,60}:\s?[^\r\n]{0,200}$", value):
                raise PolicyError(f"{where}: headers must look like 'X-Name: value'")
        elif kind == "notify":
            value = str(value).strip()[:320]
            if "@" not in value:
                raise PolicyError(f"{where}: notify needs an email address")
        else:
            value = str(value)[:120]
        actions.append({"type": kind, "value": value})
    if not actions:
        raise PolicyError(f"{where}: add at least one action")
    return {"id": str(r.get("id") or f"rule-{index + 1}")[:40], "name": name, "enabled": bool(r.get("enabled", True)),
            "priority": int(r.get("priority", index)) if str(r.get("priority", index)).lstrip("-").isdigit() else index,
            "mode": "audit" if r.get("mode") == "audit" else "enforce", "match": "any" if r.get("match") == "any" else "all",
            "conditions": conditions, "exceptions": exceptions, "actions": actions, "stop": bool(r.get("stop", False)),
            "comment": str(r.get("comment") or "")[:300]}


# --------------------------------------------------------------------------- versions

def latest(db: Session, tenant_id: str):
    from .models import EmailPolicyVersion

    return db.execute(select(EmailPolicyVersion).where(EmailPolicyVersion.tenant_id == tenant_id)
                      .order_by(EmailPolicyVersion.version.desc()).limit(1)).scalar_one_or_none()


def resolve(db: Session, tenant_id: str) -> tuple[dict, dict]:
    """The policy that applies to a customer: its own latest version, else the nearest parent's (the MSP default),
    else the Standard preset. Returns (document, {"tenantId", "version", "inherited", "preset"})."""
    from .models import Tenant

    current, inherited = db.get(Tenant, tenant_id), False
    for _ in range(10):
        if current is None:
            break
        row = latest(db, current.id)
        if row is not None and not row.inherit:
            return row.document, {"tenantId": current.id, "version": row.version, "id": row.id, "inherited": inherited,
                                  "preset": row.preset}
        inherited = True
        current = db.get(Tenant, current.parent_id) if current.parent_id else None
    return copy.deepcopy(PRESETS["standard"]), {"tenantId": None, "version": 0, "id": None, "inherited": True, "preset": "standard"}


def save(db: Session, tenant_id: str, document: dict | None, actor: str, comment: str = "", preset: str = "",
         inherit: bool = False):
    """Store a new version. ``inherit`` makes the customer follow its parent's policy again."""
    from . import audit
    from .models import EmailPolicyVersion

    if preset:
        if preset not in PRESETS:
            raise PolicyError(f"Unknown preset '{preset}'")
        clean = copy.deepcopy(PRESETS[preset])
        if document and document.get("rules"):
            clean["rules"] = document["rules"]
        clean = validate(clean)
    else:
        clean = validate(document or {}) if not inherit else {}
    version = (db.execute(select(func.max(EmailPolicyVersion.version)).where(EmailPolicyVersion.tenant_id == tenant_id)).scalar() or 0) + 1
    row = EmailPolicyVersion(tenant_id=tenant_id, version=version, document=clean, inherit=inherit, preset=preset,
                             comment=str(comment or "")[:500], created_by=actor)
    db.add(row)
    db.flush()
    audit.record(db, actor, "email_security.policy_saved", row.id, tenant_id, version=version, inherit=inherit, preset=preset,
                 comment=row.comment)
    return row


def diff(old: dict, new: dict, path: str = "") -> list[dict]:
    """What changed between two documents: [{"path", "from", "to"}]."""
    changes = []
    if path == "rules" and isinstance(old or [], list) and isinstance(new or [], list):  # rule by rule, matched on id
        old, new = old or [], new or []
        before = {r.get("id"): r for r in old if isinstance(r, dict)}
        after = {r.get("id"): r for r in new if isinstance(r, dict)}
        for rule_id in [*before, *[i for i in after if i not in before]]:
            a, b = before.get(rule_id), after.get(rule_id)
            name = (b or a or {}).get("name") or rule_id
            if a is None:
                changes.append({"path": f"rules: {name}", "from": None, "to": "added"})
            elif b is None:
                changes.append({"path": f"rules: {name}", "from": "present", "to": "removed"})
            else:
                changes += diff(a, b, f"rules: {name}")
        return changes
    if isinstance(old, dict) and isinstance(new, dict):
        for key in sorted(set(old) | set(new)):
            changes += diff(old.get(key), new.get(key), f"{path}.{key}" if path else key)
    elif old != new:
        changes.append({"path": path, "from": old, "to": new})
    return changes


# --------------------------------------------------------------------------- evaluation

def _ext(name: str) -> str:
    return name.rsplit(".", 1)[-1].lower() if "." in (name or "") else ""


def _in_ranges(ip: str, ranges: list[str]) -> bool:
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for value in ranges:
        try:
            if address in ipaddress.ip_network(value, strict=False):
                return True
        except ValueError:
            continue
    return False


def facts(message: email_security.Message, result: dict, info: dict) -> dict:
    """Everything a rule can test, from the message, Fenrir's analysis and the evidence."""
    ms = result.get("microsoft") or {}
    details = info.get("details") or {}
    origin = details.get("origin") or {}
    names = [a.get("name") or "" for a in message.attachments]
    for a in message.attachments:
        names += list(a.get("members") or [])
    return {
        "sender": (message.sender_address or "").lower(), "senderDomain": result.get("sender_domain") or "",
        "recipient": [r.lower() for r in info.get("recipients") or [message.mailbox] if r],
        "recipientDomain": [email_security.domain_of(r) for r in info.get("recipients") or [message.mailbox] if r],
        "subject": message.subject or "", "body": email_security.plain_text(message.body_html),
        "headers": message.headers, "attachmentName": names,
        "attachmentType": [_ext(n) for n in names if _ext(n)], "hasAttachment": bool(message.attachments),
        "attachmentHash": [str(a.get("sha256") or "").lower() for a in message.attachments if a.get("sha256")],
        "senderIp": info.get("ip") or origin.get("ip") or "", "country": (origin.get("country") or ms.get("country") or "").upper(),
        "sizeKb": (info.get("size") or 0) / 1024, "spf": ms.get("spf") or "", "dkim": ms.get("dkim") or "",
        "dmarc": ms.get("dmarc") or "", "score": result.get("score") or 0, "verdict": result.get("verdict") or "",
        "external": result.get("sender_domain") not in info.get("ownDomains", set()),
        "linkDomain": result.get("link_domains") or [],
        "replyToDomain": [email_security.domain_of(r) for r in message.reply_to],
    }


def _test(c: dict, f: dict) -> bool:
    field, op, value = c["field"], c["operator"], c["value"]
    if field == "header":
        name, _, wanted = str(value).partition(":")
        actual = [str(f["headers"].get(name.strip().lower(), ""))]
        value = wanted.strip()
        if op in ("isTrue", "isFalse"):
            return (name.strip().lower() in f["headers"]) == (op == "isTrue")
    else:
        actual = f.get(field)
    if op in ("isTrue", "isFalse"):
        return bool(actual) == (op == "isTrue")
    if op in ("greaterThan", "lessThan"):
        try:
            number = float(actual or 0)
        except (TypeError, ValueError):
            return False
        return number > value if op == "greaterThan" else number < value
    if op == "inRange":
        return bool(actual) and _in_ranges(str(actual), value)
    values = actual if isinstance(actual, list) else [actual]
    values = [str(v).lower() for v in values if v is not None]
    if op == "in":
        wanted = {str(v).lower() for v in value}
        return any(v in wanted for v in values)
    needle = str(value).lower()
    if op == "is":
        return needle in values
    if op == "isNot":
        return needle not in values
    if op == "contains":
        return any(needle in v for v in values)
    if op == "notContains":
        return not any(needle in v for v in values)
    if op == "startsWith":
        return any(v.startswith(needle) for v in values)
    if op == "endsWith":
        return any(v.endswith(needle) for v in values)
    if op == "matches":
        pattern = re.compile(str(c["value"]), re.IGNORECASE)
        return any(pattern.search(v[:100_000]) for v in values)
    return False


def rule_matches(rule: dict, f: dict) -> bool:
    tests = [_test(c, f) for c in rule["conditions"]]
    hit = any(tests) if rule["match"] == "any" else all(tests)
    return hit and not any(_test(c, f) for c in rule["exceptions"])


def classify(result: dict, policy: dict, gateway: bool) -> tuple[str, str]:
    """(classification, why) from Fenrir's analysis under this policy's thresholds."""
    spam = policy["antispam"]
    codes = {r["code"] for r in result.get("reasons") or []}
    score, verdict = result.get("score") or 0, result.get("verdict")
    ms = result.get("microsoft") or {}
    if verdict == "malware":
        return "malware", "Fenrir found malware"
    dmarc_action = (ms.get("dmarcAction") or result.get("dmarcPolicy") or "").lower()
    if policy["antiphish"]["honourDmarc"] and ms.get("dmarc") == "fail" and dmarc_action in ("quarantine", "reject", "oreject"):
        return "spoof", "The sender's domain failed DMARC, and its DMARC policy says not to deliver"
    if codes & {"impersonation.colleague", "lookalike.own", "spoof.own-domain"} and score >= spam["suspiciousScore"]:
        return "impersonation", "Impersonates someone or a domain this customer protects"
    if score >= spam["highPhishScore"]:
        return "highphish", f"Score {score} is at or above the high-confidence phishing level ({spam['highPhishScore']})"
    if score >= spam["phishScore"]:
        return "phish", f"Score {score} is at or above the phishing level ({spam['phishScore']})"
    if not gateway and result.get("microsoft", {}).get("verdict") in ("phish", "malware"):
        return "phish", "Microsoft classified it as phishing"
    if score >= spam["suspiciousScore"]:
        return "suspicious", f"Score {score} is at or above the suspicious level ({spam['suspiciousScore']})"
    if not gateway and ms.get("verdict") == "spam":
        return "spam", "Microsoft classified it as spam"
    if (ms.get("bcl") or 0) >= spam["bulkThreshold"]:
        return "bulk", f"Bulk level {ms.get('bcl')} is at or above {spam['bulkThreshold']}"
    return "clean", "Nothing reached a policy threshold"


def decide(message: email_security.Message, result: dict, policy: dict, info: dict, meta: dict | None = None) -> dict:
    """The action for one message, with every step that led to it.

    ``info``: {"gateway": bool, "ip", "recipients", "size", "ownDomains", "lists": {...}, "details"}.
    Returns {"action", "classification", "decidedBy", "trail", "tag", "headers", "categories", "notify",
             "scoreChange", "audit": [rules in audit mode that matched], "policy": meta}.
    """
    gateway = bool(info.get("gateway"))
    trail: list[dict] = []
    out = {"action": "deliver", "classification": "clean", "decidedBy": "", "trail": trail, "tag": "", "headers": [],
           "categories": [], "notify": [], "scoreChange": 0, "audit": [], "policy": meta or {}, "userRelease": False}
    f = facts(message, result, info)
    ip = f["senderIp"]
    bypass_spam = False

    def step(source: str, detail: str, action: str | None = None) -> None:
        trail.append({"source": source, "detail": detail, **({"action": action} if action else {})})

    def settle(action: str, classification: str, by: str) -> dict:
        out.update(action=action if (gateway or action != "reject") else "quarantine", classification=classification, decidedBy=by)
        if action == "reject" and not gateway:
            step(by, "Reject is only possible at the gateway; quarantined instead", "quarantine")
        out["userRelease"] = classification in policy["quarantine"]["userRelease"]
        return out

    # 1. Connection filter (gateway only: mailboxes do not receive mail directly).
    if gateway and ip:
        if _in_ranges(ip, policy["connection"]["ipBlock"]):
            step("Connection filter", f"{ip} is on the blocked IP list", "reject")
            return settle("reject", "spam", "Connection filter: blocked IP")
        if _in_ranges(ip, policy["connection"]["ipAllow"]):
            step("Connection filter", f"{ip} is on the allowed IP list: spam and phishing checks skipped")
            bypass_spam = True

    # 2. Mail flow rules.
    forced: tuple[str, str] | None = None
    for rule in policy["rules"]:
        if not rule["enabled"] or not rule_matches(rule, f):
            continue
        actions = [a for a in rule["actions"]]
        label = f"Mail flow rule '{rule['name']}'"
        if rule["mode"] == "audit":
            out["audit"].append({"rule": rule["name"], "actions": actions})
            step(label + " (audit only)", "Matched; would have: " + ", ".join(a["type"] + (f" {a['value']}" if a["value"] not in ("", None) else "")
                                                                             for a in actions))
            continue
        step(label, "Matched")
        for a in actions:
            kind, value = a["type"], a["value"]
            if kind in ("quarantine", "reject", "junk", "deliver"):
                if forced is None or SEVERITY[kind] > SEVERITY[forced[0]]:
                    forced = (kind, label)
                step(label, f"Action: {kind}", kind)
            elif kind == "bypass":
                bypass_spam = True
                step(label, "Spam and phishing checks skipped (malware checks still apply)")
            elif kind == "tag":
                out["tag"] = value or policy["antispam"]["subjectPrefix"]
                out["categories"].append("Fenrir: " + (value.strip("[] ") or "tagged"))
            elif kind == "addHeader":
                out["headers"].append(value)
            elif kind == "addCategory":
                out["categories"].append(value or "Fenrir")
            elif kind == "score":
                out["scoreChange"] += value
                result = {**result, "score": max(0, min(100, (result.get("score") or 0) + value))}
                step(label, f"Score changed by {value:+d} to {result['score']}")
            elif kind == "notify":
                out["notify"].append(value)
        if rule["stop"]:
            step(label, "Stop processing more rules")
            break

    # 3. Allow and block lists (malware is never allowed through).
    lists = info.get("lists") or {}
    codes = {r["code"] for r in result.get("reasons") or []}
    listed_block = "list.block" in codes or any(_listed(lists, "block", k, f) for k in ("url", "hash", "ip", "subject"))
    listed_allow = ("list.allow" in codes or any(_listed(lists, "allow", k, f) for k in ("ip", "url"))) and "list.allow-ignored" not in codes

    # 4. Anti-malware.
    malware = policy["antimalware"]
    blocked_types = set(malware["blockedTypes"])
    for a in message.attachments:
        names = [a.get("name") or ""] + (list(a.get("members") or []) if malware["scanArchives"] else [])
        for name in names:
            if _ext(name) in blocked_types:
                inside = "" if name == a.get("name") else f" inside {a.get('name')}"
                step("Anti-malware policy", f"Blocked file type .{_ext(name)}: {name}{inside}", malware["action"])
                return settle(forced[0] if forced and SEVERITY[forced[0]] > SEVERITY[malware["action"]] else malware["action"],
                              "malware", "Anti-malware policy: blocked file type")
        if a.get("encrypted") and malware["encryptedArchives"] != "deliver":
            step("Anti-malware policy", f"{a.get('name')} is a password-protected archive Fenrir cannot look inside",
                 malware["encryptedArchives"])
            if malware["encryptedArchives"] == "tag":
                out["tag"] = out["tag"] or policy["antispam"]["subjectPrefix"]
            elif forced is None:
                return settle(malware["encryptedArchives"], "malware", "Anti-malware policy: password-protected archive")
    classification, why = classify({**result, "dmarcPolicy": info.get("dmarcPolicy", "")}, policy, gateway)
    if classification == "malware":
        step("Anti-malware policy", why, malware["action"])
        return settle(malware["action"], "malware", "Anti-malware policy")
    if "attachment.macro" in codes and malware["macros"] != "deliver" and forced is None:
        step("Anti-malware policy", "Office file with macros", malware["macros"])
        if malware["macros"] == "tag":
            out["tag"] = out["tag"] or policy["antispam"]["subjectPrefix"]
        else:
            return settle(malware["macros"], "suspicious", "Anti-malware policy: macros")

    if listed_block:
        step("Block list", "The sender, domain, IP, link, file or subject is on a block list", "quarantine")
        return settle(forced[0] if forced and SEVERITY[forced[0]] > SEVERITY["quarantine"] else "quarantine", "phish",
                      "Block list")
    if forced is not None:
        return settle(forced[0], classification if forced[0] != "deliver" else "clean", forced[1])
    if listed_allow or bypass_spam:
        step("Allow list" if listed_allow else "Bypass", "Spam and phishing checks skipped")
        return settle("tag" if out["tag"] else "deliver", "clean", "Allow list" if listed_allow else "Bypass")

    # 5. Anti-phishing.
    phish = policy["antiphish"]
    if classification == "spoof":
        step("Anti-phishing policy", why, phish["actions"]["spoof"])
        return settle(phish["actions"]["spoof"], "spoof", "Anti-phishing policy: spoofing")
    if classification == "impersonation":
        step("Anti-phishing policy", why, phish["actions"]["impersonation"])
        return settle(phish["actions"]["impersonation"], "impersonation", "Anti-phishing policy: impersonation")

    # 6. Anti-spam.
    if classification in policy["antispam"]["actions"]:
        action = policy["antispam"]["actions"][classification]
        step("Anti-spam policy", why, action)
        if action == "tag":
            out["tag"] = out["tag"] or policy["antispam"]["subjectPrefix"]
            out["categories"].append("Fenrir: " + classification)
        return settle(action, classification, f"Anti-spam policy: {classification}")
    if phish["firstContactTag"] and "sender.first-contact" in codes:
        out["categories"].append("Fenrir: first contact")
        step("Anti-phishing policy", "First message from this sender: tagged")
    step("Policy", why)
    return settle("tag" if out["tag"] else "deliver", "clean", "No policy matched")


def _listed(lists: dict, kind: str, what: str, f: dict) -> bool:
    entries = lists.get((kind, what)) or set()
    if not entries:
        return False
    if what == "ip":
        return bool(f["senderIp"]) and _in_ranges(f["senderIp"], list(entries))
    if what == "subject":
        subject = f["subject"].lower()
        return any(e in subject for e in entries)
    if what == "url":
        return any(any(e in d or d.endswith("." + e) for e in entries) for d in f["linkDomain"])
    if what == "hash":
        return any(h in entries for h in f["attachmentHash"])
    return False


def summary(decision: dict) -> str:
    return f"{decision['decidedBy']}: {decision['action']}" if decision.get("decidedBy") else decision.get("action", "")


def now_iso() -> str:
    from .models import utcnow

    return utcnow().isoformat() + "Z"

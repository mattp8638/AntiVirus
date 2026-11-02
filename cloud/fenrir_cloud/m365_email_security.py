"""Email security standards for Microsoft 365 (kind "email" in m365_standards.py).

Fixed by Fenrir when a standard is set to remediate (through Exchange Online's admin endpoint, m365_exchange.py):
``email.dkim``             DKIM signing on for every custom domain (Microsoft refuses until the domain's two DKIM CNAME
                           records exist; the drift detail lists the records to publish).
``email.anti-phishing``    The default anti-phishing policy uses spoof intelligence, shows first-contact safety tips and
                           honours senders' DMARC policies.
``email.malware-attachments``  The default malware filter blocks common dangerous attachment types.

Checked and reported (alerting on drift; nothing Fenrir can safely switch on for you):
``email.safe-links`` / ``email.safe-attachments``  Defender for Office 365 Safe Links / Safe Attachments policies are
                           on (needs Defender for Office 365 Plan 1, in Business Premium; turn on the Standard preset
                           security policy in Microsoft Defender > Email & collaboration > Policies).
``email.spf-dmarc``        Every custom domain publishes SPF including Microsoft 365 and a DMARC policy of quarantine or
                           reject (public DNS, outside Microsoft 365: the detail gives the records to publish).
"""
from __future__ import annotations

import dns.exception
import dns.resolver

from . import m365, m365_exchange

STANDARDS = {
    "email.dkim": {"title": "DKIM signing on for every domain", "fixable": True},
    "email.anti-phishing": {"title": "Anti-phishing: spoof intelligence, safety tips and DMARC honoured", "fixable": True},
    "email.malware-attachments": {"title": "Malware filter blocks dangerous attachment types", "fixable": True},
    "email.safe-links": {"title": "Safe Links on (Defender for Office 365)", "fixable": False},
    "email.safe-attachments": {"title": "Safe Attachments on (Defender for Office 365)", "fixable": False},
    "email.spf-dmarc": {"title": "SPF and DMARC published for every domain", "fixable": False},
}
ANTIPHISH_DEFAULT = "Office365 AntiPhish Default"
ANTIPHISH_WANTED = {"EnableSpoofIntelligence": True, "EnableFirstContactSafetyTips": True, "HonorDmarcPolicy": True}
NOT_FIXABLE = ("Fenrir checks this but does not change it for you: ")


class EmailStandardError(Exception):
    pass


def _exo(connection, cmdlet: str, params: dict | None = None) -> list[dict]:
    try:
        with m365_exchange.session(connection) as (client, token):
            return m365_exchange.invoke(client, connection, token, cmdlet, params or {})
    except m365_exchange.ExchangeError as exc:
        raise EmailStandardError(str(exc)) from None


def _custom_domains(connection) -> list[str]:
    import httpx

    with httpx.Client(timeout=20) as client:
        token = m365.access_token(client, connection)
        response = client.get(m365.GRAPH + "/domains", headers={"Authorization": "Bearer " + token})
        if response.status_code >= 400:
            raise EmailStandardError(f"Could not list the tenant's domains (HTTP {response.status_code}).")
        rows = response.json().get("value") or []
    return sorted(d["id"] for d in rows if d.get("isVerified") and not str(d.get("id", "")).endswith(".onmicrosoft.com")
                  and "Email" in (d.get("supportedServices") or ["Email"]))


def _txt(name: str) -> list[str]:
    try:
        return [b"".join(r.strings).decode("utf-8", errors="replace") for r in dns.resolver.resolve(name, "TXT", lifetime=5)]
    except (dns.exception.DNSException, OSError):
        return []


def evaluate(connection, standard: str) -> dict:
    if standard == "email.dkim":
        rows = [r for r in _exo(connection, "Get-DkimSigningConfig") if not str(r.get("Domain", "")).endswith(".onmicrosoft.com")]
        off = [r for r in rows if not r.get("Enabled")]
        if not off:
            return {"status": "compliant", "detail": f"DKIM is on for {len(rows)} domain(s)."}
        records = "; ".join(f"selector1._domainkey.{r['Domain']} CNAME {r.get('Selector1CNAME')}, selector2._domainkey.{r['Domain']} "
                            f"CNAME {r.get('Selector2CNAME')}" for r in off[:5] if r.get("Selector1CNAME"))
        return {"status": "drifted", "detail": f"DKIM is off for {', '.join(r['Domain'] for r in off)}."
                + (f" Publish these CNAME records first: {records}." if records else "")}
    if standard == "email.anti-phishing":
        [policy] = _exo(connection, "Get-AntiPhishPolicy", {"Identity": ANTIPHISH_DEFAULT}) or [{}]
        wrong = [k for k, v in ANTIPHISH_WANTED.items() if policy.get(k) is not v]
        return {"status": "drifted" if wrong else "compliant",
                "detail": ("Not set in the default anti-phishing policy: " + ", ".join(wrong)) if wrong else "Default anti-phishing policy as recommended."}
    if standard == "email.malware-attachments":
        [policy] = _exo(connection, "Get-MalwareFilterPolicy", {"Identity": "Default"}) or [{}]
        return ({"status": "compliant", "detail": "Common attachment types are blocked."} if policy.get("EnableFileFilter")
                else {"status": "drifted", "detail": "The default malware filter does not block common dangerous attachment types."})
    if standard in ("email.safe-links", "email.safe-attachments"):
        cmdlet = "Get-SafeLinksPolicy" if standard == "email.safe-links" else "Get-SafeAttachmentPolicy"
        try:
            policies = _exo(connection, cmdlet)
        except EmailStandardError as exc:
            if "not recognized" in str(exc).lower() or "isn't recognized" in str(exc).lower():
                return {"status": "drifted", "detail": "This tenant has no Defender for Office 365 (Plan 1 or Business Premium needed)."}
            raise
        enabled = [p for p in policies if p.get("EnableSafeLinksForEmail") or p.get("Enable")]
        name = "Safe Links" if standard == "email.safe-links" else "Safe Attachments"
        return ({"status": "compliant", "detail": f"{name} policy on: {enabled[0].get('Name')}."} if enabled
                else {"status": "drifted", "detail": NOT_FIXABLE + f"no {name} policy is on. Turn on the Standard preset security "
                      "policy in Microsoft Defender > Email & collaboration > Policies & rules > Threat policies > Preset security policies."})
    if standard == "email.spf-dmarc":
        problems = []
        for domain in _custom_domains(connection)[:20]:
            spf = [t for t in _txt(domain) if t.lower().startswith("v=spf1")]
            if not spf:
                problems.append(f"{domain}: no SPF (publish TXT \"v=spf1 include:spf.protection.outlook.com -all\")")
            elif "spf.protection.outlook.com" not in spf[0].lower():
                problems.append(f"{domain}: SPF does not include spf.protection.outlook.com")
            dmarc = [t for t in _txt(f"_dmarc.{domain}") if t.lower().startswith("v=dmarc1")]
            policy = next((p.split("=", 1)[1].strip().lower() for p in (dmarc[0].split(";") if dmarc else []) if p.strip().lower().startswith("p=")), "")
            if not dmarc:
                problems.append(f"{domain}: no DMARC (publish TXT at _dmarc.{domain}: \"v=DMARC1; p=quarantine; rua=mailto:dmarc@{domain}\")")
            elif policy not in ("quarantine", "reject"):
                problems.append(f"{domain}: DMARC policy is p={policy or 'none'} (use quarantine or reject once reports look clean)")
        return {"status": "drifted" if problems else "compliant", "detail": "; ".join(problems) or "SPF and DMARC are published for every domain."}
    raise EmailStandardError("Unknown email standard.")


def deploy(connection, standard: str) -> dict:
    if not STANDARDS[standard]["fixable"]:
        raise EmailStandardError(NOT_FIXABLE + evaluate(connection, standard)["detail"])
    if standard == "email.dkim":
        rows = [r for r in _exo(connection, "Get-DkimSigningConfig") if not str(r.get("Domain", "")).endswith(".onmicrosoft.com")]
        done, failed = [], []
        for row in [r for r in rows if not r.get("Enabled")]:
            try:
                _exo(connection, "Set-DkimSigningConfig", {"Identity": row["Domain"], "Enabled": True})
                done.append(row["Domain"])
            except EmailStandardError as exc:
                failed.append(f"{row['Domain']}: {str(exc)[:150]}")
        if failed:
            raise EmailStandardError("DKIM could not be turned on for " + "; ".join(failed) + " (publish the domain's DKIM CNAME records first).")
        return {"action": "updated", "setting": "DKIM on for " + (", ".join(done) or "every domain")}
    if standard == "email.anti-phishing":
        _exo(connection, "Set-AntiPhishPolicy", {"Identity": ANTIPHISH_DEFAULT, **ANTIPHISH_WANTED})
    elif standard == "email.malware-attachments":
        _exo(connection, "Set-MalwareFilterPolicy", {"Identity": "Default", "EnableFileFilter": True})
    after = evaluate(connection, standard)
    if after["status"] != "compliant":
        raise EmailStandardError("Exchange accepted the change but the setting still reads as before: " + after["detail"])
    return {"action": "updated", "setting": STANDARDS[standard]["title"]}

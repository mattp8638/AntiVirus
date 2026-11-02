# core/reconnaissance/phishing_for_info/phishing_for_info.py
from __future__ import annotations

from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence

import dns.exception
import dns.resolver

from logging_config import get_logger

logger = get_logger(__name__)


TxtResolver = Callable[[str, str], Sequence[Any]]
BreachLookup = Callable[[str], Iterable[Dict[str, Any]]]
CatchAllChecker = Callable[[str], bool]


def _normalise_txt_record(record: Any) -> str:
    """Return a best-effort normalised string for a TXT record."""

    if record is None:
        return ""

    text = ""
    # dnspython ``TXT`` answers expose ``strings`` with the individual chunks.
    strings = getattr(record, "strings", None)
    if strings:
        try:
            text = b"".join(strings).decode("utf-8")
        except Exception:  # pragma: no cover - extremely defensive
            text = "".join(s.decode("utf-8", "ignore") if isinstance(s, bytes) else str(s) for s in strings)
    else:
        to_text = getattr(record, "to_text", None)
        if callable(to_text):
            text = to_text()
        else:
            text = str(record)

    return text.strip().strip('"')


def _resolve_txt_records(domain: str, resolver: Optional[dns.resolver.Resolver]) -> List[str]:
    """Resolve TXT records using the provided resolver."""

    if not domain:
        return []

    active_resolver = resolver or dns.resolver.Resolver()  # pragma: no cover - uses system resolver in prod

    try:
        answers = active_resolver.resolve(domain, "TXT")
    except (dns.exception.DNSException, OSError):
        return []

    return [_normalise_txt_record(record) for record in answers]


def _extract_spf_policy(records: Sequence[str]) -> Optional[str]:
    for record in records:
        if record.lower().startswith("v=spf1"):
            return record
    return None


def _extract_dmarc_policy(records: Sequence[str]) -> Optional[str]:
    for record in records:
        if record.lower().startswith("v=dmarc1"):
            return record
    return None


def _analyse_spf(spf: Optional[str], domain: str) -> str:
    if not spf:
        return f"{domain}: SPF record missing – spoofing much easier."

    policy = spf.lower()
    if "-all" in policy:
        return f"{domain}: SPF is restrictive (-all)."

    if "~all" in policy:
        return f"{domain}: SPF is soft-fail (~all); consider -all."

    return f"{domain}: SPF present but enforcement unclear."


def _analyse_dmarc(dmarc: Optional[str], domain: str) -> str:
    if not dmarc:
        return f"{domain}: DMARC record missing – spoofed messages may be accepted."

    policy = dmarc.lower()
    if "p=reject" in policy:
        return f"{domain}: DMARC policy enforces reject."

    if "p=quarantine" in policy:
        return f"{domain}: DMARC policy quarantines suspicious mail."

    return f"{domain}: DMARC policy allows spoofing (p=none)."


def _analyse_catch_all(domain: str, catch_all: Optional[bool]) -> str:
    if catch_all is None:
        return f"{domain}: Catch-all inbox status unknown."

    if catch_all:
        return f"{domain}: Catch-all inbox detected – targeted aliases likely to succeed."

    return f"{domain}: No catch-all inbox detected."


def _load_breach_records(
    domain: str,
    breach_lookup: Optional[BreachLookup] = None,
    breach_dataset: Optional[Iterable[Dict[str, Any]]] = None,
) -> List[Dict[str, Any]]:
    exposures: List[Dict[str, Any]] = []

    if callable(breach_lookup):
        try:
            exposures.extend(breach_lookup(domain) or [])
        except Exception as exc:  # pragma: no cover - defensive logging only
            logger.warning("Breach lookup failed for %s: %s", domain, exc)

    for record in breach_dataset or []:
        email = str(record.get("email", "")).lower()
        if email.endswith(f"@{domain.lower()}"):
            exposures.append(record)

    unified: Dict[str, Dict[str, Any]] = {}
    for record in exposures:
        email = str(record.get("email", "")).lower()
        if not email:
            continue

        base = unified.setdefault(email, {"email": email, "breaches": []})

        breaches = record.get("breaches")
        if isinstance(breaches, (list, tuple, set)):
            existing = set(base.get("breaches", []))
            existing.update(str(breach) for breach in breaches if isinstance(breach, str))
            base["breaches"] = sorted(existing)

        for key, value in record.items():
            if key in {"email", "breaches"}:
                continue
            base.setdefault(key, value)

    return list(unified.values())


def _summarise_targets(exposures: Sequence[Dict[str, Any]]) -> List[str]:
    targets = sorted({str(record.get("email", "")) for record in exposures if record.get("email")})
    return targets or ["No direct breach-derived targets identified."]


def _summarise_themes(domain: str, exposures: Sequence[Dict[str, Any]], catch_all: Optional[bool]) -> List[str]:
    themes: List[str] = []

    breach_themes = {
        breach
        for record in exposures
        for breach in record.get("breaches", [])
        if isinstance(breach, str)
    }

    for breach in sorted(breach_themes):
        themes.append(f"Credential phishing leveraging {breach} notifications.")

    if catch_all:
        themes.append(f"Spray-and-pray campaigns using arbitrary aliases at {domain}.")

    if not themes:
        themes.append(f"General phishing lures targeting {domain} staff.")

    return themes


def phishing_for_info(
    target_domain: Optional[str] = None,
    *,
    resolver: Optional[dns.resolver.Resolver] = None,
    breach_lookup: Optional[BreachLookup] = None,
    breach_dataset: Optional[Iterable[Dict[str, Any]]] = None,
    catch_all_checker: Optional[CatchAllChecker] = None,
) -> Dict[str, Any]:
    """Collect phishing-related intelligence for a domain."""

    domain = (target_domain or "").lower()
    logger.info("Gathering phishing-related info for %s", domain or "general assessment")

    spf_records = _resolve_txt_records(domain, resolver)
    dmarc_records = _resolve_txt_records(f"_dmarc.{domain}" if domain else "", resolver)

    spf_policy = _extract_spf_policy(spf_records)
    dmarc_policy = _extract_dmarc_policy(dmarc_records)

    catch_all: Optional[bool] = None
    if callable(catch_all_checker) and domain:
        try:
            catch_all = bool(catch_all_checker(domain))
        except Exception as exc:  # pragma: no cover - defensive logging only
            logger.warning("Catch-all detection failed for %s: %s", domain, exc)

    exposures = _load_breach_records(domain, breach_lookup, breach_dataset)

    targets = _summarise_targets(exposures)
    themes = _summarise_themes(domain or "the organisation", exposures, catch_all)

    vulnerabilities = [
        _analyse_spf(spf_policy, domain or "the organisation"),
        _analyse_dmarc(dmarc_policy, domain or "the organisation"),
        _analyse_catch_all(domain or "the organisation", catch_all),
    ]

    summary = {
        "domain": domain or None,
        "potential_targets": targets,
        "common_themes": themes,
        "domain_vulnerabilities": vulnerabilities,
    }

    logger.info("Phishing info gathering finished for %s", domain or "general assessment")
    return summary

if __name__ == '__main__':
    info = phishing_for_info("example.com")
    logger.info("Phishing-Related Information (Placeholder):")
    for key, value in info.items():
        logger.info(f"  {key}: {value}")

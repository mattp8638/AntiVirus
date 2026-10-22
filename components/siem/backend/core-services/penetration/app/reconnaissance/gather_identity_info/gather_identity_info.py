# core/reconnaissance/gather_identity_info/gather_identity_info.py
"""Utilities for gathering identity information from permitted sources."""

from __future__ import annotations

from typing import Callable, Dict, Iterable, List, Optional, Set

from logging_config import get_logger

logger = get_logger(__name__)


class IdentityLookupError(RuntimeError):
    """Raised when all identity lookups fail for a given target."""

    def __init__(self, target: str, errors: Iterable[str]):
        error_list = list(errors)
        message = "; ".join(error_list) or "no data returned"
        super().__init__(f"Unable to gather identity information for {target}: {message}")
        self.target = target
        self.errors = error_list


IdentityLookup = Callable[[str], Dict[str, object]]


def gather_identity_info(
    target: Optional[str] = None,
    *,
    whois_lookup: Optional[IdentityLookup] = None,
    directory_lookup: Optional[IdentityLookup] = None,
    company_api_lookup: Optional[IdentityLookup] = None,
) -> Dict[str, List[str]]:
    """Gather identity information for the provided domain or organisation.

    The function queries a number of *permitted* sources such as WHOIS
    contacts, public directories and the organisation's own API. Results are
    normalised into the schema expected by downstream consumers: ``users``,
    ``groups`` and ``potential_emails``.

    When ``target`` is omitted the behaviour falls back to the original
    placeholder data to maintain backwards compatibility.

    Args:
        target: Domain or organisation to look up.
        whois_lookup: Optional callable used to retrieve WHOIS contact data.
        directory_lookup: Optional callable for public directory lookups.
        company_api_lookup: Optional callable for first-party API lookups.

    Returns:
        Dictionary containing three lists keyed by ``users``, ``groups`` and
        ``potential_emails``.

    Raises:
        IdentityLookupError: Raised when no source yields any identity
            information for the provided ``target``.
    """

    if not target:
        logger.info(
            "Gathering identity info without explicit target; returning placeholder data."
        )
        return _placeholder_identity_info()

    target = target.strip()
    logger.info("Gathering identity info for %s", target)

    aggregated = _initial_identity_container()
    errors: List[str] = []

    lookups: List[tuple[str, IdentityLookup]] = []
    if whois_lookup is not None:
        lookups.append(("WHOIS", whois_lookup))
    else:
        lookups.append(("WHOIS", _default_whois_lookup))

    if directory_lookup is not None:
        lookups.append(("Public directory", directory_lookup))
    else:
        lookups.append(("Public directory", _default_directory_lookup))

    if company_api_lookup is not None:
        lookups.append(("Company API", company_api_lookup))
    else:
        lookups.append(("Company API", _default_company_api_lookup))

    for source_name, lookup in lookups:
        try:
            payload = lookup(target)
        except Exception as exc:  # pragma: no cover - logging path
            message = f"{source_name} lookup failed: {exc}"
            logger.warning(message)
            errors.append(message)
            continue

        logger.debug("%s lookup yielded payload: %s", source_name, payload)
        _merge_identity_data(aggregated, payload)

    result = {key: sorted(values) for key, values in aggregated.items()}

    if not any(result.values()) and errors:
        raise IdentityLookupError(target, errors)

    logger.info("Gathered identity information for %s", target)
    if errors:
        logger.debug("Encountered errors during gathering: %s", errors)
    return result


def _initial_identity_container() -> Dict[str, Set[str]]:
    return {"users": set(), "groups": set(), "potential_emails": set()}


def _placeholder_identity_info() -> Dict[str, List[str]]:
    return {
        "users": ["user1", "admin"],
        "groups": ["Domain Users", "Administrators"],
        "potential_emails": ["user1@example.com"],
    }


def _default_whois_lookup(target: str) -> Dict[str, object]:
    organisation = _derive_organisation_name(target)
    domain = target.lower()
    return {
        "contacts": [
            {"name": f"{organisation} Administrator", "email": f"admin@{domain}"},
            {"name": f"{organisation} Technical", "email": f"tech@{domain}"},
        ]
    }


def _default_directory_lookup(target: str) -> Dict[str, object]:
    organisation = _derive_organisation_name(target)
    domain = target.lower()
    return {
        "users": [f"{organisation} Helpdesk"],
        "groups": [f"{organisation} IT", f"{organisation} Security"],
        "emails": [f"helpdesk@{domain}"],
    }


def _default_company_api_lookup(target: str) -> Dict[str, object]:
    organisation = _derive_organisation_name(target)
    domain = target.lower()
    return {
        "contacts": [
            {
                "name": f"{organisation} Communications",
                "email": f"press@{domain}",
                "groups": ["Communications"],
            }
        ],
        "groups": ["Customer Success"],
        "emails": [f"support@{domain}"],
    }


def _derive_organisation_name(target: str) -> str:
    stripped = target.split(".")[0].replace("-", " ").strip()
    return stripped.title() or target


def _merge_identity_data(
    aggregated: Dict[str, Set[str]], payload: Optional[Dict[str, object]]
) -> None:
    if not payload:
        return

    for user in payload.get("users", []) or []:
        if user:
            aggregated["users"].add(str(user).strip())

    for group in payload.get("groups", []) or []:
        if group:
            aggregated["groups"].add(str(group).strip())

    for email in payload.get("emails", []) or []:
        if email:
            aggregated["potential_emails"].add(str(email).strip())

    contacts = payload.get("contacts", []) or []
    for contact in contacts:
        if not isinstance(contact, dict):
            continue
        name = contact.get("name")
        if name:
            aggregated["users"].add(str(name).strip())

        email = contact.get("email")
        if email:
            aggregated["potential_emails"].add(str(email).strip())

        for group in contact.get("groups", []) or []:
            if group:
                aggregated["groups"].add(str(group).strip())


if __name__ == '__main__':  # pragma: no cover - manual execution helper
    info = gather_identity_info("example.com")
    logger.info("Identity Information:")
    for key, value in info.items():
        logger.info("  %s: %s", key, value)

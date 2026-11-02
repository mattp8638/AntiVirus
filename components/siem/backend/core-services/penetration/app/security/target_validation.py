"""Utilities for validating requested targets against approved scopes."""

from __future__ import annotations

import fnmatch
import ipaddress
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Sequence, Tuple, Union

from database.models import ApprovedTarget


Network = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]


@dataclass(frozen=True)
class NormalisedApprovedTarget:
    """Representation of an approved target after normalisation."""

    label: str
    raw_value: str
    target_type: str
    network: Optional[Network]
    domain_pattern: Optional[str]


class TargetAuthorizationError(RuntimeError):
    """Raised when a requested target does not match the approved scope."""

    def __init__(self, errors: Sequence[str], rejected_targets: Sequence[Dict[str, str]]):
        message = "; ".join(errors)
        super().__init__(message)
        self.errors = list(errors)
        self.rejected_targets = list(rejected_targets)


def load_approved_targets() -> List[ApprovedTarget]:
    """Return all configured approved targets."""

    return ApprovedTarget.query.order_by(ApprovedTarget.id).all()


def _determine_target_type(entry: ApprovedTarget) -> str:
    explicit_type = (getattr(entry, 'target_type', '') or '').strip().lower()
    if explicit_type in {'cidr', 'network', 'subnet'}:
        return 'network'
    if explicit_type in {'ip', 'host'}:
        return 'ip'
    if explicit_type in {'domain', 'hostname'}:
        return 'domain'
    if explicit_type:
        return explicit_type
    return ''


def normalise_approved_targets(entries: Iterable[ApprovedTarget]) -> List[NormalisedApprovedTarget]:
    """Convert raw approved targets into a uniform representation."""

    normalised: List[NormalisedApprovedTarget] = []
    for entry in entries:
        raw_value = (getattr(entry, 'target_value', '') or '').strip()
        if not raw_value:
            continue
        label = (getattr(entry, 'label', '') or '').strip() or raw_value
        declared_type = _determine_target_type(entry)
        network: Optional[Network] = None
        domain_pattern: Optional[str] = None

        candidate_value = raw_value
        if declared_type in {'network', 'ip', 'cidr', 'subnet'}:
            try:
                network = ipaddress.ip_network(candidate_value, strict=False)
                target_type = 'network'
            except ValueError:
                target_type = 'domain'
                domain_pattern = candidate_value.lower()
        elif declared_type == 'domain':
            target_type = 'domain'
            domain_pattern = candidate_value.lower()
        else:
            try:
                network = ipaddress.ip_network(candidate_value, strict=False)
                target_type = 'network'
            except ValueError:
                target_type = 'domain'
                domain_pattern = candidate_value.lower()

        if network is None and domain_pattern is None:
            # Fallback to raw string matching
            domain_pattern = candidate_value.lower()
            target_type = 'domain'

        normalised.append(
            NormalisedApprovedTarget(
                label=label,
                raw_value=raw_value,
                target_type=target_type,
                network=network,
                domain_pattern=domain_pattern,
            )
        )

    return normalised


def _ip_candidate_is_authorised(
    candidate: Network,
    approved_entries: Sequence[NormalisedApprovedTarget],
) -> bool:
    for entry in approved_entries:
        if entry.network is None:
            continue
        try:
            if candidate.subnet_of(entry.network):
                return True
        except AttributeError:
            # Python <3.7 compatibility fallback; compare via supernet
            if entry.network.supernet_of(candidate):  # pragma: no cover - defensive
                return True
    return False


def _domain_candidate_is_authorised(
    candidate: str, approved_entries: Sequence[NormalisedApprovedTarget]
) -> bool:
    candidate_normalised = candidate.lower().rstrip('.')
    for entry in approved_entries:
        if not entry.domain_pattern:
            continue
        pattern = entry.domain_pattern.rstrip('.')
        if '*' in pattern:
            if fnmatch.fnmatch(candidate_normalised, pattern):
                return True
        elif candidate_normalised == pattern:
            return True
    return False


def validate_targets(
    targets: Dict[str, Optional[str]],
    *,
    phase_name: Optional[str] = None,
    normalised_entries: Optional[Sequence[NormalisedApprovedTarget]] = None,
    approved_entries: Optional[Iterable[ApprovedTarget]] = None,
) -> Tuple[bool, List[str], List[Dict[str, str]]]:
    """Validate *targets* against the approved configuration.

    Returns a tuple ``(is_valid, errors, rejected_targets)`` where ``errors`` is a
    list of human readable messages and ``rejected_targets`` contains metadata
    about each rejected target.
    """

    if normalised_entries is None:
        entries = approved_entries if approved_entries is not None else load_approved_targets()
        normalised_entries = normalise_approved_targets(entries)

    errors: List[str] = []
    rejected: List[Dict[str, str]] = []

    if not normalised_entries:
        requested = {key: value for key, value in targets.items() if value}
        if requested:
            for key, value in requested.items():
                reason = (
                    "No approved targets are configured; cannot authorise "
                    f"{key.replace('_', ' ')} '{value}'"
                )
                if phase_name:
                    reason += f" for phase '{phase_name}'"
                errors.append(reason)
                rejected.append(
                    {
                        'field': key,
                        'value': value,
                        'reason': reason,
                        'phase': phase_name or '',
                    }
                )
        return (not errors, errors, rejected)

    for field, value in targets.items():
        if not value:
            continue
        candidate_value = value.strip()
        if not candidate_value:
            continue

        try:
            network_candidate = ipaddress.ip_network(candidate_value, strict=False)
        except ValueError:
            network_candidate = None

        authorised = False
        if network_candidate is not None:
            authorised = _ip_candidate_is_authorised(network_candidate, normalised_entries)
        else:
            authorised = _domain_candidate_is_authorised(candidate_value, normalised_entries)

        if not authorised:
            reason = (
                f"Target '{candidate_value}' ({field.replace('_', ' ')}) is not within the approved scope"
            )
            if phase_name:
                reason += f" for phase '{phase_name}'"
            errors.append(reason)
            rejected.append(
                {
                    'field': field,
                    'value': candidate_value,
                    'reason': reason,
                    'phase': phase_name or '',
                }
            )

    return (not errors, errors, rejected)


def ensure_targets_authorized(
    phase_name: str,
    targets: Dict[str, Optional[str]],
    *,
    normalised_entries: Optional[Sequence[NormalisedApprovedTarget]] = None,
    approved_entries: Optional[Iterable[ApprovedTarget]] = None,
) -> Sequence[NormalisedApprovedTarget]:
    """Ensure that *targets* are authorised for *phase_name*.

    Raises :class:`TargetAuthorizationError` if validation fails and returns the
    normalised approved entries otherwise. When ``normalised_entries`` is
    provided, it will be reused to avoid reprocessing.
    """

    normalised = normalised_entries
    if normalised is None:
        entries = approved_entries if approved_entries is not None else load_approved_targets()
        normalised = normalise_approved_targets(entries)

    is_valid, errors, rejected = validate_targets(
        targets,
        phase_name=phase_name,
        normalised_entries=normalised,
    )
    if not is_valid:
        raise TargetAuthorizationError(errors, rejected)
    return normalised


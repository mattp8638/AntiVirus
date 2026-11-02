"""Transport security enforcement helpers.

Transport is the only network boundary. It verifies that mTLS headers are
present (as supplied by the TLS terminator) and forwards only validated
requests to core-services.
"""
from __future__ import annotations

from typing import Optional

from fastapi import HTTPException, status


def enforce_transport_identity(
    client_identity: Optional[str],
    client_cert_fingerprint: Optional[str],
) -> None:
    """Ensure transport-supplied identity headers are present."""
    if not client_identity or not client_cert_fingerprint:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="missing_transport_identity",
        )


def enforce_mtls_only(mtls_state: Optional[str]) -> None:
    """Require mTLS termination to be flagged by the edge proxy."""
    if not mtls_state or mtls_state.lower() != "success":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="mtls_required",
        )


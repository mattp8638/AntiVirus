"""Transport gateway entry point.

The transport layer is the only component permitted to perform network I/O.
It validates transport headers and proxies signed hello payloads to the
identity service.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

import httpx
from fastapi import Depends, FastAPI, Header, HTTPException, Request, status
from fastapi.responses import JSONResponse
from pydantic import ValidationError

from .config import Settings, load_settings
from .models import (
    HelloRequest,
    HelloResponse,
    HardwareInventory,
    OsInventory,
    SoftwareInventory,
    LocalUsersInventory,
    LocalGroupsInventory,
    EventBatch,
)
from .security import enforce_mtls_only, enforce_transport_identity
from .trust import enforce_trusted_fingerprint, parse_fingerprints

app = FastAPI(title="Transport Gateway", version="0.1.0")


def get_settings() -> Settings:
    """Dependency to load settings once per request."""
    return load_settings()


async def enforce_https(request: Request) -> None:
    """Reject non-HTTPS requests.

    Transport terminates TLS at the edge proxy and forwards HTTPS headers.
    """
    # Allow CORS preflight requests to pass through without HTTPS enforcement
    if request.method == "OPTIONS":
        return None
    forwarded_proto = request.headers.get("x-forwarded-proto", "http")
    if forwarded_proto.lower() != "https":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="https_required",
        )


@app.get("/health", response_class=JSONResponse)
async def health_check(settings: Settings = Depends(get_settings)) -> dict:
    """Simple health endpoint for load balancers."""
    return {
        "status": "ok",
        "service": settings.service_name,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.post("/mtls/hello", response_model=HelloResponse)
async def mtls_hello(
    payload: HelloRequest,
    settings: Settings = Depends(get_settings),
    signature: Optional[str] = Header(None, alias="X-Request-Signature"),
    timestamp: Optional[str] = Header(None, alias="X-Request-Timestamp"),
    client_identity: Optional[str] = Header(None, alias="X-Client-Identity"),
    client_cert_fingerprint: Optional[str] = Header(
        None, alias="X-Client-Cert-Sha256"
    ),
    mtls_state: Optional[str] = Header(None, alias="X-Client-MTLS"),
    _: None = Depends(enforce_https),
) -> HelloResponse:
    """Validate transport headers and proxy the hello to identity."""
    enforce_transport_identity(client_identity, client_cert_fingerprint)
    enforce_mtls_only(mtls_state)
    trust_store = parse_fingerprints(settings.trusted_fingerprints)
    enforce_trusted_fingerprint(trust_store, client_cert_fingerprint)

    if not signature or not timestamp:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="missing_signature_headers",
        )

    async with httpx.AsyncClient(timeout=settings.request_timeout_seconds) as client:
        response = await client.post(
            f"{settings.identity_service_url}/hello",
            json=payload.model_dump(),
            headers={
                "X-Request-Signature": signature,
                "X-Request-Timestamp": timestamp,
                "X-Client-Identity": client_identity,
                "X-Client-Cert-Sha256": client_cert_fingerprint,
                "X-Forwarded-Proto": "https",
            },
        )

    if response.status_code >= 400:
        raise HTTPException(
            status_code=response.status_code,
            detail=response.json().get("detail", "identity_error"),
        )

    return HelloResponse(**response.json())


async def _forward_inventory(path: str, payload: dict, settings: Settings) -> dict:
    async with httpx.AsyncClient(timeout=settings.request_timeout_seconds) as client:
        response = await client.post(
            f"{settings.ingestion_service_url}{path}",
            json=payload,
            headers={"X-Forwarded-Proto": "https"},
        )

    if response.status_code >= 400:
        raise HTTPException(
            status_code=response.status_code,
            detail=response.json().get("detail", "ingestion_error"),
        )
    return response.json()


async def _forward_event_batch(
    raw_body: bytes,
    settings: Settings,
    signature: str,
    timestamp: str,
    client_identity: str | None,
    client_cert_fingerprint: str | None,
) -> dict:
    headers = {
        "X-Forwarded-Proto": "https",
        "X-Request-Signature": signature,
        "X-Request-Timestamp": timestamp,
    }
    if client_identity:
        headers["X-Client-Identity"] = client_identity
    if client_cert_fingerprint:
        headers["X-Client-Cert-Sha256"] = client_cert_fingerprint

    async with httpx.AsyncClient(timeout=settings.request_timeout_seconds) as client:
        response = await client.post(
            f"{settings.ingestion_service_url}/events",
            content=raw_body,
            headers=headers,
        )

    if response.status_code >= 400:
        raise HTTPException(
            status_code=response.status_code,
            detail=response.json().get("detail", "ingestion_error"),
        )
    return response.json()


async def _forward_penetration_get(path: str, settings: Settings) -> dict:
    async with httpx.AsyncClient(timeout=settings.request_timeout_seconds) as client:
        response = await client.get(
            f"{settings.penetration_service_url}{path}",
            headers={"X-Forwarded-Proto": "https"},
        )

    if response.status_code >= 400:
        raise HTTPException(
            status_code=response.status_code,
            detail=response.json().get("detail", "penetration_error"),
        )
    return response.json()


@app.get("/penetration/tests", response_class=JSONResponse)
async def penetration_tests(
    settings: Settings = Depends(get_settings),
    _: None = Depends(enforce_https),
) -> dict:
    return await _forward_penetration_get("/tests", settings)


@app.get("/penetration/tests/{test_id}", response_class=JSONResponse)
async def penetration_test_detail(
    test_id: str,
    settings: Settings = Depends(get_settings),
    _: None = Depends(enforce_https),
) -> dict:
    return await _forward_penetration_get(f"/tests/{test_id}", settings)


@app.post("/mtls/inventory/hardware", response_class=JSONResponse)
async def mtls_inventory_hardware(
    payload: HardwareInventory,
    settings: Settings = Depends(get_settings),
    _: None = Depends(enforce_https),
) -> dict:
    return await _forward_inventory("/inventory/hardware", payload.model_dump(), settings)


@app.post("/mtls/inventory/os", response_class=JSONResponse)
async def mtls_inventory_os(
    payload: OsInventory,
    settings: Settings = Depends(get_settings),
    _: None = Depends(enforce_https),
) -> dict:
    return await _forward_inventory("/inventory/os", payload.model_dump(), settings)


@app.post("/mtls/inventory/software", response_class=JSONResponse)
async def mtls_inventory_software(
    payload: SoftwareInventory,
    settings: Settings = Depends(get_settings),
    _: None = Depends(enforce_https),
) -> dict:
    return await _forward_inventory("/inventory/software", payload.model_dump(), settings)


@app.post("/mtls/inventory/users", response_class=JSONResponse)
async def mtls_inventory_users(
    payload: LocalUsersInventory,
    settings: Settings = Depends(get_settings),
    _: None = Depends(enforce_https),
) -> dict:
    return await _forward_inventory("/inventory/users", payload.model_dump(), settings)


@app.post("/mtls/inventory/groups", response_class=JSONResponse)
async def mtls_inventory_groups(
    payload: LocalGroupsInventory,
    settings: Settings = Depends(get_settings),
    _: None = Depends(enforce_https),
) -> dict:
    return await _forward_inventory("/inventory/groups", payload.model_dump(), settings)


@app.post("/mtls/events", response_class=JSONResponse)
async def mtls_events(
    request: Request,
    settings: Settings = Depends(get_settings),
    signature: Optional[str] = Header(None, alias="X-Request-Signature"),
    timestamp: Optional[str] = Header(None, alias="X-Request-Timestamp"),
    client_identity: Optional[str] = Header(None, alias="X-Client-Identity"),
    client_cert_fingerprint: Optional[str] = Header(
        None, alias="X-Client-Cert-Sha256"
    ),
    mtls_state: Optional[str] = Header(None, alias="X-Client-MTLS"),
    _: None = Depends(enforce_https),
) -> dict:
    enforce_transport_identity(client_identity, client_cert_fingerprint)
    enforce_mtls_only(mtls_state)
    trust_store = parse_fingerprints(settings.trusted_fingerprints)
    enforce_trusted_fingerprint(trust_store, client_cert_fingerprint)

    if not signature or not timestamp:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="missing_signature_headers",
        )

    raw_body = await request.body()
    try:
        EventBatch.model_validate_json(raw_body)
    except ValidationError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="invalid_payload",
        ) from exc

    return await _forward_event_batch(
        raw_body=raw_body,
        settings=settings,
        signature=signature,
        timestamp=timestamp,
        client_identity=client_identity,
        client_cert_fingerprint=client_cert_fingerprint,
    )

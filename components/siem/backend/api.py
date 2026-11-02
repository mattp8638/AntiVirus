"""API gateway for UI-to-core-service routing.

This lightweight proxy unifies frontend calls behind a single origin,
reducing CORS preflight traffic and keeping service URLs centralised.
"""
from __future__ import annotations

from typing import Dict
import os

import httpx
from fastapi import FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response


def _load_service_urls() -> Dict[str, str]:
    """Load service base URLs from environment with safe defaults."""
    return {
        "identity": os.environ.get("API_IDENTITY_URL", "http://localhost:8085"),
        "patch": os.environ.get("API_PATCH_URL", "http://localhost:8082"),
        "penetration": os.environ.get("API_PENETRATION_URL", "http://localhost:8083"),
        "psa": os.environ.get("API_PSA_URL", "http://localhost:8001"),
        "rmm": os.environ.get("API_RMM_URL", "http://localhost:8020"),
        "detection": os.environ.get("API_DETECTION_URL", "http://localhost:8030"),
        "vulnerability": os.environ.get("API_VULNERABILITY_URL", "http://localhost:8004"),
        "compliance": os.environ.get("API_COMPLIANCE_URL", "http://localhost:8031"),
        "auditing": os.environ.get("API_AUDITING_URL", "http://localhost:8010"),
        "siem": os.environ.get("API_SIEM_URL", "http://localhost:8002"),
    }


app = FastAPI(title="Tamsilcms API Gateway", version="0.1.0")

cors_origins = tuple(
    origin.strip()
    for origin in os.environ.get(
        "API_CORS_ORIGINS",
        "http://localhost:5173,http://127.0.0.1:5173",
    ).split(",")
    if origin.strip()
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)


@app.get("/health", response_class=JSONResponse)
async def health_check() -> dict[str, str]:
    """Simple health endpoint for load balancers."""
    return {"status": "ok", "service": "api-gateway"}


async def _proxy_request(service: str, request: Request) -> Response:
    services = _load_service_urls()
    base_url = services.get(service)
    if not base_url:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="unknown_service",
        )

    path = request.path_params.get("path", "")
    upstream_url = f"{base_url.rstrip('/')}/{path}".rstrip("/")
    if request.url.query:
        upstream_url = f"{upstream_url}?{request.url.query}"

    headers = {
        key: value
        for key, value in request.headers.items()
        if key.lower() not in {"host", "content-length"}
    }
    headers.setdefault("X-Forwarded-Proto", "https")
    service_api_key = os.environ.get(f"API_{service.upper()}_API_KEY")
    if service_api_key and "X-API-Key" not in headers:
        headers["X-API-Key"] = service_api_key

    body = await request.body()

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            upstream_response = await client.request(
                method=request.method,
                url=upstream_url,
                headers=headers,
                content=body or None,
            )
    except httpx.RequestError:
        return JSONResponse(
            status_code=status.HTTP_502_BAD_GATEWAY,
            content={
                "detail": "upstream_unreachable",
                "service": service,
                "upstream_url": upstream_url,
            },
        )

    response_headers: Dict[str, str] = {}
    content_type = upstream_response.headers.get("content-type")
    if content_type:
        response_headers["content-type"] = content_type

    return Response(
        content=upstream_response.content,
        status_code=upstream_response.status_code,
        headers=response_headers,
    )


@app.api_route(
    "/api/{service}/{path:path}",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
)
async def proxy_service(service: str, request: Request) -> Response:
    """Proxy UI requests to the appropriate backend service."""
    return await _proxy_request(service, request)

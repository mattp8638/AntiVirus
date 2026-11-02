"""Pydantic models shared with identity for the hello pipeline."""
from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Union

from pydantic import BaseModel, Field


class HelloRequest(BaseModel):
    """Signed hello payload emitted by agents via the transport layer."""

    tenant_id: str = Field(..., min_length=8, max_length=64)
    asset_id: str = Field(..., min_length=8, max_length=64)
    identity_id: str = Field(..., min_length=8, max_length=64)
    event_id: str = Field(..., min_length=8, max_length=64)
    agent_version: str = Field(..., min_length=1, max_length=32)
    hostname: str = Field(..., min_length=1, max_length=255)
    os: str = Field(..., min_length=1, max_length=64)
    uptime_seconds: int = Field(..., ge=0)
    trust_state: str = Field(..., min_length=1, max_length=32)
    sent_at: datetime


class HelloResponse(BaseModel):
    """Response returned by identity service."""

    status: str
    received_at: datetime
    service: str


class InventoryBase(BaseModel):
    tenant_id: str = Field(..., min_length=8, max_length=64)
    asset_id: str = Field(..., min_length=8, max_length=64)
    collected_at: datetime
    hostname: str | None = None


class HardwareInventory(InventoryBase):
    manufacturer: str | None = None
    model: str | None = None
    serial_number: str | None = None
    cpu_model: str | None = None
    cpu_cores: int | None = None
    memory_mb: int | None = None
    storage_gb: int | None = None


class OsInventory(InventoryBase):
    os_name: str = Field(..., min_length=1, max_length=64)
    os_version: str = Field(..., min_length=1, max_length=64)
    kernel_version: str | None = None
    architecture: str | None = None
    install_date: str | None = None


class SoftwareItem(BaseModel):
    name: str = Field(..., min_length=1, max_length=128)
    vendor: str | None = None
    version: str | None = None
    install_date: str | None = None
    source: str | None = None


class SoftwareInventory(InventoryBase):
    items: list[SoftwareItem]


class LocalUser(BaseModel):
    username: str = Field(..., min_length=1, max_length=64)
    display_name: str | None = None
    uid: str | None = None
    is_admin: bool = False
    last_login_at: datetime | None = None


class LocalUsersInventory(InventoryBase):
    users: list[LocalUser]


class LocalGroup(BaseModel):
    name: str = Field(..., min_length=1, max_length=64)
    gid: str | None = None
    members: list[str] = Field(default_factory=list)


class LocalGroupsInventory(InventoryBase):
    groups: list[LocalGroup]


EventPayloadValue = Any  # use Any to avoid implicit recursive type aliases which Pydantic cannot resolve reliably


class EventEnvelope(BaseModel):
    event_id: str = Field(..., min_length=8, max_length=64)
    event_type: str = Field(..., min_length=3, max_length=80)
    event_category: str = Field(..., min_length=3, max_length=32)
    timestamp_local: datetime
    sequence_number: int = Field(..., ge=0)
    source_module: str = Field(..., min_length=3, max_length=64)
    severity: str = Field(default="info", min_length=3, max_length=16)
    payload: Dict[str, EventPayloadValue]
    payload_hash: str = Field(..., min_length=32, max_length=128)


class EventBatch(BaseModel):
    payload_id: str = Field(..., min_length=8, max_length=64)
    tenant_id: str = Field(..., min_length=8, max_length=64)
    asset_id: str = Field(..., min_length=8, max_length=64)
    collected_at: datetime
    schema_version: str = Field(default="v1", max_length=16)
    events: list[EventEnvelope]

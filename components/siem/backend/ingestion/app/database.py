"""Database connection helpers for the ingestion service."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Optional
from uuid import UUID

import asyncpg

from .config import Settings
from .models import (
    AssetInventoryOverview,
    AssetInventoryStats,
    AssetRecord,
    AssetStateResponse,
    EventBatch,
    EventClockDrift,
    EventGapReport,
    EventIngestLogRecord,
    EventRecord,
    EventTimeline,
    HardwareInventory,
    InventorySnapshot,
    LocalGroupsInventory,
    LocalUsersInventory,
    OsInventory,
    SoftwareInventory,
    TelemetryBaseline,
    TelemetryMetricSummary,
    TelemetryPayload,
    TelemetrySeries,
    TelemetrySample,
    TelemetryAnomaly,
)
from .storage import InventoryStore


async def create_pool(settings: Settings) -> asyncpg.Pool:
    """Create and validate an asyncpg pool for ingestion storage."""
    pool = await asyncpg.create_pool(
        dsn=settings.database_dsn,
        min_size=settings.database_min_connections,
        max_size=settings.database_max_connections,
    )
    async with pool.acquire() as connection:
        await connection.execute("SELECT 1")
    return pool


@dataclass(slots=True)
class IngestionDatabase:
    """Facade that coordinates PostgreSQL reads and writes for ingestion."""

    pool: asyncpg.Pool
    store: InventoryStore

    async def close(self) -> None:
        await self.pool.close()

    async def upsert_hardware(self, payload: HardwareInventory) -> None:
        await self.store.upsert_hardware(payload)

    async def upsert_os(self, payload: OsInventory) -> None:
        await self.store.upsert_os(payload)

    async def upsert_software(self, payload: SoftwareInventory) -> None:
        await self.store.upsert_software(payload)

    async def upsert_users(self, payload: LocalUsersInventory) -> None:
        await self.store.upsert_users(payload)

    async def upsert_groups(self, payload: LocalGroupsInventory) -> None:
        await self.store.upsert_groups(payload)

    async def ingest_telemetry(
        self,
        payload: TelemetryPayload,
        samples: list[TelemetrySample],
        baseline_window: int,
        anomaly_threshold: float,
    ) -> None:
        await self.store.ingest_telemetry(
            payload=payload,
            samples=samples,
            baseline_window=baseline_window,
            anomaly_threshold=anomaly_threshold,
        )

    async def record_telemetry_rejection(
        self,
        payload_id: UUID,
        tenant_id: str,
        asset_id: str,
        reason: str,
    ) -> None:
        await self.store.record_telemetry_rejection(
            payload_id=payload_id,
            tenant_id=tenant_id,
            asset_id=asset_id,
            reason=reason,
        )

    async def list_telemetry_metrics(self, asset_id: str) -> list[TelemetryMetricSummary]:
        return await self.store.list_telemetry_metrics(asset_id)

    async def get_telemetry_series(
        self,
        asset_id: str,
        metric_name: str,
        since: datetime | None,
        until: datetime | None,
        limit: int,
    ) -> TelemetrySeries:
        return await self.store.get_telemetry_series(
            asset_id=asset_id,
            metric_name=metric_name,
            since=since,
            until=until,
            limit=limit,
        )

    async def list_telemetry_baselines(self, asset_id: str) -> list[TelemetryBaseline]:
        return await self.store.list_telemetry_baselines(asset_id)

    async def list_telemetry_anomalies(
        self,
        asset_id: str,
        status: str | None,
        since: datetime | None,
        limit: int,
    ) -> list[TelemetryAnomaly]:
        return await self.store.list_telemetry_anomalies(
            asset_id=asset_id,
            status=status,
            since=since,
            limit=limit,
        )

    async def event_payload_exists(self, payload_id: UUID) -> bool:
        return await self.store.event_payload_exists(payload_id)

    async def record_event_batch_log(
        self,
        payload_id: UUID,
        tenant_id: str,
        asset_id: str,
        status: str,
        signature: str | None,
        signature_verified: bool,
        event_count: int,
        accepted_count: int,
        rejected_count: int,
        reject_reason: str | None,
        schema_version: str,
    ) -> None:
        await self.store.record_event_batch_log(
            payload_id=payload_id,
            tenant_id=tenant_id,
            asset_id=asset_id,
            status=status,
            signature=signature,
            signature_verified=signature_verified,
            event_count=event_count,
            accepted_count=accepted_count,
            rejected_count=rejected_count,
            reject_reason=reject_reason,
            schema_version=schema_version,
        )

    async def ingest_event_batch(
        self,
        batch: EventBatch,
        signature: str | None,
        signature_verified: bool,
    ) -> tuple[list[EventGapReport], list[EventClockDrift], int, int]:
        return await self.store.ingest_event_batch(
            batch=batch,
            signature=signature,
            signature_verified=signature_verified,
        )

    async def list_recent_events(
        self,
        tenant_id: Optional[str],
        limit: int,
        since: Optional[datetime],
        event_category: Optional[str],
        event_type: Optional[str],
    ) -> list[EventRecord]:
        return await self.store.list_recent_events(
            tenant_id=tenant_id,
            limit=limit,
            since=since,
            event_category=event_category,
            event_type=event_type,
        )

    async def get_event(self, event_id: UUID) -> Optional[EventRecord]:
        return await self.store.get_event(event_id)

    async def get_asset_timeline(self, asset_id: str, limit: int) -> EventTimeline:
        return await self.store.get_asset_timeline(asset_id=asset_id, limit=limit)

    async def list_event_gaps(self, asset_id: str, limit: int) -> list[EventGapReport]:
        return await self.store.list_event_gaps(asset_id=asset_id, limit=limit)

    async def list_event_drifts(self, asset_id: str, limit: int) -> list[EventClockDrift]:
        return await self.store.list_event_drifts(asset_id=asset_id, limit=limit)

    async def list_event_ingest_logs(
        self,
        tenant_id: Optional[str],
        asset_id: Optional[str],
        limit: int,
    ) -> list[EventIngestLogRecord]:
        return await self.store.list_event_ingest_logs(
            tenant_id=tenant_id,
            asset_id=asset_id,
            limit=limit,
        )

    async def snapshot(self, asset_id: str) -> InventorySnapshot:
        return await self.store.snapshot(asset_id)

    async def list_assets(
        self,
        tenant_id: Optional[str],
        limit: int,
        offset: int,
        since: datetime | None,
    ) -> list[AssetRecord]:
        return await self.store.list_assets(
            tenant_id=tenant_id,
            limit=limit,
            offset=offset,
            since=since,
        )

    async def list_assets_page(
        self,
        tenant_id: Optional[str],
        limit: int,
        offset: int,
        since: datetime | None,
    ) -> tuple[list[AssetRecord], int]:
        return await self.store.list_assets_page(
            tenant_id=tenant_id,
            limit=limit,
            offset=offset,
            since=since,
        )

    async def list_asset_states(
        self,
        tenant_id: Optional[str],
        limit: int,
        offset: int,
        since: datetime | None,
    ) -> list[AssetStateResponse]:
        return await self.store.list_asset_states(
            tenant_id=tenant_id,
            limit=limit,
            offset=offset,
            since=since,
        )

    async def list_asset_states_page(
        self,
        tenant_id: Optional[str],
        limit: int,
        offset: int,
        since: datetime | None,
    ) -> tuple[list[AssetStateResponse], int]:
        return await self.store.list_asset_states_page(
            tenant_id=tenant_id,
            limit=limit,
            offset=offset,
            since=since,
        )

    async def list_asset_overviews(
        self,
        tenant_id: Optional[str],
        limit: int,
        offset: int,
        since: datetime | None,
    ) -> list[AssetInventoryOverview]:
        return await self.store.list_asset_overviews(
            tenant_id=tenant_id,
            limit=limit,
            offset=offset,
            since=since,
        )

    async def list_asset_overview_page(
        self,
        tenant_id: Optional[str],
        limit: int,
        offset: int,
        since: datetime | None,
    ) -> tuple[list[AssetInventoryOverview], int]:
        return await self.store.list_asset_overview_page(
            tenant_id=tenant_id,
            limit=limit,
            offset=offset,
            since=since,
        )

    async def get_asset_overview(self, asset_id: str) -> AssetInventoryOverview:
        return await self.store.get_asset_overview(asset_id)

    async def get_asset_inventory_stats(
        self,
        tenant_id: Optional[str],
    ) -> AssetInventoryStats:
        return await self.store.get_asset_inventory_stats(tenant_id=tenant_id)


async def create_database(settings: Settings) -> IngestionDatabase:
    """Create the ingestion database facade and its underlying pool."""
    pool = await create_pool(settings)
    store = InventoryStore(pool=pool)
    return IngestionDatabase(pool=pool, store=store)

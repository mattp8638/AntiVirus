"""PostgreSQL-backed storage for MVP-3 inventory and MVP-4 telemetry ingestion."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime, timezone
from typing import List, Optional
from uuid import UUID

import asyncpg

from .models import (
    AssetInventoryOverview,
    AssetRecord,
    AssetStateResponse,
    AssetInventoryStats,
    EventBatch,
    EventClockDrift,
    EventGapReport,
    EventIngestLogRecord,
    EventRecord,
    EventTimeline,
    HardwareInventory,
    InventorySnapshot,
    LocalGroup,
    LocalGroupsInventory,
    LocalUser,
    LocalUsersInventory,
    OsInventory,
    SoftwareInventory,
    SoftwareItem,
    TelemetryMetricSummary,
    TelemetryPayload,
    TelemetryPoint,
    TelemetrySample,
    TelemetrySeries,
    TelemetryBaseline,
    TelemetryAnomaly,
)
from .telemetry import metric_description, metric_unit
from .events import canonical_payload_hash, ensure_timestamp_bounds, EventValidationError


def _parse_date(value: Optional[str]) -> Optional[date]:
    if not value:
        return None
    try:
        return date.fromisoformat(value)
    except ValueError:
        return None


def _to_iso_date(value: Optional[date]) -> Optional[str]:
    return value.isoformat() if value else None


class TelemetryReplayError(RuntimeError):
    """Raised when a telemetry payload is replayed."""


@dataclass
class InventoryStore:
    pool: asyncpg.Pool

    async def _ensure_tenant(self, tenant_id: str) -> None:
        tenant_name = f"tenant-{tenant_id}"
        tenant_slug = f"tenant-{tenant_id}"
        await self.pool.execute(
            """
            INSERT INTO tenants (tenant_id, name, slug)
            VALUES ($1, $2, $3)
            ON CONFLICT (tenant_id) DO NOTHING
            """,
            tenant_id,
            tenant_name,
            tenant_slug,
        )

    async def _ensure_asset(
        self,
        tenant_id: str,
        asset_id: str,
        hostname: Optional[str],
        collected_at: datetime,
    ) -> None:
        await self._ensure_tenant(tenant_id)
        resolved_hostname = hostname or asset_id
        await self.pool.execute(
            """
            INSERT INTO assets (
                asset_id,
                tenant_id,
                hostname,
                asset_type,
                last_seen_at
            )
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT (asset_id) DO UPDATE
            SET hostname = EXCLUDED.hostname,
                updated_at = NOW(),
                last_seen_at = EXCLUDED.last_seen_at
            """,
            asset_id,
            tenant_id,
            resolved_hostname,
            "unknown",
            collected_at,
        )

    async def _ensure_asset_with_connection(
        self,
        connection: asyncpg.Connection,
        tenant_id: str,
        asset_id: str,
        hostname: Optional[str],
        collected_at: datetime,
    ) -> None:
        await connection.execute(
            """
            INSERT INTO tenants (tenant_id, name, slug)
            VALUES ($1, $2, $3)
            ON CONFLICT (tenant_id) DO NOTHING
            """,
            tenant_id,
            f"tenant-{tenant_id}",
            f"tenant-{tenant_id}",
        )
        resolved_hostname = hostname or asset_id
        await connection.execute(
            """
            INSERT INTO assets (
                asset_id,
                tenant_id,
                hostname,
                asset_type,
                last_seen_at
            )
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT (asset_id) DO UPDATE
            SET hostname = EXCLUDED.hostname,
                updated_at = NOW(),
                last_seen_at = EXCLUDED.last_seen_at
            """,
            asset_id,
            tenant_id,
            resolved_hostname,
            "unknown",
            collected_at,
        )

    async def upsert_hardware(self, payload: HardwareInventory) -> None:
        await self._ensure_asset(
            payload.tenant_id,
            payload.asset_id,
            payload.hostname,
            payload.collected_at,
        )
        await self.pool.execute(
            """
            INSERT INTO hardware_inventory (
                asset_id,
                manufacturer,
                model,
                serial_number,
                cpu_model,
                cpu_cores,
                memory_mb,
                storage_gb,
                updated_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            ON CONFLICT (asset_id) DO UPDATE
            SET manufacturer = EXCLUDED.manufacturer,
                model = EXCLUDED.model,
                serial_number = EXCLUDED.serial_number,
                cpu_model = EXCLUDED.cpu_model,
                cpu_cores = EXCLUDED.cpu_cores,
                memory_mb = EXCLUDED.memory_mb,
                storage_gb = EXCLUDED.storage_gb,
                updated_at = EXCLUDED.updated_at
            """,
            payload.asset_id,
            payload.manufacturer,
            payload.model,
            payload.serial_number,
            payload.cpu_model,
            payload.cpu_cores,
            payload.memory_mb,
            payload.storage_gb,
            payload.collected_at,
        )

    async def upsert_os(self, payload: OsInventory) -> None:
        await self._ensure_asset(
            payload.tenant_id,
            payload.asset_id,
            payload.hostname,
            payload.collected_at,
        )
        await self.pool.execute(
            """
            INSERT INTO os_inventory (
                asset_id,
                os_name,
                os_version,
                kernel_version,
                architecture,
                install_date,
                updated_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            ON CONFLICT (asset_id) DO UPDATE
            SET os_name = EXCLUDED.os_name,
                os_version = EXCLUDED.os_version,
                kernel_version = EXCLUDED.kernel_version,
                architecture = EXCLUDED.architecture,
                install_date = EXCLUDED.install_date,
                updated_at = EXCLUDED.updated_at
            """,
            payload.asset_id,
            payload.os_name,
            payload.os_version,
            payload.kernel_version,
            payload.architecture,
            _parse_date(payload.install_date),
            payload.collected_at,
        )

    async def upsert_software(self, payload: SoftwareInventory) -> None:
        await self._ensure_asset(
            payload.tenant_id,
            payload.asset_id,
            payload.hostname,
            payload.collected_at,
        )
        async with self.pool.acquire() as connection:
            async with connection.transaction():
                await connection.execute(
                    "DELETE FROM software_inventory WHERE asset_id = $1",
                    payload.asset_id,
                )
                for item in payload.items:
                    await connection.execute(
                        """
                        INSERT INTO software_inventory (
                            asset_id,
                            name,
                            vendor,
                            version,
                            install_date,
                            source,
                            updated_at
                        )
                        VALUES ($1, $2, $3, $4, $5, $6, $7)
                        """,
                        payload.asset_id,
                        item.name,
                        item.vendor,
                        item.version,
                        _parse_date(item.install_date),
                        item.source,
                        payload.collected_at,
                    )

    async def upsert_users(self, payload: LocalUsersInventory) -> None:
        await self._ensure_asset(
            payload.tenant_id,
            payload.asset_id,
            payload.hostname,
            payload.collected_at,
        )
        async with self.pool.acquire() as connection:
            async with connection.transaction():
                await connection.execute(
                    "DELETE FROM local_users WHERE asset_id = $1",
                    payload.asset_id,
                )
                for user in payload.users:
                    await connection.execute(
                        """
                        INSERT INTO local_users (
                            asset_id,
                            username,
                            display_name,
                            uid,
                            is_admin,
                            last_login_at,
                            updated_at
                        )
                        VALUES ($1, $2, $3, $4, $5, $6, $7)
                        """,
                        payload.asset_id,
                        user.username,
                        user.display_name,
                        user.uid,
                        user.is_admin,
                        user.last_login_at,
                        payload.collected_at,
                    )

    async def upsert_groups(self, payload: LocalGroupsInventory) -> None:
        await self._ensure_asset(
            payload.tenant_id,
            payload.asset_id,
            payload.hostname,
            payload.collected_at,
        )
        async with self.pool.acquire() as connection:
            async with connection.transaction():
                await connection.execute(
                    """
                    DELETE FROM local_group_members
                    WHERE group_id IN (
                        SELECT group_id FROM local_groups WHERE asset_id = $1
                    )
                    """,
                    payload.asset_id,
                )
                await connection.execute(
                    "DELETE FROM local_groups WHERE asset_id = $1",
                    payload.asset_id,
                )

                for group in payload.groups:
                    group_id = await connection.fetchval(
                        """
                        INSERT INTO local_groups (
                            asset_id,
                            name,
                            gid,
                            updated_at
                        )
                        VALUES ($1, $2, $3, $4)
                        RETURNING group_id
                        """,
                        payload.asset_id,
                        group.name,
                        group.gid,
                        payload.collected_at,
                    )

                    for member in group.members:
                        await connection.execute(
                            """
                            INSERT INTO local_group_members (
                                group_id,
                                member_name
                            )
                            VALUES ($1, $2)
                            ON CONFLICT (group_id, member_name) DO NOTHING
                            """,
                            group_id,
                            member,
                        )

    async def ingest_telemetry(
        self,
        payload: TelemetryPayload,
        samples: List[TelemetrySample],
        baseline_window: int,
        anomaly_threshold: float,
    ) -> None:
        await self._ensure_asset(
            payload.tenant_id,
            payload.asset_id,
            payload.hostname,
            payload.collected_at,
        )
        async with self.pool.acquire() as connection:
            async with connection.transaction():
                await self._record_telemetry_receipt(
                    connection,
                    payload_id=payload.payload_id,
                    tenant_id=payload.tenant_id,
                    asset_id=payload.asset_id,
                )
                for sample in samples:
                    metric_id = await self._ensure_metric(
                        connection,
                        name=sample.name,
                        unit=sample.unit or metric_unit(sample.name),
                    )
                    await connection.execute(
                        """
                        INSERT INTO telemetry_samples (
                            asset_id,
                            metric_id,
                            value,
                            observed_at,
                            collected_at
                        )
                        VALUES ($1, $2, $3, $4, $5)
                        """,
                        payload.asset_id,
                        metric_id,
                        sample.value,
                        sample.observed_at,
                        payload.collected_at,
                    )
                    await self._update_baseline(
                        connection,
                        asset_id=payload.asset_id,
                        metric_id=metric_id,
                        window=baseline_window,
                        anomaly_threshold=anomaly_threshold,
                        latest_observed_at=sample.observed_at,
                        latest_value=sample.value,
                    )
                await connection.execute(
                    """
                    UPDATE telemetry_ingest_log
                    SET status = $1,
                        processed_at = NOW()
                    WHERE payload_id = $2
                    """,
                    "accepted",
                    payload.payload_id,
                )

    async def list_telemetry_metrics(self, asset_id: str) -> List[TelemetryMetricSummary]:
        rows = await self.pool.fetch(
            """
            SELECT DISTINCT ON (s.metric_id)
                   m.name,
                   m.unit,
                   s.value,
                   s.observed_at
            FROM telemetry_samples s
            JOIN telemetry_metrics m ON m.metric_id = s.metric_id
            WHERE s.asset_id = $1
            ORDER BY s.metric_id, s.observed_at DESC
            """,
            asset_id,
        )
        return [
            TelemetryMetricSummary(
                name=row["name"],
                unit=row["unit"],
                last_value=row["value"],
                last_observed_at=row["observed_at"],
            )
            for row in rows
        ]

    async def get_telemetry_series(
        self,
        asset_id: str,
        metric_name: str,
        since: Optional[datetime],
        until: Optional[datetime],
        limit: int,
    ) -> TelemetrySeries:
        rows = await self.pool.fetch(
            """
            SELECT s.value,
                   s.observed_at,
                   m.unit
            FROM telemetry_samples s
            JOIN telemetry_metrics m ON m.metric_id = s.metric_id
            WHERE s.asset_id = $1
              AND m.name = $2
              AND ($3::timestamptz IS NULL OR s.observed_at >= $3)
              AND ($4::timestamptz IS NULL OR s.observed_at <= $4)
            ORDER BY s.observed_at DESC
            LIMIT $5
            """,
            asset_id,
            metric_name,
            since,
            until,
            limit,
        )
        if not rows:
            unit = metric_unit(metric_name)
            return TelemetrySeries(
                asset_id=asset_id,
                metric_name=metric_name,
                unit=unit,
                points=[],
            )
        unit = rows[0]["unit"]
        points = [
            TelemetryPoint(
                observed_at=row["observed_at"],
                value=row["value"],
            )
            for row in rows
        ]
        points.reverse()
        return TelemetrySeries(
            asset_id=asset_id,
            metric_name=metric_name,
            unit=unit,
            points=points,
        )

    async def list_telemetry_baselines(self, asset_id: str) -> List[TelemetryBaseline]:
        rows = await self.pool.fetch(
            """
            SELECT b.asset_id,
                   m.name,
                   m.unit,
                   b.sample_count,
                   b.avg_value,
                   b.stddev_value,
                   b.updated_at
            FROM telemetry_baselines b
            JOIN telemetry_metrics m ON m.metric_id = b.metric_id
            WHERE b.asset_id = $1
            ORDER BY m.name
            """,
            asset_id,
        )
        return [
            TelemetryBaseline(
                asset_id=str(row["asset_id"]),
                metric_name=row["name"],
                unit=row["unit"],
                sample_count=row["sample_count"],
                avg_value=row["avg_value"],
                stddev_value=row["stddev_value"],
                updated_at=row["updated_at"],
            )
            for row in rows
        ]

    async def list_telemetry_anomalies(
        self,
        asset_id: str,
        status: Optional[str],
        since: Optional[datetime],
        limit: int,
    ) -> List[TelemetryAnomaly]:
        rows = await self.pool.fetch(
            """
            SELECT a.anomaly_id,
                   a.asset_id,
                   m.name,
                   m.unit,
                   a.observed_at,
                   a.value,
                   a.baseline_value,
                   a.deviation,
                   a.status,
                   a.created_at
            FROM telemetry_anomalies a
            JOIN telemetry_metrics m ON m.metric_id = a.metric_id
            WHERE a.asset_id = $1
              AND ($2::text IS NULL OR a.status = $2)
              AND ($3::timestamptz IS NULL OR a.observed_at >= $3)
            ORDER BY a.observed_at DESC
            LIMIT $4
            """,
            asset_id,
            status,
            since,
            limit,
        )
        return [
            TelemetryAnomaly(
                anomaly_id=row["anomaly_id"],
                asset_id=str(row["asset_id"]),
                metric_name=row["name"],
                unit=row["unit"],
                observed_at=row["observed_at"],
                value=row["value"],
                baseline_value=row["baseline_value"],
                deviation=row["deviation"],
                status=row["status"],
                created_at=row["created_at"],
            )
            for row in rows
        ]

    async def snapshot(self, asset_id: str) -> InventorySnapshot:
        asset = await self._fetch_asset_context(asset_id)
        tenant_id = asset["tenant_id"] if asset else ""
        hostname = asset["hostname"] if asset else None

        hardware = await self._fetch_hardware(asset_id, tenant_id, hostname)
        os_inventory = await self._fetch_os(asset_id, tenant_id, hostname)
        software = await self._fetch_software(asset_id, tenant_id, hostname)
        users = await self._fetch_users(asset_id, tenant_id, hostname)
        groups = await self._fetch_groups(asset_id, tenant_id, hostname)
        return InventorySnapshot(
            hardware=hardware,
            os=os_inventory,
            software=software,
            users=users,
            groups=groups,
        )

    async def list_assets(
        self,
        tenant_id: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
        since: Optional[datetime] = None,
    ) -> List[AssetRecord]:
        if tenant_id and since:
            rows = await self.pool.fetch(
                """
                SELECT asset_id,
                       tenant_id,
                       hostname,
                       asset_type,
                       environment,
                       status,
                       criticality,
                       last_seen_at,
                       updated_at
                FROM assets
                WHERE tenant_id = $1
                  AND last_seen_at >= $2
                ORDER BY updated_at DESC
                LIMIT $3 OFFSET $4
                """,
                tenant_id,
                since,
                limit,
                offset,
            )
        elif tenant_id:
            rows = await self.pool.fetch(
                """
                SELECT asset_id,
                       tenant_id,
                       hostname,
                       asset_type,
                       environment,
                       status,
                       criticality,
                       last_seen_at,
                       updated_at
                FROM assets
                WHERE tenant_id = $1
                ORDER BY updated_at DESC
                LIMIT $2 OFFSET $3
                """,
                tenant_id,
                limit,
                offset,
            )
        elif since:
            rows = await self.pool.fetch(
                """
                SELECT asset_id,
                       tenant_id,
                       hostname,
                       asset_type,
                       environment,
                       status,
                       criticality,
                       last_seen_at,
                       updated_at
                FROM assets
                WHERE last_seen_at >= $1
                ORDER BY updated_at DESC
                LIMIT $2 OFFSET $3
                """,
                since,
                limit,
                offset,
            )
        else:
            rows = await self.pool.fetch(
                """
                SELECT asset_id,
                       tenant_id,
                       hostname,
                       asset_type,
                       environment,
                       status,
                       criticality,
                       last_seen_at,
                       updated_at
                FROM assets
                ORDER BY updated_at DESC
                LIMIT $1 OFFSET $2
                """,
                limit,
                offset,
            )
        return [
            AssetRecord(
                asset_id=str(row["asset_id"]),
                tenant_id=str(row["tenant_id"]),
                hostname=row["hostname"],
                asset_type=row["asset_type"],
                environment=row["environment"],
                status=row["status"],
                criticality=row["criticality"],
                last_seen_at=row["last_seen_at"],
                updated_at=row["updated_at"],
            )
            for row in rows
        ]

    async def list_assets_page(
        self,
        tenant_id: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
        since: Optional[datetime] = None,
    ) -> tuple[List[AssetRecord], int]:
        if tenant_id and since:
            total = await self.pool.fetchval(
                """
                SELECT COUNT(*)
                FROM assets
                WHERE tenant_id = $1
                  AND last_seen_at >= $2
                """,
                tenant_id,
                since,
            )
        elif tenant_id:
            total = await self.pool.fetchval(
                "SELECT COUNT(*) FROM assets WHERE tenant_id = $1",
                tenant_id,
            )
        elif since:
            total = await self.pool.fetchval(
                "SELECT COUNT(*) FROM assets WHERE last_seen_at >= $1",
                since,
            )
        else:
            total = await self.pool.fetchval("SELECT COUNT(*) FROM assets")
        items = await self.list_assets(
            tenant_id=tenant_id,
            limit=limit,
            offset=offset,
            since=since,
        )
        return items, int(total or 0)

    async def list_asset_states(
        self,
        tenant_id: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
        since: Optional[datetime] = None,
    ) -> List[AssetStateResponse]:
        base_query = """
            SELECT a.asset_id,
                   a.hostname,
                   os.os_name,
                   os.os_version,
                   COALESCE(sw.software_count, 0) AS software_count,
                   COALESCE(u.user_count, 0) AS users_count,
                   COALESCE(g.group_count, 0) AS groups_count
            FROM assets a
            LEFT JOIN os_inventory os ON os.asset_id = a.asset_id
            LEFT JOIN (
                SELECT asset_id, COUNT(*) AS software_count
                FROM software_inventory
                GROUP BY asset_id
            ) sw ON sw.asset_id = a.asset_id
            LEFT JOIN (
                SELECT asset_id, COUNT(*) AS user_count
                FROM local_users
                GROUP BY asset_id
            ) u ON u.asset_id = a.asset_id
            LEFT JOIN (
                SELECT asset_id, COUNT(*) AS group_count
                    FROM local_groups
                    GROUP BY asset_id
            ) g ON g.asset_id = a.asset_id
        """
        if tenant_id and since:
            rows = await self.pool.fetch(
                base_query
                + """
                WHERE a.tenant_id = $1
                  AND a.last_seen_at >= $2
                ORDER BY a.updated_at DESC
                LIMIT $3 OFFSET $4
                """,
                tenant_id,
                since,
                limit,
                offset,
            )
        elif tenant_id:
            rows = await self.pool.fetch(
                base_query
                + " WHERE a.tenant_id = $1 ORDER BY a.updated_at DESC LIMIT $2 OFFSET $3",
                tenant_id,
                limit,
                offset,
            )
        elif since:
            rows = await self.pool.fetch(
                base_query
                + " WHERE a.last_seen_at >= $1 ORDER BY a.updated_at DESC LIMIT $2 OFFSET $3",
                since,
                limit,
                offset,
            )
        else:
            rows = await self.pool.fetch(
                base_query + " ORDER BY a.updated_at DESC LIMIT $1 OFFSET $2",
                limit,
                offset,
            )
        return [
            AssetStateResponse(
                asset_id=str(row["asset_id"]),
                hostname=row["hostname"],
                os_name=row["os_name"],
                os_version=row["os_version"],
                software_count=row["software_count"],
                users_count=row["users_count"],
                groups_count=row["groups_count"],
            )
            for row in rows
        ]

    async def list_asset_states_page(
        self,
        tenant_id: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
        since: Optional[datetime] = None,
    ) -> tuple[List[AssetStateResponse], int]:
        if tenant_id and since:
            total = await self.pool.fetchval(
                """
                SELECT COUNT(*)
                FROM assets
                WHERE tenant_id = $1
                  AND last_seen_at >= $2
                """,
                tenant_id,
                since,
            )
        elif tenant_id:
            total = await self.pool.fetchval(
                "SELECT COUNT(*) FROM assets WHERE tenant_id = $1",
                tenant_id,
            )
        elif since:
            total = await self.pool.fetchval(
                "SELECT COUNT(*) FROM assets WHERE last_seen_at >= $1",
                since,
            )
        else:
            total = await self.pool.fetchval("SELECT COUNT(*) FROM assets")
        items = await self.list_asset_states(
            tenant_id=tenant_id,
            limit=limit,
            offset=offset,
            since=since,
        )
        return items, int(total or 0)

    async def list_asset_overviews(
        self,
        tenant_id: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
        since: Optional[datetime] = None,
    ) -> List[AssetInventoryOverview]:
        base_query = """
            SELECT a.asset_id,
                   a.tenant_id,
                   a.hostname,
                   a.last_seen_at,
                   a.updated_at,
                   os.os_name,
                   os.os_version,
                   hw.model AS hardware_model,
                   COALESCE(sw.software_count, 0) AS software_count,
                   COALESCE(u.user_count, 0) AS users_count,
                   COALESCE(g.group_count, 0) AS groups_count
            FROM assets a
            LEFT JOIN os_inventory os ON os.asset_id = a.asset_id
            LEFT JOIN hardware_inventory hw ON hw.asset_id = a.asset_id
            LEFT JOIN (
                SELECT asset_id, COUNT(*) AS software_count
                FROM software_inventory
                GROUP BY asset_id
            ) sw ON sw.asset_id = a.asset_id
            LEFT JOIN (
                SELECT asset_id, COUNT(*) AS user_count
                FROM local_users
                GROUP BY asset_id
            ) u ON u.asset_id = a.asset_id
            LEFT JOIN (
                SELECT asset_id, COUNT(*) AS group_count
                FROM local_groups
                GROUP BY asset_id
            ) g ON g.asset_id = a.asset_id
        """
        if tenant_id and since:
            rows = await self.pool.fetch(
                base_query
                + """
                WHERE a.tenant_id = $1
                  AND a.last_seen_at >= $2
                ORDER BY a.updated_at DESC
                LIMIT $3 OFFSET $4
                """,
                tenant_id,
                since,
                limit,
                offset,
            )
        elif tenant_id:
            rows = await self.pool.fetch(
                base_query
                + " WHERE a.tenant_id = $1 ORDER BY a.updated_at DESC LIMIT $2 OFFSET $3",
                tenant_id,
                limit,
                offset,
            )
        elif since:
            rows = await self.pool.fetch(
                base_query
                + " WHERE a.last_seen_at >= $1 ORDER BY a.updated_at DESC LIMIT $2 OFFSET $3",
                since,
                limit,
                offset,
            )
        else:
            rows = await self.pool.fetch(
                base_query + " ORDER BY a.updated_at DESC LIMIT $1 OFFSET $2",
                limit,
                offset,
            )
        return [
            AssetInventoryOverview(
                asset_id=str(row["asset_id"]),
                tenant_id=str(row["tenant_id"]),
                hostname=row["hostname"],
                os_name=row["os_name"],
                os_version=row["os_version"],
                hardware_model=row["hardware_model"],
                software_count=row["software_count"],
                users_count=row["users_count"],
                groups_count=row["groups_count"],
                last_seen_at=row["last_seen_at"],
                updated_at=row["updated_at"],
            )
            for row in rows
        ]

    async def list_asset_overview_page(
        self,
        tenant_id: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
        since: Optional[datetime] = None,
    ) -> tuple[List[AssetInventoryOverview], int]:
        if tenant_id and since:
            total = await self.pool.fetchval(
                """
                SELECT COUNT(*)
                FROM assets
                WHERE tenant_id = $1
                  AND last_seen_at >= $2
                """,
                tenant_id,
                since,
            )
        elif tenant_id:
            total = await self.pool.fetchval(
                "SELECT COUNT(*) FROM assets WHERE tenant_id = $1",
                tenant_id,
            )
        elif since:
            total = await self.pool.fetchval(
                "SELECT COUNT(*) FROM assets WHERE last_seen_at >= $1",
                since,
            )
        else:
            total = await self.pool.fetchval("SELECT COUNT(*) FROM assets")
        items = await self.list_asset_overviews(
            tenant_id=tenant_id,
            limit=limit,
            offset=offset,
            since=since,
        )
        return items, int(total or 0)

    async def get_asset_overview(
        self, asset_id: str
    ) -> Optional[AssetInventoryOverview]:
        row = await self.pool.fetchrow(
            """
            SELECT a.asset_id,
                   a.tenant_id,
                   a.hostname,
                   a.last_seen_at,
                   a.updated_at,
                   os.os_name,
                   os.os_version,
                   hw.model AS hardware_model,
                   COALESCE(sw.software_count, 0) AS software_count,
                   COALESCE(u.user_count, 0) AS users_count,
                   COALESCE(g.group_count, 0) AS groups_count
            FROM assets a
            LEFT JOIN os_inventory os ON os.asset_id = a.asset_id
            LEFT JOIN hardware_inventory hw ON hw.asset_id = a.asset_id
            LEFT JOIN (
                SELECT asset_id, COUNT(*) AS software_count
                FROM software_inventory
                GROUP BY asset_id
            ) sw ON sw.asset_id = a.asset_id
            LEFT JOIN (
                SELECT asset_id, COUNT(*) AS user_count
                FROM local_users
                GROUP BY asset_id
            ) u ON u.asset_id = a.asset_id
            LEFT JOIN (
                SELECT asset_id, COUNT(*) AS group_count
                FROM local_groups
                GROUP BY asset_id
            ) g ON g.asset_id = a.asset_id
            WHERE a.asset_id = $1
            """,
            asset_id,
        )
        if not row:
            return None
        return AssetInventoryOverview(
            asset_id=str(row["asset_id"]),
            tenant_id=str(row["tenant_id"]),
            hostname=row["hostname"],
            os_name=row["os_name"],
            os_version=row["os_version"],
            hardware_model=row["hardware_model"],
            software_count=row["software_count"],
            users_count=row["users_count"],
            groups_count=row["groups_count"],
            last_seen_at=row["last_seen_at"],
            updated_at=row["updated_at"],
        )

    async def get_asset_inventory_stats(
        self, tenant_id: Optional[str] = None
    ) -> AssetInventoryStats:
        if tenant_id:
            row = await self.pool.fetchrow(
                """
                WITH scoped_assets AS (
                    SELECT asset_id FROM assets WHERE tenant_id = $1
                )
                SELECT
                    (SELECT COUNT(*) FROM scoped_assets) AS total_assets,
                    (SELECT COUNT(*) FROM hardware_inventory h
                        JOIN scoped_assets sa ON sa.asset_id = h.asset_id) AS assets_with_hardware,
                    (SELECT COUNT(*) FROM os_inventory o
                        JOIN scoped_assets sa ON sa.asset_id = o.asset_id) AS assets_with_os,
                    (SELECT COUNT(DISTINCT s.asset_id) FROM software_inventory s
                        JOIN scoped_assets sa ON sa.asset_id = s.asset_id) AS assets_with_software,
                    (SELECT COUNT(DISTINCT u.asset_id) FROM local_users u
                        JOIN scoped_assets sa ON sa.asset_id = u.asset_id) AS assets_with_users,
                    (SELECT COUNT(DISTINCT g.asset_id) FROM local_groups g
                        JOIN scoped_assets sa ON sa.asset_id = g.asset_id) AS assets_with_groups
                """,
                tenant_id,
            )
        else:
            row = await self.pool.fetchrow(
                """
                SELECT
                    (SELECT COUNT(*) FROM assets) AS total_assets,
                    (SELECT COUNT(*) FROM hardware_inventory) AS assets_with_hardware,
                    (SELECT COUNT(*) FROM os_inventory) AS assets_with_os,
                    (SELECT COUNT(DISTINCT asset_id) FROM software_inventory) AS assets_with_software,
                    (SELECT COUNT(DISTINCT asset_id) FROM local_users) AS assets_with_users,
                    (SELECT COUNT(DISTINCT asset_id) FROM local_groups) AS assets_with_groups
                """
            )
        return AssetInventoryStats(
            total_assets=row["total_assets"],
            assets_with_hardware=row["assets_with_hardware"],
            assets_with_os=row["assets_with_os"],
            assets_with_software=row["assets_with_software"],
            assets_with_users=row["assets_with_users"],
            assets_with_groups=row["assets_with_groups"],
        )

    async def _fetch_asset_context(self, asset_id: str) -> Optional[asyncpg.Record]:
        return await self.pool.fetchrow(
            """
            SELECT tenant_id,
                   hostname
            FROM assets
            WHERE asset_id = $1
            """,
            asset_id,
        )

    async def _fetch_hardware(
        self,
        asset_id: str,
        tenant_id: str,
        hostname: Optional[str],
    ) -> Optional[HardwareInventory]:
        row = await self.pool.fetchrow(
            """
            SELECT manufacturer,
                   model,
                   serial_number,
                   cpu_model,
                   cpu_cores,
                   memory_mb,
                   storage_gb,
                   updated_at
            FROM hardware_inventory
            WHERE asset_id = $1
            """,
            asset_id,
        )
        if not row:
            return None
        return HardwareInventory(
            tenant_id=tenant_id,
            asset_id=asset_id,
            collected_at=row["updated_at"],
            hostname=hostname,
            manufacturer=row["manufacturer"],
            model=row["model"],
            serial_number=row["serial_number"],
            cpu_model=row["cpu_model"],
            cpu_cores=row["cpu_cores"],
            memory_mb=row["memory_mb"],
            storage_gb=row["storage_gb"],
        )

    async def _fetch_os(
        self,
        asset_id: str,
        tenant_id: str,
        hostname: Optional[str],
    ) -> Optional[OsInventory]:
        row = await self.pool.fetchrow(
            """
            SELECT os_name,
                   os_version,
                   kernel_version,
                   architecture,
                   install_date,
                   updated_at
            FROM os_inventory
            WHERE asset_id = $1
            """,
            asset_id,
        )
        if not row:
            return None
        return OsInventory(
            tenant_id=tenant_id,
            asset_id=asset_id,
            collected_at=row["updated_at"],
            hostname=hostname,
            os_name=row["os_name"],
            os_version=row["os_version"],
            kernel_version=row["kernel_version"],
            architecture=row["architecture"],
            install_date=_to_iso_date(row["install_date"]),
        )

    async def _fetch_software(
        self,
        asset_id: str,
        tenant_id: str,
        hostname: Optional[str],
    ) -> Optional[SoftwareInventory]:
        rows = await self.pool.fetch(
            """
            SELECT name,
                   vendor,
                   version,
                   install_date,
                   source,
                   updated_at
            FROM software_inventory
            WHERE asset_id = $1
            ORDER BY name
            """,
            asset_id,
        )
        if not rows:
            return None
        collected_at = max(row["updated_at"] for row in rows)
        items = [
            SoftwareItem(
                name=row["name"],
                vendor=row["vendor"],
                version=row["version"],
                install_date=_to_iso_date(row["install_date"]),
                source=row["source"],
            )
            for row in rows
        ]
        return SoftwareInventory(
            tenant_id=tenant_id,
            asset_id=asset_id,
            collected_at=collected_at,
            hostname=hostname,
            items=items,
        )

    async def _fetch_users(
        self,
        asset_id: str,
        tenant_id: str,
        hostname: Optional[str],
    ) -> Optional[LocalUsersInventory]:
        rows = await self.pool.fetch(
            """
            SELECT username,
                   display_name,
                   uid,
                   is_admin,
                   last_login_at,
                   updated_at
            FROM local_users
            WHERE asset_id = $1
            ORDER BY username
            """,
            asset_id,
        )
        if not rows:
            return None
        collected_at = max(row["updated_at"] for row in rows)
        users = [
            LocalUser(
                username=row["username"],
                display_name=row["display_name"],
                uid=row["uid"],
                is_admin=row["is_admin"],
                last_login_at=row["last_login_at"],
            )
            for row in rows
        ]
        return LocalUsersInventory(
            tenant_id=tenant_id,
            asset_id=asset_id,
            collected_at=collected_at,
            hostname=hostname,
            users=users,
        )

    async def _fetch_groups(
        self,
        asset_id: str,
        tenant_id: str,
        hostname: Optional[str],
    ) -> Optional[LocalGroupsInventory]:
        rows = await self.pool.fetch(
            """
            SELECT g.group_id,
                   g.name,
                   g.gid,
                   g.updated_at,
                   COALESCE(
                       ARRAY_AGG(m.member_name) FILTER (WHERE m.member_name IS NOT NULL),
                       ARRAY[]::text[]
                   ) AS members
            FROM local_groups g
            LEFT JOIN local_group_members m ON m.group_id = g.group_id
            WHERE g.asset_id = $1
            GROUP BY g.group_id
            ORDER BY g.name
            """,
            asset_id,
        )
        if not rows:
            return None
        collected_at = max(row["updated_at"] for row in rows)
        groups = [
            LocalGroup(
                name=row["name"],
                gid=row["gid"],
                members=list(row["members"] or []),
            )
            for row in rows
        ]
        return LocalGroupsInventory(
            tenant_id=tenant_id,
            asset_id=asset_id,
            collected_at=collected_at,
            hostname=hostname,
            groups=groups,
        )

    async def _record_telemetry_receipt(
        self,
        connection: asyncpg.Connection,
        payload_id: UUID,
        tenant_id: str,
        asset_id: str,
    ) -> None:
        try:
            await connection.execute(
                """
                INSERT INTO telemetry_ingest_log (
                    payload_id,
                    tenant_id,
                    asset_id,
                    status,
                    received_at
                )
                VALUES ($1, $2, $3, $4, NOW())
                """,
                payload_id,
                tenant_id,
                asset_id,
                "received",
            )
        except asyncpg.UniqueViolationError as exc:
            raise TelemetryReplayError("payload_replay") from exc

    async def record_telemetry_rejection(
        self,
        payload_id: UUID,
        tenant_id: str,
        asset_id: str,
        reason: str,
    ) -> None:
        await self.pool.execute(
            """
            INSERT INTO telemetry_ingest_log (
                payload_id,
                tenant_id,
                asset_id,
                status,
                received_at,
                processed_at,
                reject_reason
            )
            VALUES ($1, $2, $3, $4, NOW(), NOW(), $5)
            ON CONFLICT (payload_id) DO NOTHING
            """,
            payload_id,
            tenant_id,
            asset_id,
            "rejected",
            reason,
        )

    async def _ensure_metric(
        self,
        connection: asyncpg.Connection,
        name: str,
        unit: str,
    ) -> UUID:
        description = metric_description(name)
        row = await connection.fetchrow(
            """
            INSERT INTO telemetry_metrics (name, unit, description)
            VALUES ($1, $2, $3)
            ON CONFLICT (name) DO UPDATE
            SET unit = EXCLUDED.unit,
                description = EXCLUDED.description
            RETURNING metric_id
            """,
            name,
            unit,
            description,
        )
        return row["metric_id"]

    async def _update_baseline(
        self,
        connection: asyncpg.Connection,
        asset_id: str,
        metric_id: UUID,
        window: int,
        anomaly_threshold: float,
        latest_observed_at: datetime,
        latest_value: float,
    ) -> None:
        stats = await connection.fetchrow(
            """
            SELECT AVG(value) AS avg_value,
                   STDDEV_POP(value) AS stddev_value,
                   COUNT(*) AS sample_count
            FROM (
                SELECT value
                FROM telemetry_samples
                WHERE asset_id = $1
                  AND metric_id = $2
                ORDER BY observed_at DESC
                LIMIT $3
            ) AS recent
            """,
            asset_id,
            metric_id,
            window,
        )
        if not stats:
            return
        avg_value = float(stats["avg_value"]) if stats["avg_value"] is not None else 0.0
        stddev_value = (
            float(stats["stddev_value"]) if stats["stddev_value"] is not None else 0.0
        )
        sample_count = int(stats["sample_count"] or 0)
        await connection.execute(
            """
            INSERT INTO telemetry_baselines (
                asset_id,
                metric_id,
                sample_count,
                avg_value,
                stddev_value,
                updated_at
            )
            VALUES ($1, $2, $3, $4, $5, NOW())
            ON CONFLICT (asset_id, metric_id) DO UPDATE
            SET sample_count = EXCLUDED.sample_count,
                avg_value = EXCLUDED.avg_value,
                stddev_value = EXCLUDED.stddev_value,
                updated_at = NOW()
            """,
            asset_id,
            metric_id,
            sample_count,
            avg_value,
            stddev_value,
        )
        if sample_count < max(window // 2, 5) or stddev_value <= 0:
            return
        deviation = abs(latest_value - avg_value)
        if deviation >= anomaly_threshold * stddev_value:
            await connection.execute(
                """
                INSERT INTO telemetry_anomalies (
                    asset_id,
                    metric_id,
                    observed_at,
                    value,
                    baseline_value,
                    deviation,
                    status,
                    created_at
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
                """,
                asset_id,
                metric_id,
                latest_observed_at,
                latest_value,
                avg_value,
                deviation,
                "open",
            )

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
        await self.pool.execute(
            """
            INSERT INTO event_ingest_log (
                payload_id,
                tenant_id,
                asset_id,
                status,
                received_at,
                processed_at,
                event_count,
                accepted_count,
                rejected_count,
                reject_reason,
                signature,
                signature_verified,
                schema_version
            )
            VALUES ($1, $2, $3, $4, NOW(), NOW(), $5, $6, $7, $8, $9, $10, $11, $12)
            ON CONFLICT (payload_id) DO UPDATE
            SET status = EXCLUDED.status,
                processed_at = EXCLUDED.processed_at,
                event_count = EXCLUDED.event_count,
                accepted_count = EXCLUDED.accepted_count,
                rejected_count = EXCLUDED.rejected_count,
                reject_reason = EXCLUDED.reject_reason,
                signature = EXCLUDED.signature,
                signature_verified = EXCLUDED.signature_verified,
                schema_version = EXCLUDED.schema_version
            """,
            payload_id,
            tenant_id,
            asset_id,
            status,
            event_count,
            accepted_count,
            rejected_count,
            reject_reason,
            signature,
            signature_verified,
            schema_version,
        )

    async def event_payload_exists(self, payload_id: UUID) -> bool:
        existing = await self.pool.fetchval(
            "SELECT 1 FROM event_ingest_log WHERE payload_id = $1",
            payload_id,
        )
        return existing is not None

    async def ingest_event_batch(
        self,
        batch: EventBatch,
        signature: str | None,
        signature_verified: bool,
        event_stale_seconds: int,
        event_future_seconds: int,
        clock_drift_seconds: int,
    ) -> tuple[list[EventGapReport], list[EventClockDrift], int, int]:
        received_at = datetime.now(timezone.utc)
        accepted = 0
        rejected = 0
        gap_reports: list[EventGapReport] = []
        drift_reports: list[EventClockDrift] = []
        trust_level = "verified" if signature_verified else "unverified"

        await self.record_event_batch_log(
            payload_id=batch.payload_id,
            tenant_id=batch.tenant_id,
            asset_id=batch.asset_id,
            status="processing",
            signature=signature,
            signature_verified=signature_verified,
            event_count=len(batch.events),
            accepted_count=0,
            rejected_count=0,
            reject_reason=None,
            schema_version=batch.schema_version,
        )

        async with self.pool.acquire() as connection:
            async with connection.transaction():
                await self._ensure_asset_with_connection(
                    connection=connection,
                    tenant_id=batch.tenant_id,
                    asset_id=batch.asset_id,
                    hostname=None,
                    collected_at=received_at,
                )
                for event in batch.events:
                    reject_reason = None
                    try:
                        ensure_timestamp_bounds(
                            event=event,
                            now=received_at,
                            stale_seconds=event_stale_seconds,
                            future_seconds=event_future_seconds,
                        )
                        if canonical_payload_hash(event.payload) != event.payload_hash:
                            reject_reason = "payload_hash_mismatch"
                    except EventValidationError as exc:
                        reject_reason = exc.reason
                    if reject_reason:
                        rejected += 1
                        await connection.execute(
                            """
                            INSERT INTO event_rejections (
                                event_id,
                                payload_id,
                                tenant_id,
                                asset_id,
                                reason,
                                detected_at
                            )
                            VALUES ($1, $2, $3, $4, $5, NOW())
                            """,
                            event.event_id,
                            batch.payload_id,
                            batch.tenant_id,
                            batch.asset_id,
                            reject_reason,
                        )
                        continue

                    event_time = event.timestamp_local
                    if event_time.tzinfo is None:
                        event_time = event_time.replace(tzinfo=timezone.utc)

                    last_sequence = await connection.fetchval(
                        """
                        SELECT last_sequence
                        FROM event_sequence_state
                        WHERE asset_id = $1 AND source_module = $2
                        FOR UPDATE
                        """,
                        batch.asset_id,
                        event.source_module,
                    )
                    if last_sequence is not None and event.sequence_number <= last_sequence:
                        rejected += 1
                        await connection.execute(
                            """
                            INSERT INTO event_rejections (
                                event_id,
                                payload_id,
                                tenant_id,
                                asset_id,
                                reason,
                                detected_at
                            )
                            VALUES ($1, $2, $3, $4, $5, NOW())
                            """,
                            event.event_id,
                            batch.payload_id,
                            batch.tenant_id,
                            batch.asset_id,
                            "sequence_replay",
                        )
                        continue
                    if last_sequence is not None and event.sequence_number > last_sequence + 1:
                        missing_from = last_sequence + 1
                        missing_to = event.sequence_number - 1
                        await connection.execute(
                            """
                            INSERT INTO event_gap_reports (
                                asset_id,
                                source_module,
                                missing_from,
                                missing_to,
                                detected_at
                            )
                            VALUES ($1, $2, $3, $4, NOW())
                            """,
                            batch.asset_id,
                            event.source_module,
                            missing_from,
                            missing_to,
                        )
                        gap_reports.append(
                            EventGapReport(
                                asset_id=batch.asset_id,
                                source_module=event.source_module,
                                missing_from=missing_from,
                                missing_to=missing_to,
                                detected_at=received_at,
                            )
                        )

                    inserted = await connection.fetchval(
                        """
                        INSERT INTO event_ledger (
                            event_id,
                            tenant_id,
                            asset_id,
                            event_type,
                            event_category,
                            source_module,
                            trust_level,
                            severity,
                            sequence_number,
                            timestamp_local,
                            timestamp_received,
                            payload,
                            payload_hash
                        )
                        VALUES (
                            $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13
                        )
                        ON CONFLICT (event_id) DO NOTHING
                        RETURNING event_id
                        """,
                        event.event_id,
                        batch.tenant_id,
                        batch.asset_id,
                        event.event_type,
                        event.event_category,
                        event.source_module,
                        trust_level,
                        event.severity,
                        event.sequence_number,
                        event_time,
                        received_at,
                        event.payload,
                        event.payload_hash,
                    )
                    if not inserted:
                        rejected += 1
                        await connection.execute(
                            """
                            INSERT INTO event_rejections (
                                event_id,
                                payload_id,
                                tenant_id,
                                asset_id,
                                reason,
                                detected_at
                            )
                            VALUES ($1, $2, $3, $4, $5, NOW())
                            """,
                            event.event_id,
                            batch.payload_id,
                            batch.tenant_id,
                            batch.asset_id,
                            "event_replay",
                        )
                        continue

                    await connection.execute(
                        """
                        INSERT INTO event_sequence_state (
                            asset_id,
                            source_module,
                            last_sequence,
                            updated_at
                        )
                        VALUES ($1, $2, $3, NOW())
                        ON CONFLICT (asset_id, source_module) DO UPDATE
                        SET last_sequence = EXCLUDED.last_sequence,
                            updated_at = NOW()
                        """,
                        batch.asset_id,
                        event.source_module,
                        event.sequence_number,
                    )

                    drift_seconds = int(abs((received_at - event_time).total_seconds()))
                    if drift_seconds > clock_drift_seconds:
                        await connection.execute(
                            """
                            INSERT INTO event_clock_drifts (
                                event_id,
                                asset_id,
                                source_module,
                                drift_seconds,
                                timestamp_local,
                                timestamp_received,
                                detected_at
                            )
                            VALUES ($1, $2, $3, $4, $5, $6, NOW())
                            """,
                            event.event_id,
                            batch.asset_id,
                            event.source_module,
                            drift_seconds,
                            event_time,
                            received_at,
                        )
                        drift_reports.append(
                            EventClockDrift(
                                event_id=event.event_id,
                                asset_id=batch.asset_id,
                                source_module=event.source_module,
                                drift_seconds=drift_seconds,
                                timestamp_local=event_time,
                                timestamp_received=received_at,
                            )
                        )

                    accepted += 1

        status = "accepted" if rejected == 0 else "partial"
        await self.record_event_batch_log(
            payload_id=batch.payload_id,
            tenant_id=batch.tenant_id,
            asset_id=batch.asset_id,
            status=status,
            signature=signature,
            signature_verified=signature_verified,
            event_count=len(batch.events),
            accepted_count=accepted,
            rejected_count=rejected,
            reject_reason=None,
            schema_version=batch.schema_version,
        )
        return gap_reports, drift_reports, accepted, rejected

    async def list_recent_events(
        self,
        tenant_id: Optional[str],
        limit: int,
        since: Optional[datetime],
        event_category: Optional[str],
        event_type: Optional[str],
    ) -> list[EventRecord]:
        conditions = ["1=1"]
        params: list[object] = []
        if tenant_id:
            params.append(tenant_id)
            conditions.append(f"tenant_id = ${len(params)}")
        if since:
            params.append(since)
            conditions.append(f"timestamp_received >= ${len(params)}")
        if event_category:
            params.append(event_category)
            conditions.append(f"event_category = ${len(params)}")
        if event_type:
            params.append(event_type)
            conditions.append(f"event_type = ${len(params)}")
        params.append(limit)
        query = f"""
            SELECT event_id, tenant_id, asset_id, event_type, event_category,
                   source_module, trust_level, severity, sequence_number,
                   timestamp_local, timestamp_received, payload, payload_hash
            FROM event_ledger
            WHERE {" AND ".join(conditions)}
            ORDER BY timestamp_received DESC
            LIMIT ${len(params)}
        """
        rows = await self.pool.fetch(query, *params)
        return [
            EventRecord(
                event_id=row["event_id"],
                tenant_id=row["tenant_id"],
                asset_id=row["asset_id"],
                event_type=row["event_type"],
                event_category=row["event_category"],
                source_module=row["source_module"],
                trust_level=row["trust_level"],
                severity=row["severity"],
                sequence_number=row["sequence_number"],
                timestamp_local=row["timestamp_local"],
                timestamp_received=row["timestamp_received"],
                payload=row["payload"],
                payload_hash=row["payload_hash"],
            )
            for row in rows
        ]

    async def get_event(self, event_id: UUID) -> Optional[EventRecord]:
        row = await self.pool.fetchrow(
            """
            SELECT event_id, tenant_id, asset_id, event_type, event_category,
                   source_module, trust_level, severity, sequence_number,
                   timestamp_local, timestamp_received, payload, payload_hash
            FROM event_ledger
            WHERE event_id = $1
            """,
            event_id,
        )
        if not row:
            return None
        return EventRecord(
            event_id=row["event_id"],
            tenant_id=row["tenant_id"],
            asset_id=row["asset_id"],
            event_type=row["event_type"],
            event_category=row["event_category"],
            source_module=row["source_module"],
            trust_level=row["trust_level"],
            severity=row["severity"],
            sequence_number=row["sequence_number"],
            timestamp_local=row["timestamp_local"],
            timestamp_received=row["timestamp_received"],
            payload=row["payload"],
            payload_hash=row["payload_hash"],
        )

    async def get_asset_timeline(
        self,
        asset_id: str,
        limit: int,
        since: Optional[datetime],
        until: Optional[datetime],
        event_category: Optional[str],
        event_type: Optional[str],
    ) -> EventTimeline:
        conditions = ["asset_id = $1"]
        params: list[object] = [asset_id]
        if since:
            params.append(since)
            conditions.append(f"timestamp_received >= ${len(params)}")
        if until:
            params.append(until)
            conditions.append(f"timestamp_received <= ${len(params)}")
        if event_category:
            params.append(event_category)
            conditions.append(f"event_category = ${len(params)}")
        if event_type:
            params.append(event_type)
            conditions.append(f"event_type = ${len(params)}")
        params.append(limit)
        query = f"""
            SELECT event_id, tenant_id, asset_id, event_type, event_category,
                   source_module, trust_level, severity, sequence_number,
                   timestamp_local, timestamp_received, payload, payload_hash
            FROM event_ledger
            WHERE {" AND ".join(conditions)}
            ORDER BY timestamp_received DESC
            LIMIT ${len(params)}
        """
        rows = await self.pool.fetch(query, *params)
        events = [
            EventRecord(
                event_id=row["event_id"],
                tenant_id=row["tenant_id"],
                asset_id=row["asset_id"],
                event_type=row["event_type"],
                event_category=row["event_category"],
                source_module=row["source_module"],
                trust_level=row["trust_level"],
                severity=row["severity"],
                sequence_number=row["sequence_number"],
                timestamp_local=row["timestamp_local"],
                timestamp_received=row["timestamp_received"],
                payload=row["payload"],
                payload_hash=row["payload_hash"],
            )
            for row in rows
        ]
        return EventTimeline(asset_id=asset_id, events=events)

    async def list_event_gaps(
        self,
        asset_id: str,
        limit: int,
    ) -> list[EventGapReport]:
        rows = await self.pool.fetch(
            """
            SELECT asset_id, source_module, missing_from, missing_to, detected_at
            FROM event_gap_reports
            WHERE asset_id = $1
            ORDER BY detected_at DESC
            LIMIT $2
            """,
            asset_id,
            limit,
        )
        return [
            EventGapReport(
                asset_id=row["asset_id"],
                source_module=row["source_module"],
                missing_from=row["missing_from"],
                missing_to=row["missing_to"],
                detected_at=row["detected_at"],
            )
            for row in rows
        ]

    async def list_event_drifts(
        self,
        asset_id: str,
        limit: int,
    ) -> list[EventClockDrift]:
        rows = await self.pool.fetch(
            """
            SELECT event_id, asset_id, source_module, drift_seconds,
                   timestamp_local, timestamp_received
            FROM event_clock_drifts
            WHERE asset_id = $1
            ORDER BY detected_at DESC
            LIMIT $2
            """,
            asset_id,
            limit,
        )
        return [
            EventClockDrift(
                event_id=row["event_id"],
                asset_id=row["asset_id"],
                source_module=row["source_module"],
                drift_seconds=row["drift_seconds"],
                timestamp_local=row["timestamp_local"],
                timestamp_received=row["timestamp_received"],
            )
            for row in rows
        ]

    async def list_event_ingest_logs(
        self,
        tenant_id: Optional[str],
        asset_id: Optional[str],
        status: Optional[str],
        limit: int,
        since: Optional[datetime],
    ) -> list["EventIngestLogRecord"]:
        conditions = ["1=1"]
        params: list[object] = []
        if tenant_id:
            params.append(tenant_id)
            conditions.append(f"tenant_id = ${len(params)}")
        if asset_id:
            params.append(asset_id)
            conditions.append(f"asset_id = ${len(params)}")
        if status:
            params.append(status)
            conditions.append(f"status = ${len(params)}")
        if since:
            params.append(since)
            conditions.append(f"received_at >= ${len(params)}")
        params.append(limit)
        query = f"""
            SELECT payload_id,
                   tenant_id,
                   asset_id,
                   status,
                   received_at,
                   processed_at,
                   event_count,
                   accepted_count,
                   rejected_count,
                   reject_reason,
                   signature_verified,
                   schema_version
            FROM event_ingest_log
            WHERE {" AND ".join(conditions)}
            ORDER BY received_at DESC
            LIMIT ${len(params)}
        """
        rows = await self.pool.fetch(query, *params)
        return [
            EventIngestLogRecord(
                payload_id=row["payload_id"],
                tenant_id=row["tenant_id"],
                asset_id=row["asset_id"],
                status=row["status"],
                received_at=row["received_at"],
                processed_at=row["processed_at"],
                event_count=row["event_count"],
                accepted_count=row["accepted_count"],
                rejected_count=row["rejected_count"],
                reject_reason=row["reject_reason"],
                signature_verified=row["signature_verified"],
                schema_version=row["schema_version"],
            )
            for row in rows
        ]

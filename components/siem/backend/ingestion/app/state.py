"""Derived asset state for MVP-3 inventory."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from .models import InventorySnapshot


@dataclass
class AssetState:
    asset_id: str
    hostname: Optional[str]
    os_name: Optional[str]
    os_version: Optional[str]
    software_count: int
    users_count: int
    groups_count: int


def derive_state(asset_id: str, snapshot: InventorySnapshot) -> AssetState:
    software_count = len(snapshot.software.items) if snapshot.software else 0
    users_count = len(snapshot.users.users) if snapshot.users else 0
    groups_count = len(snapshot.groups.groups) if snapshot.groups else 0

    hostname = None
    for source in (
        snapshot.hardware,
        snapshot.os,
        snapshot.software,
        snapshot.users,
        snapshot.groups,
    ):
        if source and source.hostname:
            hostname = source.hostname
            break
    os_name = snapshot.os.os_name if snapshot.os else None
    os_version = snapshot.os.os_version if snapshot.os else None

    return AssetState(
        asset_id=asset_id,
        hostname=hostname,
        os_name=os_name,
        os_version=os_version,
        software_count=software_count,
        users_count=users_count,
        groups_count=groups_count,
    )

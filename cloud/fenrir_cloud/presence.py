"""Whether a device is up, decided in one place so every page agrees.

How often each kind of device is heard from:

- Windows, Linux and macOS agents hold a live connection to the server and send a ping on it every 30 seconds; each
  ping counts as a check-in. Without the live connection they poll for commands every 15 seconds (Windows, Linux and
  macOS) and send a heartbeat every 60 seconds. So an agent that is up is heard from at least every 30 seconds.
- Android phones check in every 30 seconds (heartbeat every 60) while awake. When the phone sleeps, Android's power
  saving (Doze) holds the app back and a wake-up alarm gets through about every 10 minutes, sometimes later.
- iPhones, iPads and Macs with only the web protection profile are heard from whenever they look a website up.

So: an agent is **online** when heard from in the last 2 minutes (four missed pings). A phone heard from in the last
30 minutes but not the last 2 is **asleep**: normal, and it picks up actions when it next wakes. Profile-only devices
are online when they looked something up in the last 15 minutes and idle after that. Anything else is **offline**.
"""

from __future__ import annotations

from datetime import datetime, timedelta

from sqlalchemy import and_, or_

from .models import Device, utcnow

ONLINE_AFTER = timedelta(minutes=2)
PHONE_ASLEEP_AFTER = timedelta(minutes=30)
PROFILE_IDLE_AFTER = timedelta(minutes=15)
TOUCH_EVERY = timedelta(seconds=20)  # the most often one device's last-seen time is written
PHONE_PLATFORMS = ("android",)


def _profile(device: Device) -> bool:
    return bool((device.metrics or {}).get("agentless"))


def retired(device: Device) -> bool:
    return device.api_key_hash == f"retired-{device.id}"


def state(device: Device, now: datetime | None = None) -> str:
    """online | asleep (a phone saving power) | idle (a profile-only device not browsing) | offline | retired"""
    now = now or utcnow()
    if retired(device):
        return "retired"
    seen = device.last_seen_at
    if seen is None:
        return "offline"
    age = now - seen
    if _profile(device):
        return "online" if age <= PROFILE_IDLE_AFTER else "idle"
    if age <= ONLINE_AFTER:
        return "online"
    if device.platform in PHONE_PLATFORMS and age <= PHONE_ASLEEP_AFTER:
        return "asleep"
    return "offline"


def is_up(device: Device, now: datetime | None = None) -> bool:
    """Counts as up in totals: online, or a phone asleep (which is not a fault)."""
    return state(device, now) in ("online", "asleep")


def up_clause(now: datetime | None = None):
    """The SQL form of is_up, for list filters."""
    now = now or utcnow()
    profile = Device.api_key_hash.like("profile-%")
    return or_(
        and_(~profile, Device.last_seen_at >= now - ONLINE_AFTER),
        and_(~profile, Device.platform.in_(PHONE_PLATFORMS), Device.last_seen_at >= now - PHONE_ASLEEP_AFTER),
        and_(profile, Device.last_seen_at >= now - PROFILE_IDLE_AFTER),
    )


def touch(device: Device, now: datetime | None = None) -> bool:
    """Record a check-in, at most every TOUCH_EVERY. True when it wrote."""
    now = now or utcnow()
    if device.last_seen_at is not None and now - device.last_seen_at < TOUCH_EVERY:
        return False
    device.last_seen_at = now
    return True

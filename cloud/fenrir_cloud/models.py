"""ORM models for every Fenrir Cloud module.

Kept in one file on purpose: the security, SIEM, and CRM sides reference each
other constantly (an incident opens a ticket, a ticket bills a contract, a
contract covers a tenant's devices) and one module avoids import cycles.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import BigInteger, JSON, Boolean, DateTime, Float, ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from .db import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:20]}"


# --------------------------------------------------------------------------
# Tenancy and identity
# --------------------------------------------------------------------------


class Tenant(Base):
    """A customer organisation. The MSP itself is the root tenant."""

    __tablename__ = "tenants"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: new_id("ten"))
    name: Mapped[str] = mapped_column(String(200))
    slug: Mapped[str] = mapped_column(String(80), unique=True)
    parent_id: Mapped[str | None] = mapped_column(ForeignKey("tenants.id"), nullable=True)
    kind: Mapped[str] = mapped_column(String(20), default="customer")  # msp | customer | unassigned
    plan: Mapped[str] = mapped_column(String(40), default="complete")  # essentials | advanced | complete | mdr
    default_policy_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    settings: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    account_owner: Mapped[str | None] = mapped_column(String(200), nullable=True)  # MSP staff member who owns the customer


class User(Base):
    __tablename__ = "users"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: new_id("usr"))
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"))
    email: Mapped[str] = mapped_column(String(200), unique=True)
    name: Mapped[str] = mapped_column(String(200), default="")
    password_hash: Mapped[str] = mapped_column(String(300))
    role: Mapped[str] = mapped_column(String(40), default="viewer")
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    # TOTP multi-factor authentication. The seed is stored encrypted (crypto.encrypt envelope).
    mfa_enabled: Mapped[bool | None] = mapped_column(Boolean, nullable=True, default=False)
    mfa_secret: Mapped[dict | None] = mapped_column(JSON, nullable=True)


class AuditLog(Base):
    """Append-only, hash-chained audit trail (each row commits to the previous)."""

    __tablename__ = "audit_log"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    tenant_id: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    actor: Mapped[str] = mapped_column(String(200))
    action: Mapped[str] = mapped_column(String(120))
    target: Mapped[str] = mapped_column(String(200), default="")
    details: Mapped[dict] = mapped_column(JSON, default=dict)
    at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    prev_hash: Mapped[str] = mapped_column(String(64), default="")
    hash: Mapped[str] = mapped_column(String(64), default="")


# --------------------------------------------------------------------------
# Fleet
# --------------------------------------------------------------------------


class DeviceGroup(Base):
    __tablename__ = "device_groups"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: new_id("grp"))
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    parent_id: Mapped[str | None] = mapped_column(ForeignKey("device_groups.id"), nullable=True)
    name: Mapped[str] = mapped_column(String(200))
    policy_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    # Dynamic membership, e.g. {"platform": "windows", "tag": "servers"}
    match_rules: Mapped[dict] = mapped_column(JSON, default=dict)


class EnrollmentToken(Base):
    __tablename__ = "enrollment_tokens"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: new_id("enr"))
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"))
    group_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    label: Mapped[str] = mapped_column(String(200), default="")
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    token_hint: Mapped[str] = mapped_column(String(12), default="")
    max_uses: Mapped[int | None] = mapped_column(Integer, nullable=True)
    uses: Mapped[int] = mapped_column(Integer, default=0)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class Device(Base):
    __tablename__ = "devices"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: new_id("dev"))
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    group_id: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    hostname: Mapped[str] = mapped_column(String(255))
    platform: Mapped[str] = mapped_column(String(20), default="windows")
    os_version: Mapped[str] = mapped_column(String(255), default="")
    serial_number: Mapped[str] = mapped_column(String(255), default="")
    agent_version: Mapped[str] = mapped_column(String(64), default="")
    platform_version: Mapped[str] = mapped_column(String(64), default="")
    health_state: Mapped[str] = mapped_column(String(40), default="unknown")
    isolated: Mapped[bool] = mapped_column(Boolean, default=False)
    approved: Mapped[bool] = mapped_column(Boolean, default=True)
    api_key_hash: Mapped[str] = mapped_column(String(64), unique=True)
    dns_token: Mapped[str] = mapped_column(String(48), unique=True)
    policy_id: Mapped[str | None] = mapped_column(String(32), nullable=True)  # device-level override
    applied_policy_revision: Mapped[str] = mapped_column(String(64), default="")
    tags: Mapped[list] = mapped_column(JSON, default=list)
    risk_score: Mapped[int] = mapped_column(Integer, default=0)
    inventory: Mapped[dict] = mapped_column(JSON, default=dict)
    ip_address: Mapped[str] = mapped_column(String(64), default="")
    # Live health from the agent heartbeat: cpu/memory/disks/uptime/logged-on user/reboot pending.
    metrics: Mapped[dict | None] = mapped_column(JSON, default=dict, nullable=True)
    custom_fields: Mapped[dict | None] = mapped_column(JSON, default=dict, nullable=True)
    site_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    notes: Mapped[str | None] = mapped_column(Text, default="", nullable=True)
    enrolled_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    # Business criticality (low|medium|high|critical) used to rank vulnerabilities and alerts.
    criticality: Mapped[str | None] = mapped_column(String(16), nullable=True, default="medium")
    # Last maintenance window in which protection-policy patching ran on this device ("2026-10-25T22:00").
    patch_window_run: Mapped[str | None] = mapped_column(String(20), nullable=True)


class Policy(Base):
    """A layered protection policy. ``settings`` holds only the keys this layer sets."""

    __tablename__ = "policies"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: new_id("pol"))
    tenant_id: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)  # null = global
    parent_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    name: Mapped[str] = mapped_column(String(200))
    description: Mapped[str] = mapped_column(Text, default="")
    template: Mapped[str] = mapped_column(String(40), default="balanced")
    settings: Mapped[dict] = mapped_column(JSON, default=dict)
    # Dotted keys this layer forces on every child ("antimalware.realtimeProtection").
    locks: Mapped[list] = mapped_column(JSON, default=list)
    version: Mapped[int] = mapped_column(Integer, default=1)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_by: Mapped[str] = mapped_column(String(200), default="system")


class Command(Base):
    __tablename__ = "commands"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: new_id("cmd"))
    tenant_id: Mapped[str] = mapped_column(String(32), index=True)
    device_id: Mapped[str] = mapped_column(ForeignKey("devices.id"), index=True)
    type: Mapped[str] = mapped_column(String(80))
    status: Mapped[str] = mapped_column(String(20), default="pending")  # pending|dispatched|completed|failed|cancelled
    issued_by: Mapped[str] = mapped_column(String(200))
    target_path: Mapped[str] = mapped_column(Text, default="")
    record_id: Mapped[str] = mapped_column(String(200), default="")
    payload: Mapped[dict] = mapped_column(JSON, default=dict)
    result: Mapped[dict] = mapped_column(JSON, default=dict)
    reason: Mapped[str] = mapped_column(Text, default="")
    incident_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    dispatched_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class DeviceArtifact(Base):
    """A forensic or support bundle an agent uploaded for a command."""

    __tablename__ = "device_artifacts"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: new_id("art"))
    tenant_id: Mapped[str] = mapped_column(String(32), index=True)
    device_id: Mapped[str] = mapped_column(String(32), index=True)
    command_id: Mapped[str] = mapped_column(String(32), index=True)
    kind: Mapped[str] = mapped_column(String(40))  # the command type that produced it
    filename: Mapped[str] = mapped_column(String(200))
    size: Mapped[int] = mapped_column(BigInteger, default=0)
    sha256: Mapped[str] = mapped_column(String(64))
    storage_name: Mapped[str] = mapped_column(String(80))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class DeviceProfile(Base):
    """The agent's full system profile (hardware, disks and SMART, volumes, users, network, battery, security
    posture, event-log problems...), replaced each time the agent reports it (every 6 hours or on demand)."""

    __tablename__ = "device_profiles"
    device_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(32), index=True)
    profile: Mapped[dict] = mapped_column(JSON, default=dict)
    collected_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class RecoveryKey(Base):
    """A disk-encryption recovery key (BitLocker recovery password) escrowed by the agent, encrypted with the
    vault key. Revealing one needs re-authentication and is audited, like local admin passwords."""

    __tablename__ = "recovery_keys"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: new_id("rk"))
    tenant_id: Mapped[str] = mapped_column(String(32), index=True)
    device_id: Mapped[str] = mapped_column(String(32), index=True)
    volume: Mapped[str] = mapped_column(String(64))
    key_id: Mapped[str] = mapped_column(String(64))  # protector id, e.g. {8B1C...}
    kind: Mapped[str] = mapped_column(String(32), default="bitlocker")
    ciphertext: Mapped[dict] = mapped_column(JSON, default=dict)
    status: Mapped[str] = mapped_column(String(16), default="active")  # active | removed
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class ElevationRequest(Base):
    """A signed-in user asking for temporary local admin rights (privilege.elevationRequests).

    pending -> approved (a technician or the auto-approve policy; elevation.grant is queued) -> granted (the
    agent added the user) -> expired; or denied / failed / revoked.
    """

    __tablename__ = "elevation_requests"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: new_id("elv"))
    tenant_id: Mapped[str] = mapped_column(String(32), index=True)
    device_id: Mapped[str] = mapped_column(String(32), index=True)
    user: Mapped[str] = mapped_column(String(200))
    user_sid: Mapped[str] = mapped_column(String(200))
    reason: Mapped[str] = mapped_column(String(1000), default="")
    minutes: Mapped[int] = mapped_column(Integer, default=30)
    status: Mapped[str] = mapped_column(String(16), default="pending", index=True)
    decided_by: Mapped[str] = mapped_column(String(200), default="")
    decided_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    note: Mapped[str] = mapped_column(String(500), default="")
    command_id: Mapped[str] = mapped_column(String(32), default="")
    granted_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class LocalAdminPassword(Base):
    """A local administrator password the Windows agent set (LAPS-style), stored encrypted with the vault key.

    The agent escrows a new password here first (status "pending") and only then changes it on the device, so a
    password can never be set without the cloud holding it. The confirmed one becomes "active"; earlier ones are
    kept as "superseded" for recovery.
    """

    __tablename__ = "local_admin_passwords"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: new_id("lap"))
    tenant_id: Mapped[str] = mapped_column(String(32), index=True)
    device_id: Mapped[str] = mapped_column(String(32), index=True)
    account: Mapped[str] = mapped_column(String(120))
    ciphertext: Mapped[dict] = mapped_column(JSON)
    status: Mapped[str] = mapped_column(String(16), default="pending")  # pending|active|superseded|failed
    error: Mapped[str] = mapped_column(String(300), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    confirmed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class AgentRelease(Base):
    __tablename__ = "agent_releases"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: new_id("rel"))
    platform: Mapped[str] = mapped_column(String(20))
    channel: Mapped[str] = mapped_column(String(20), default="stable")
    component: Mapped[str] = mapped_column(String(40), default="agent")
    version: Mapped[str] = mapped_column(String(64))
    url: Mapped[str] = mapped_column(Text)
    sha256: Mapped[str] = mapped_column(String(64))
    signature: Mapped[str] = mapped_column(Text, default="")
    notes: Mapped[str] = mapped_column(Text, default="")
    rollout_percent: Mapped[int] = mapped_column(Integer, default=100)
    published_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


# --------------------------------------------------------------------------
# SIEM / XDR
# --------------------------------------------------------------------------


class Event(Base):
    __tablename__ = "events"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(32))
    device_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    event_id: Mapped[str] = mapped_column(String(100))
    event_type: Mapped[str] = mapped_column(String(100))
    category: Mapped[str] = mapped_column(String(40), default="other")
    source: Mapped[str] = mapped_column(String(100), default="agent")
    summary: Mapped[str] = mapped_column(Text, default="")
    severity: Mapped[str] = mapped_column(String(16), default="info")
    occurred_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    received_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    fields: Mapped[dict] = mapped_column(JSON, default=dict)

    __table_args__ = (
        Index("ix_events_tenant_time", "tenant_id", "occurred_at"),
        Index("ix_events_device_time", "device_id", "occurred_at"),
        UniqueConstraint("device_id", "event_id", name="uq_events_device_event"),
    )


class DetectionRule(Base):
    __tablename__ = "detection_rules"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str | None] = mapped_column(String(32), nullable=True)  # null = global
    title: Mapped[str] = mapped_column(String(300))
    kind: Mapped[str] = mapped_column(String(20), default="sigma")  # sigma | correlation
    source: Mapped[str] = mapped_column(Text)
    level: Mapped[str] = mapped_column(String(16), default="medium")
    mitre: Mapped[list] = mapped_column(JSON, default=list)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    builtin: Mapped[bool] = mapped_column(Boolean, default=False)
    # Optional auto-response: list of command types to queue when this fires.
    response: Mapped[list] = mapped_column(JSON, default=list)
    hits: Mapped[int] = mapped_column(Integer, default=0)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class RuleMatch(Base):
    """Lightweight record of every rule hit; correlation rules count these."""

    __tablename__ = "rule_matches"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(32))
    rule_id: Mapped[str] = mapped_column(String(64))
    device_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    group_key: Mapped[str] = mapped_column(String(300), default="")
    event_pk: Mapped[int | None] = mapped_column(Integer, nullable=True)
    at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    __table_args__ = (Index("ix_rule_matches_lookup", "rule_id", "tenant_id", "group_key", "at"),)


class Alert(Base):
    __tablename__ = "alerts"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: new_id("alr"))
    tenant_id: Mapped[str] = mapped_column(String(32), index=True)
    device_id: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    rule_id: Mapped[str] = mapped_column(String(64))
    title: Mapped[str] = mapped_column(String(300))
    severity: Mapped[str] = mapped_column(String(16), default="medium")
    status: Mapped[str] = mapped_column(String(20), default="new")  # new|triaged|resolved|false_positive
    mitre: Mapped[list] = mapped_column(JSON, default=list)
    event_ids: Mapped[list] = mapped_column(JSON, default=list)
    details: Mapped[dict] = mapped_column(JSON, default=dict)
    incident_id: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class Incident(Base):
    __tablename__ = "incidents"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: new_id("inc"))
    tenant_id: Mapped[str] = mapped_column(String(32), index=True)
    device_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    title: Mapped[str] = mapped_column(String(300))
    severity: Mapped[str] = mapped_column(String(16), default="medium")
    status: Mapped[str] = mapped_column(String(20), default="open")  # open|investigating|contained|resolved|closed
    assignee: Mapped[str] = mapped_column(String(200), default="")
    mitre: Mapped[list] = mapped_column(JSON, default=list)
    alert_count: Mapped[int] = mapped_column(Integer, default=0)
    ticket_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    playbook: Mapped[str] = mapped_column(String(80), default="")
    checklist: Mapped[list] = mapped_column(JSON, default=list)
    timeline: Mapped[list] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class AutomationRule(Base):
    """SOAR rule: when an alert matches, run actions."""

    __tablename__ = "automation_rules"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: new_id("aut"))
    tenant_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    name: Mapped[str] = mapped_column(String(200))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    # {"minSeverity": "high", "ruleIds": [...], "mitre": ["T1486"], "titleContains": "ransom"}
    conditions: Mapped[dict] = mapped_column(JSON, default=dict)
    # [{"type": "command", "command": "device.isolate"}, {"type": "ticket"}, {"type": "webhook", "url": ...}]
    actions: Mapped[list] = mapped_column(JSON, default=list)
    runs: Mapped[int] = mapped_column(Integer, default=0)


# --------------------------------------------------------------------------
# Threat intelligence and DNS protection
# --------------------------------------------------------------------------


class Indicator(Base):
    __tablename__ = "indicators"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    tenant_id: Mapped[str | None] = mapped_column(String(32), nullable=True)  # null = global
    type: Mapped[str] = mapped_column(String(16))  # sha256|md5|sha1|domain|url|ip
    value: Mapped[str] = mapped_column(String(2048))
    verdict: Mapped[str] = mapped_column(String(16), default="malicious")  # malicious|suspicious|allow
    category: Mapped[str] = mapped_column(String(40), default="malware")
    source: Mapped[str] = mapped_column(String(100), default="manual")
    confidence: Mapped[int] = mapped_column(Integer, default=80)
    description: Mapped[str] = mapped_column(Text, default="")
    expires_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    __table_args__ = (Index("ix_indicators_lookup", "type", "value"),)


class YaraRule(Base):
    __tablename__ = "yara_rules"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: new_id("yar"))
    tenant_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    name: Mapped[str] = mapped_column(String(200))
    source: Mapped[str] = mapped_column(Text)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    origin: Mapped[str] = mapped_column(String(100), default="custom")
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class DnsQueryLog(Base):
    __tablename__ = "dns_query_log"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(32), index=True)
    device_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    qname: Mapped[str] = mapped_column(String(255))
    qtype: Mapped[str] = mapped_column(String(12))
    action: Mapped[str] = mapped_column(String(12))  # allow|block|sinkhole
    reason: Mapped[str] = mapped_column(String(200), default="")
    category: Mapped[str] = mapped_column(String(40), default="")
    at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


# --------------------------------------------------------------------------
# Exposure management (vulnerabilities, attack surface, compliance)
# --------------------------------------------------------------------------


class SoftwareItem(Base):
    __tablename__ = "software_items"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(32), index=True)
    device_id: Mapped[str] = mapped_column(String(32), index=True)
    name: Mapped[str] = mapped_column(String(300))
    version: Mapped[str] = mapped_column(String(100), default="")
    vendor: Mapped[str] = mapped_column(String(200), default="")
    ecosystem: Mapped[str] = mapped_column(String(40), default="")  # e.g. Debian:12, Ubuntu:22.04, windows
    seen_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(32), index=True)
    device_id: Mapped[str] = mapped_column(String(32), index=True)
    vuln_id: Mapped[str] = mapped_column(String(80))  # CVE-…, GHSA-…, DSA-…
    package: Mapped[str] = mapped_column(String(300))
    installed_version: Mapped[str] = mapped_column(String(100), default="")
    fixed_version: Mapped[str] = mapped_column(String(100), default="")
    severity: Mapped[str] = mapped_column(String(16), default="medium")
    cvss: Mapped[float | None] = mapped_column(Float, nullable=True)
    known_exploited: Mapped[bool] = mapped_column(Boolean, default=False)
    summary: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String(20), default="open")  # open|patching|mitigated|accepted|fixed
    source: Mapped[str] = mapped_column(String(40), default="osv")
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    # Remediation workflow. "fixed" is only set by a rescan that no longer finds the vulnerability.
    assignee: Mapped[str | None] = mapped_column(String(200), nullable=True)
    ticket_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    due_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    status_changed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    verified_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    exception_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    exception_approved_by: Mapped[str | None] = mapped_column(String(200), nullable=True)
    exception_expires_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    __table_args__ = (UniqueConstraint("device_id", "vuln_id", "package", name="uq_vuln_device"),)


class ExternalAsset(Base):
    __tablename__ = "external_assets"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: new_id("ext"))
    tenant_id: Mapped[str] = mapped_column(String(32), index=True)
    target: Mapped[str] = mapped_column(String(255))  # hostname or IP the tenant owns
    label: Mapped[str] = mapped_column(String(200), default="")
    ownership_attested_by: Mapped[str] = mapped_column(String(200))
    last_scan_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_result: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


# --------------------------------------------------------------------------
# CRM / PSA / billing
# --------------------------------------------------------------------------


class Contact(Base):
    __tablename__ = "crm_contacts"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: new_id("con"))
    tenant_id: Mapped[str] = mapped_column(String(32), index=True)  # owning MSP tenant
    account_tenant_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    name: Mapped[str] = mapped_column(String(200))
    email: Mapped[str] = mapped_column(String(200), default="")
    phone: Mapped[str] = mapped_column(String(60), default="")
    title: Mapped[str] = mapped_column(String(120), default="")
    is_primary: Mapped[bool] = mapped_column(Boolean, default=False)
    notes: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class Lead(Base):
    __tablename__ = "crm_leads"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: new_id("led"))
    tenant_id: Mapped[str] = mapped_column(String(32), index=True)
    company: Mapped[str] = mapped_column(String(200))
    contact: Mapped[str] = mapped_column(String(200), default="")
    email: Mapped[str] = mapped_column(String(200), default="")
    phone: Mapped[str] = mapped_column(String(60), default="")
    stage: Mapped[str] = mapped_column(String(40), default="New")  # New|Contacted|Qualified|Proposal|Won|Lost
    value: Mapped[float] = mapped_column(Float, default=0)
    seats: Mapped[int] = mapped_column(Integer, default=0)
    source: Mapped[str] = mapped_column(String(80), default="")
    owner: Mapped[str] = mapped_column(String(200), default="")
    notes: Mapped[str] = mapped_column(Text, default="")
    converted_tenant_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class Opportunity(Base):
    """A deal: new business from a lead, or an upsell/renewal for an existing customer."""

    __tablename__ = "crm_opportunities"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: new_id("opp"))
    tenant_id: Mapped[str] = mapped_column(String(32), index=True)  # owning MSP tenant
    account_tenant_id: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    lead_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    name: Mapped[str] = mapped_column(String(200))
    kind: Mapped[str] = mapped_column(String(30), default="New business")  # New business|Upsell|Renewal|Project
    stage: Mapped[str] = mapped_column(String(30), default="Prospecting")
    value: Mapped[float] = mapped_column(Float, default=0)  # one-off value
    monthly_value: Mapped[float] = mapped_column(Float, default=0)  # recurring value per month
    probability: Mapped[int] = mapped_column(Integer, default=10)
    close_date: Mapped[str] = mapped_column(String(20), default="")
    owner: Mapped[str] = mapped_column(String(200), default="")
    source: Mapped[str] = mapped_column(String(80), default="")
    notes: Mapped[str] = mapped_column(Text, default="")
    lost_reason: Mapped[str] = mapped_column(String(300), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    closed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class Activity(Base):
    """Communication history and follow-ups: calls, emails, meetings, notes and tasks."""

    __tablename__ = "crm_activities"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: new_id("act"))
    tenant_id: Mapped[str] = mapped_column(String(32), index=True)
    account_tenant_id: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    contact_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    lead_id: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    opportunity_id: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    kind: Mapped[str] = mapped_column(String(20), default="note")  # call|email|meeting|note|task
    direction: Mapped[str] = mapped_column(String(10), default="")  # inbound|outbound|""
    subject: Mapped[str] = mapped_column(String(300))
    body: Mapped[str] = mapped_column(Text, default="")
    owner: Mapped[str] = mapped_column(String(200), default="")
    due_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_by: Mapped[str] = mapped_column(String(200), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class Project(Base):
    __tablename__ = "crm_projects"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: new_id("prj"))
    tenant_id: Mapped[str] = mapped_column(String(32), index=True)
    account_tenant_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    name: Mapped[str] = mapped_column(String(200))
    status: Mapped[str] = mapped_column(String(40), default="Planning")
    progress: Mapped[int] = mapped_column(Integer, default=0)
    budget: Mapped[float] = mapped_column(Float, default=0)
    due_date: Mapped[str] = mapped_column(String(20), default="")
    tasks: Mapped[list] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    manager: Mapped[str | None] = mapped_column(String(200), default="", nullable=True)
    billing_method: Mapped[str | None] = mapped_column(String(30), default="Time & Materials", nullable=True)  # or Fixed Fee
    estimated_hours: Mapped[float | None] = mapped_column(Float, default=0, nullable=True)
    start_date: Mapped[str | None] = mapped_column(String(20), default="", nullable=True)
    # [{"name": "Discovery", "status": "Open", "budgetHours": 4, "tasks": [{"text": "...", "done": false}]}]
    phases: Mapped[list | None] = mapped_column(JSON, default=list, nullable=True)
    description: Mapped[str | None] = mapped_column(Text, default="", nullable=True)


class Ticket(Base):
    __tablename__ = "psa_tickets"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: new_id("tkt"))
    number: Mapped[int] = mapped_column(Integer, index=True)
    tenant_id: Mapped[str] = mapped_column(String(32), index=True)  # owning MSP tenant
    account_tenant_id: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    subject: Mapped[str] = mapped_column(String(300))
    description: Mapped[str] = mapped_column(Text, default="")
    priority: Mapped[str] = mapped_column(String(16), default="P3")  # P1..P4
    status: Mapped[str] = mapped_column(String(30), default="Open")  # Open|In Progress|Waiting|Resolved|Closed
    queue: Mapped[str] = mapped_column(String(60), default="Service Desk")
    assignee: Mapped[str] = mapped_column(String(200), default="")
    requester: Mapped[str] = mapped_column(String(200), default="")
    source: Mapped[str] = mapped_column(String(40), default="manual")  # manual|incident|email|portal|vulnerability
    incident_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    device_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    sla_due_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    time_minutes: Mapped[int] = mapped_column(Integer, default=0)
    billable: Mapped[bool] = mapped_column(Boolean, default=True)
    comments: Mapped[list] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    # Service board fields. Nullable so older databases gain them with ALTER TABLE.
    board_id: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    type: Mapped[str | None] = mapped_column(String(80), default="", nullable=True)
    subtype: Mapped[str | None] = mapped_column(String(80), default="", nullable=True)
    item: Mapped[str | None] = mapped_column(String(80), default="", nullable=True)
    impact: Mapped[str | None] = mapped_column(String(10), default="Medium", nullable=True)
    urgency: Mapped[str | None] = mapped_column(String(10), default="Medium", nullable=True)
    site_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    contact_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    contact_email: Mapped[str | None] = mapped_column(String(200), default="", nullable=True)
    agreement_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    project_id: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    phase: Mapped[str | None] = mapped_column(String(120), default="", nullable=True)
    parent_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    resources: Mapped[list | None] = mapped_column(JSON, default=list, nullable=True)  # extra assigned members
    team: Mapped[str | None] = mapped_column(String(80), default="", nullable=True)
    configuration_ids: Mapped[list | None] = mapped_column(JSON, default=list, nullable=True)
    tasks: Mapped[list | None] = mapped_column(JSON, default=list, nullable=True)  # [{text, done, by, at}]
    budget_hours: Mapped[float | None] = mapped_column(Float, default=0, nullable=True)
    required_date: Mapped[str | None] = mapped_column(String(20), default="", nullable=True)
    responded_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    respond_due_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    sla_warned: Mapped[bool | None] = mapped_column(Boolean, default=False, nullable=True)
    # ITIL record type and problem/change management (all optional; plain tickets are incidents).
    record_type: Mapped[str | None] = mapped_column(String(20), default="incident", nullable=True)  # incident|service_request|problem|change
    problem_id: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)  # incident -> its problem
    root_cause: Mapped[str | None] = mapped_column(Text, default="", nullable=True)
    workaround: Mapped[str | None] = mapped_column(Text, default="", nullable=True)
    known_error: Mapped[bool | None] = mapped_column(Boolean, default=False, nullable=True)
    change_risk: Mapped[str | None] = mapped_column(String(10), default="", nullable=True)  # Low|Medium|High
    change_state: Mapped[str | None] = mapped_column(String(20), default="", nullable=True)
    planned_start: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    planned_end: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    implementation_plan: Mapped[str | None] = mapped_column(Text, default="", nullable=True)
    backout_plan: Mapped[str | None] = mapped_column(Text, default="", nullable=True)
    test_plan: Mapped[str | None] = mapped_column(Text, default="", nullable=True)
    change_approvals: Mapped[list | None] = mapped_column(JSON, default=list, nullable=True)  # [{by, decision, comment, at}]
    status_changed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    email_thread_id: Mapped[str | None] = mapped_column(String(300), default="", nullable=True)
    workflow_fired: Mapped[list | None] = mapped_column(JSON, default=list, nullable=True)  # markers so timed rules fire once


class Contract(Base):
    __tablename__ = "billing_contracts"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: new_id("ctr"))
    tenant_id: Mapped[str] = mapped_column(String(32), index=True)  # owning MSP tenant
    account_tenant_id: Mapped[str] = mapped_column(String(32), index=True)
    name: Mapped[str] = mapped_column(String(200))
    plan: Mapped[str] = mapped_column(String(40), default="complete")
    price_per_device: Mapped[float] = mapped_column(Float, default=0)
    monthly_fee: Mapped[float] = mapped_column(Float, default=0)
    hourly_rate: Mapped[float] = mapped_column(Float, default=0)
    included_hours: Mapped[float] = mapped_column(Float, default=0)
    currency: Mapped[str] = mapped_column(String(3), default="GBP")
    sla: Mapped[dict] = mapped_column(JSON, default=dict)  # {"P1": 1, "P2": 4, "P3": 24, "P4": 72} hours
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    start_date: Mapped[str] = mapped_column(String(20), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    # Agreement fields (ConnectWise-style). Managed Services | Block Hours | Retainer | Time & Materials
    agreement_type: Mapped[str | None] = mapped_column(String(40), default="Managed Services", nullable=True)
    billing_cycle: Mapped[str | None] = mapped_column(String(20), default="Monthly", nullable=True)  # Monthly|Quarterly|Annually
    end_date: Mapped[str | None] = mapped_column(String(20), default="", nullable=True)
    covered_work_types: Mapped[list | None] = mapped_column(JSON, default=list, nullable=True)  # empty = all covered
    covers_after_hours: Mapped[bool | None] = mapped_column(Boolean, default=False, nullable=True)
    # [{"product": "Backup per server", "quantity": 2, "unitPrice": 15, "autoCount": "devices:windows"}]
    additions: Mapped[list | None] = mapped_column(JSON, default=list, nullable=True)
    business_hours: Mapped[dict | None] = mapped_column(JSON, default=dict, nullable=True)  # {"days":[0..4],"start":9,"end":17,"tz":"Europe/London"}
    notes: Mapped[str | None] = mapped_column(Text, default="", nullable=True)


class Invoice(Base):
    __tablename__ = "billing_invoices"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: new_id("inv"))
    number: Mapped[str] = mapped_column(String(40), index=True)
    tenant_id: Mapped[str] = mapped_column(String(32), index=True)
    account_tenant_id: Mapped[str] = mapped_column(String(32), index=True)
    contract_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    period: Mapped[str] = mapped_column(String(7), default="")  # YYYY-MM
    lines: Mapped[list] = mapped_column(JSON, default=list)
    subtotal: Mapped[float] = mapped_column(Float, default=0)
    tax_rate: Mapped[float] = mapped_column(Float, default=0.2)
    total: Mapped[float] = mapped_column(Float, default=0)
    currency: Mapped[str] = mapped_column(String(3), default="GBP")
    status: Mapped[str] = mapped_column(String(20), default="Draft")  # Draft|Sent|Paid|Overdue|Void
    due_date: Mapped[str] = mapped_column(String(20), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class Webhook(Base):
    __tablename__ = "webhooks"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: new_id("whk"))
    tenant_id: Mapped[str] = mapped_column(String(32), index=True)
    name: Mapped[str] = mapped_column(String(200))
    url: Mapped[str] = mapped_column(Text)
    kind: Mapped[str] = mapped_column(String(20), default="generic")  # generic|slack|teams
    events: Mapped[list] = mapped_column(JSON, default=lambda: ["incident.created"])
    secret: Mapped[str] = mapped_column(String(80), default="")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)



# --------------------------------------------------------------------------
# RMM: scripting, jobs, scheduling, monitoring, patching, software
# --------------------------------------------------------------------------


class Script(Base):
    """A reusable script in the library. Parameters become a form when it is run."""

    __tablename__ = "rmm_scripts"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: new_id("scr"))
    tenant_id: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)  # null = shared built-in
    name: Mapped[str] = mapped_column(String(200))
    description: Mapped[str] = mapped_column(Text, default="")
    category: Mapped[str] = mapped_column(String(80), default="General")
    language: Mapped[str] = mapped_column(String(20), default="powershell")  # powershell|cmd|bash|sh|python
    platforms: Mapped[list] = mapped_column(JSON, default=lambda: ["windows"])
    body: Mapped[str] = mapped_column(Text, default="")
    # [{"name": "ServiceName", "label": "Service", "type": "string|number|boolean|choice", "default": "", "required": true, "choices": []}]
    parameters: Mapped[list] = mapped_column(JSON, default=list)
    run_as: Mapped[str] = mapped_column(String(20), default="system")  # system|user
    timeout_seconds: Mapped[int] = mapped_column(Integer, default=600)
    version: Mapped[int] = mapped_column(Integer, default=1)
    builtin: Mapped[bool] = mapped_column(Boolean, default=False)
    updated_by: Mapped[str] = mapped_column(String(200), default="system")
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class Job(Base):
    """One run of an action across many devices (a script, patch install, software deploy...)."""

    __tablename__ = "rmm_jobs"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: new_id("job"))
    tenant_id: Mapped[str] = mapped_column(String(32), index=True)
    name: Mapped[str] = mapped_column(String(200))
    kind: Mapped[str] = mapped_column(String(30), default="script")  # script|command|patch|software
    command_type: Mapped[str] = mapped_column(String(80), default="script.run")
    script_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    parameters: Mapped[dict] = mapped_column(JSON, default=dict)
    payload: Mapped[dict] = mapped_column(JSON, default=dict)
    targets: Mapped[dict] = mapped_column(JSON, default=dict)  # {"deviceIds": [], "groupIds": [], "tenantIds": [], "platforms": []}
    # {deviceId: commandId}
    command_ids: Mapped[dict] = mapped_column(JSON, default=dict)
    status: Mapped[str] = mapped_column(String(20), default="running")  # running|completed|failed|partial|cancelled
    created_by: Mapped[str] = mapped_column(String(200), default="system")
    scheduled_task_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    ticket_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class ScheduledTask(Base):
    """Run scripts/commands on a schedule against a set of devices."""

    __tablename__ = "rmm_scheduled_tasks"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: new_id("sch"))
    tenant_id: Mapped[str] = mapped_column(String(32), index=True)
    name: Mapped[str] = mapped_column(String(200))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    # {"type": "once|interval|daily|weekly|monthly", "at": "02:00", "days": [0..6], "dayOfMonth": 1, "everyMinutes": 60, "date": "2026-11-01"}
    schedule: Mapped[dict] = mapped_column(JSON, default=dict)
    targets: Mapped[dict] = mapped_column(JSON, default=dict)
    # [{"type": "script", "scriptId": "...", "parameters": {}} | {"type": "command", "command": "patch.install", "payload": {}}]
    actions: Mapped[list] = mapped_column(JSON, default=list)
    run_offline_on_reconnect: Mapped[bool] = mapped_column(Boolean, default=True)
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    next_run_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_by: Mapped[str] = mapped_column(String(200), default="system")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class MonitorCondition(Base):
    """A health check evaluated against agent heartbeats (CPU, disk, offline, service down...)."""

    __tablename__ = "rmm_conditions"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: new_id("mon"))
    tenant_id: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)  # null = every tenant
    name: Mapped[str] = mapped_column(String(200))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    # cpu|memory|disk_free_percent|disk_free_gb|offline_minutes|service_stopped|process_missing|reboot_pending|
    # pending_patches|uptime_days|av_unhealthy|script
    metric: Mapped[str] = mapped_column(String(40))
    operator: Mapped[str] = mapped_column(String(4), default=">")  # > < >= <= == !=
    threshold: Mapped[float] = mapped_column(Float, default=0)
    target: Mapped[str] = mapped_column(String(200), default="")  # service/process name, mount point, script id
    duration_minutes: Mapped[int] = mapped_column(Integer, default=5)
    severity: Mapped[str] = mapped_column(String(16), default="medium")
    scope: Mapped[dict] = mapped_column(JSON, default=dict)  # {"groupIds": [], "platforms": [], "tags": []}
    # [{"type": "ticket"}, {"type": "script", "scriptId": "..."}, {"type": "webhook"}, {"type": "email", "to": "..."}]
    actions: Mapped[list] = mapped_column(JSON, default=list)
    auto_resolve: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class ConditionState(Base):
    """Per-device state of a monitor: when it started failing and the alert it raised."""

    __tablename__ = "rmm_condition_states"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    condition_id: Mapped[str] = mapped_column(String(32), index=True)
    device_id: Mapped[str] = mapped_column(String(32), index=True)
    tenant_id: Mapped[str] = mapped_column(String(32), index=True)
    failing_since: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    triggered: Mapped[bool] = mapped_column(Boolean, default=False)
    last_value: Mapped[float | None] = mapped_column(Float, nullable=True)
    message: Mapped[str] = mapped_column(String(300), default="")
    alert_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    ticket_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    triggered_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    __table_args__ = (UniqueConstraint("condition_id", "device_id"),)


class DeviceMetric(Base):
    """Down-sampled health history for device charts (one row per heartbeat, kept 30 days)."""

    __tablename__ = "rmm_device_metrics"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    device_id: Mapped[str] = mapped_column(String(32), index=True)
    at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    cpu: Mapped[float] = mapped_column(Float, default=0)
    memory: Mapped[float] = mapped_column(Float, default=0)
    disk_free_percent: Mapped[float] = mapped_column(Float, default=100)


class PatchPolicy(Base):
    """Approval rules, rings, maintenance window and reboot behaviour for a tenant or group."""

    __tablename__ = "rmm_patch_policies"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: new_id("ppl"))
    tenant_id: Mapped[str] = mapped_column(String(32), index=True)
    group_id: Mapped[str | None] = mapped_column(String(32), nullable=True)  # null = whole tenant
    name: Mapped[str] = mapped_column(String(200))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    # {"critical": "auto", "security": "auto", "updates": "manual", "feature": "reject", "driver": "reject",
    #  "definition": "auto", "third-party": "auto"}  values: auto | manual | reject
    approvals: Mapped[dict] = mapped_column(JSON, default=dict)
    # Auto-approved patches wait this many days after release before installing.
    delay_days: Mapped[int] = mapped_column(Integer, default=0)
    # [{"name": "Pilot", "groupIds": [...], "delayDays": 0}, {"name": "Broad", "groupIds": [], "delayDays": 7}]
    rings: Mapped[list] = mapped_column(JSON, default=list)
    # {"days": [5, 6], "start": "02:00", "durationMinutes": 180}
    window: Mapped[dict] = mapped_column(JSON, default=dict)
    # {"mode": "if_required|never|always", "notifyUser": true, "deferMinutes": 60, "maxDeferrals": 3}
    reboot: Mapped[dict] = mapped_column(JSON, default=dict)
    scan_interval_hours: Mapped[int] = mapped_column(Integer, default=12)
    last_window_run: Mapped[str] = mapped_column(String(20), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class DevicePatch(Base):
    """A patch the agent reported as missing, installed or failed on a device."""

    __tablename__ = "rmm_device_patches"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    device_id: Mapped[str] = mapped_column(String(32), index=True)
    tenant_id: Mapped[str] = mapped_column(String(32), index=True)
    patch_key: Mapped[str] = mapped_column(String(200), index=True)  # KB5034441 | apt:openssl | winget:Mozilla.Firefox
    title: Mapped[str] = mapped_column(String(400), default="")
    classification: Mapped[str] = mapped_column(String(30), default="updates")
    severity: Mapped[str] = mapped_column(String(20), default="")
    source: Mapped[str] = mapped_column(String(30), default="windows-update")  # windows-update|apt|dnf|zypper|winget
    product: Mapped[str] = mapped_column(String(200), default="")
    installed_version: Mapped[str] = mapped_column(String(80), default="")
    available_version: Mapped[str] = mapped_column(String(80), default="")
    reboot_required: Mapped[bool] = mapped_column(Boolean, default=False)
    status: Mapped[str] = mapped_column(String(20), default="missing")  # missing|installing|installed|failed
    released_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    installed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    error: Mapped[str] = mapped_column(String(300), default="")
    __table_args__ = (UniqueConstraint("device_id", "patch_key"),)


class PatchApproval(Base):
    """A manual approve/reject decision that overrides the policy's rule for one patch."""

    __tablename__ = "rmm_patch_approvals"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(32), index=True)
    patch_key: Mapped[str] = mapped_column(String(200))
    decision: Mapped[str] = mapped_column(String(10))  # approved|rejected
    decided_by: Mapped[str] = mapped_column(String(200))
    note: Mapped[str] = mapped_column(String(300), default="")
    decided_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    __table_args__ = (UniqueConstraint("tenant_id", "patch_key"),)


class SoftwarePackage(Base):
    """An application the MSP can deploy: winget/choco/apt id, or a downloadable installer."""

    __tablename__ = "rmm_software_packages"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: new_id("pkg"))
    tenant_id: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    name: Mapped[str] = mapped_column(String(200))
    publisher: Mapped[str] = mapped_column(String(200), default="")
    platform: Mapped[str] = mapped_column(String(20), default="windows")
    installer: Mapped[str] = mapped_column(String(20), default="winget")  # winget|choco|msi|exe|apt|dnf|snap|script
    identifier: Mapped[str] = mapped_column(String(300), default="")  # winget id, apt package, or download URL
    sha256: Mapped[str] = mapped_column(String(64), default="")
    install_args: Mapped[str] = mapped_column(String(400), default="")
    uninstall_args: Mapped[str] = mapped_column(String(400), default="")
    version: Mapped[str] = mapped_column(String(60), default="latest")
    keep_updated: Mapped[bool] = mapped_column(Boolean, default=True)
    builtin: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


# --------------------------------------------------------------------------
# Remote access
# --------------------------------------------------------------------------


class RemoteSession(Base):
    """A remote desktop / terminal / file session brokered by the cloud relay."""

    __tablename__ = "remote_sessions"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: new_id("rs"))
    tenant_id: Mapped[str] = mapped_column(String(32), index=True)
    device_id: Mapped[str] = mapped_column(String(32), index=True)
    technician: Mapped[str] = mapped_column(String(200))
    mode: Mapped[str] = mapped_column(String(20), default="desktop")  # desktop|terminal|files
    status: Mapped[str] = mapped_column(String(20), default="waiting")  # waiting|connected|ended|failed|denied
    consent: Mapped[str] = mapped_column(String(20), default="not_required")  # not_required|pending|granted|denied
    view_only: Mapped[bool] = mapped_column(Boolean, default=False)
    command_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    ticket_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    reason: Mapped[str] = mapped_column(Text, default="")
    # Session events: connect, file transfer, Ctrl+Alt+Del, chat... for the audit trail.
    events: Mapped[list] = mapped_column(JSON, default=list)
    bytes_relayed: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    connected_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    ended_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


# --------------------------------------------------------------------------
# PSA (ConnectWise Manage-style)
# --------------------------------------------------------------------------


class Board(Base):
    """A service board: its own statuses, types/subtypes/items, team and defaults."""

    __tablename__ = "psa_boards"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: new_id("brd"))
    tenant_id: Mapped[str] = mapped_column(String(32), index=True)
    name: Mapped[str] = mapped_column(String(120))
    # [{"name": "New", "closed": false, "default": true, "customerResponded": false, "timeEntryNotAllowed": false}]
    statuses: Mapped[list] = mapped_column(JSON, default=list)
    # [{"name": "Hardware", "subtypes": [{"name": "Laptop", "items": ["Screen", "Battery"]}]}]
    types: Mapped[list] = mapped_column(JSON, default=list)
    members: Mapped[list] = mapped_column(JSON, default=list)  # user emails
    teams: Mapped[list] = mapped_column(JSON, default=list)  # [{"name": "Tier 1", "members": [...]}]
    default_priority: Mapped[str] = mapped_column(String(4), default="P3")
    default_work_type: Mapped[str] = mapped_column(String(60), default="Remote Support")
    mailbox: Mapped[str] = mapped_column(String(200), default="")  # inbound address routed to this board
    auto_assign: Mapped[str] = mapped_column(String(20), default="none")  # none|round_robin
    rr_index: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class Site(Base):
    __tablename__ = "psa_sites"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: new_id("sit"))
    tenant_id: Mapped[str] = mapped_column(String(32), index=True)  # MSP owner
    account_tenant_id: Mapped[str] = mapped_column(String(32), index=True)
    name: Mapped[str] = mapped_column(String(200))
    address: Mapped[str] = mapped_column(Text, default="")
    city: Mapped[str] = mapped_column(String(100), default="")
    postcode: Mapped[str] = mapped_column(String(20), default="")
    country: Mapped[str] = mapped_column(String(60), default="United Kingdom")
    phone: Mapped[str] = mapped_column(String(60), default="")
    primary: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class TimeEntry(Base):
    __tablename__ = "psa_time_entries"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: new_id("tim"))
    tenant_id: Mapped[str] = mapped_column(String(32), index=True)  # MSP owner
    account_tenant_id: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    member: Mapped[str] = mapped_column(String(200), index=True)
    charge_to: Mapped[str] = mapped_column(String(20), default="ticket")  # ticket|project|activity|internal
    ticket_id: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    project_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    remote_session_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    work_type: Mapped[str] = mapped_column(String(60), default="Remote Support")
    work_role: Mapped[str] = mapped_column(String(60), default="Engineer")
    started_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    ended_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    hours: Mapped[float] = mapped_column(Float, default=0)
    hours_billed: Mapped[float] = mapped_column(Float, default=0)
    billable: Mapped[str] = mapped_column(String(20), default="Billable")  # Billable|Do Not Bill|No Charge
    notes: Mapped[str] = mapped_column(Text, default="")
    internal_notes: Mapped[str] = mapped_column(Text, default="")
    agreement_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    covered: Mapped[bool] = mapped_column(Boolean, default=False)  # covered by an agreement (not billed per hour)
    rate: Mapped[float] = mapped_column(Float, default=0)
    status: Mapped[str] = mapped_column(String(20), default="Open")  # Open|Submitted|Approved|Rejected|Billed
    invoice_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class Configuration(Base):
    """CMDB item: a device, network kit, licence or service a customer owns."""

    __tablename__ = "psa_configurations"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: new_id("cfg"))
    tenant_id: Mapped[str] = mapped_column(String(32), index=True)
    account_tenant_id: Mapped[str] = mapped_column(String(32), index=True)
    name: Mapped[str] = mapped_column(String(200))
    type: Mapped[str] = mapped_column(String(60), default="Workstation")
    status: Mapped[str] = mapped_column(String(30), default="Active")
    device_id: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    site_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    contact_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    manufacturer: Mapped[str] = mapped_column(String(120), default="")
    model: Mapped[str] = mapped_column(String(120), default="")
    serial_number: Mapped[str] = mapped_column(String(120), default="")
    ip_address: Mapped[str] = mapped_column(String(64), default="")
    mac_address: Mapped[str] = mapped_column(String(64), default="")
    os: Mapped[str] = mapped_column(String(200), default="")
    purchase_date: Mapped[str] = mapped_column(String(20), default="")
    warranty_expires: Mapped[str] = mapped_column(String(20), default="")
    vendor: Mapped[str] = mapped_column(String(120), default="")
    notes: Mapped[str] = mapped_column(Text, default="")
    questions: Mapped[dict] = mapped_column(JSON, default=dict)  # type-specific fields
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class Product(Base):
    """Catalogue item for quotes, agreements additions and procurement."""

    __tablename__ = "psa_products"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: new_id("prd"))
    tenant_id: Mapped[str] = mapped_column(String(32), index=True)
    sku: Mapped[str] = mapped_column(String(80))
    description: Mapped[str] = mapped_column(String(300))
    category: Mapped[str] = mapped_column(String(80), default="Service")  # Hardware|Software|Service|Licence
    cost: Mapped[float] = mapped_column(Float, default=0)
    price: Mapped[float] = mapped_column(Float, default=0)
    recurring: Mapped[bool] = mapped_column(Boolean, default=False)
    taxable: Mapped[bool] = mapped_column(Boolean, default=True)
    vendor: Mapped[str] = mapped_column(String(120), default="")
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class Quote(Base):
    __tablename__ = "psa_quotes"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: new_id("quo"))
    number: Mapped[str] = mapped_column(String(30), index=True)
    tenant_id: Mapped[str] = mapped_column(String(32), index=True)
    account_tenant_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    lead_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    title: Mapped[str] = mapped_column(String(200))
    # [{"productId": "...", "description": "...", "quantity": 1, "unitPrice": 0, "recurring": false}]
    lines: Mapped[list] = mapped_column(JSON, default=list)
    status: Mapped[str] = mapped_column(String(20), default="Draft")  # Draft|Sent|Accepted|Declined
    valid_until: Mapped[str] = mapped_column(String(20), default="")
    notes: Mapped[str] = mapped_column(Text, default="")
    created_by: Mapped[str] = mapped_column(String(200), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class ScheduleEntry(Base):
    """Dispatch calendar entry: a member booked on a ticket, project or other activity."""

    __tablename__ = "psa_schedule"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: new_id("sce"))
    tenant_id: Mapped[str] = mapped_column(String(32), index=True)
    member: Mapped[str] = mapped_column(String(200), index=True)
    ticket_id: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    project_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    title: Mapped[str] = mapped_column(String(300), default="")
    kind: Mapped[str] = mapped_column(String(20), default="Service")  # Service|Onsite|Meeting|Leave|Project
    status: Mapped[str] = mapped_column(String(20), default="Firm")  # Firm|Tentative|Done|Cancelled
    location: Mapped[str] = mapped_column(String(200), default="")
    start_at: Mapped[datetime] = mapped_column(DateTime, index=True)
    end_at: Mapped[datetime] = mapped_column(DateTime)
    created_by: Mapped[str] = mapped_column(String(200), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class WorkflowRule(Base):
    """Board automation: when a ticket matches conditions on an event or after a delay, do things."""

    __tablename__ = "psa_workflow_rules"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: new_id("wfr"))
    tenant_id: Mapped[str] = mapped_column(String(32), index=True)
    board_id: Mapped[str | None] = mapped_column(String(32), nullable=True)  # null = every board
    name: Mapped[str] = mapped_column(String(200))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    trigger: Mapped[str] = mapped_column(String(30), default="ticket.created")  # ticket.created|ticket.updated|ticket.idle|sla.warning|sla.breached
    idle_hours: Mapped[float] = mapped_column(Float, default=0)  # for ticket.idle: hours in the same status
    # [{"field": "status", "op": "equals|not_equals|contains|in", "value": "Waiting Customer"}]
    conditions: Mapped[list] = mapped_column(JSON, default=list)
    # [{"type": "set", "field": "status", "value": "Closed"}, {"type": "note", "text": "...", "kind": "discussion"},
    #  {"type": "email_contact", "subject": "...", "body": "..."}, {"type": "notify", "to": "..."}, {"type": "assign", "member": "..."}]
    actions: Mapped[list] = mapped_column(JSON, default=list)
    runs: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class KbArticle(Base):
    __tablename__ = "psa_kb_articles"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: new_id("kb"))
    tenant_id: Mapped[str] = mapped_column(String(32), index=True)
    title: Mapped[str] = mapped_column(String(300))
    body: Mapped[str] = mapped_column(Text, default="")
    category: Mapped[str] = mapped_column(String(80), default="General")
    tags: Mapped[list] = mapped_column(JSON, default=list)
    public: Mapped[bool] = mapped_column(Boolean, default=False)  # visible in the client portal
    author: Mapped[str] = mapped_column(String(200), default="")
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


# --------------------------------------------------------------------------
# Platform foundation: cross-module events
# --------------------------------------------------------------------------


class PlatformEvent(Base):
    """Durable outbox for cross-module automation (vulnerability -> ticket -> patch -> evidence).

    ``key`` makes publishing idempotent; ``results`` records each handler's outcome so a retry
    re-runs only the handlers that failed.
    """

    __tablename__ = "platform_events"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    type: Mapped[str] = mapped_column(String(80), index=True)
    tenant_id: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    key: Mapped[str] = mapped_column(String(200), unique=True)
    payload: Mapped[dict] = mapped_column(JSON, default=dict)
    status: Mapped[str] = mapped_column(String(16), default="pending")  # pending|done|dead
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    results: Mapped[dict] = mapped_column(JSON, default=dict)
    last_error: Mapped[str] = mapped_column(Text, default="")
    next_attempt_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    processed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    __table_args__ = (Index("ix_platform_events_due", "status", "next_attempt_at"),)


class RateLimitBucket(Base):
    """Shared sliding windows, serialized using a database write lock per key."""
    __tablename__ = "rate_limit_buckets"
    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    hits: Mapped[list] = mapped_column(JSON, default=list)
    expires_at: Mapped[datetime] = mapped_column(DateTime, index=True)


class SchemaMigration(Base):
    """History of additive schema upgrades; also included in test DB cleanup."""
    __tablename__ = "schema_migrations"
    version: Mapped[int] = mapped_column(Integer, primary_key=True)
    applied_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class DocumentRevision(Base):
    __tablename__ = "document_revisions"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: new_id("rev"))
    article_id: Mapped[str] = mapped_column(String(32), index=True)
    tenant_id: Mapped[str] = mapped_column(String(32), index=True)
    snapshot: Mapped[dict] = mapped_column(JSON)
    author: Mapped[str] = mapped_column(String(200))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class VaultCredential(Base):
    __tablename__ = "vault_credentials"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: new_id("cred"))
    tenant_id: Mapped[str] = mapped_column(String(32), index=True)
    name: Mapped[str] = mapped_column(String(200))
    username: Mapped[str] = mapped_column(String(200), default="")
    url: Mapped[str] = mapped_column(String(1000), default="")
    notes: Mapped[str] = mapped_column(Text, default="")
    configuration_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    ciphertext: Mapped[dict] = mapped_column(JSON)
    archived: Mapped[bool] = mapped_column(Boolean, default=False)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    updated_by: Mapped[str] = mapped_column(String(200))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class M365Connection(Base):
    __tablename__ = "m365_connections"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: new_id("m365"))
    tenant_id: Mapped[str] = mapped_column(String(32), index=True)
    name: Mapped[str] = mapped_column(String(200))
    directory_id: Mapped[str] = mapped_column(String(36))
    client_id: Mapped[str] = mapped_column(String(36))
    credentials_envelope: Mapped[dict] = mapped_column(JSON)
    snapshot: Mapped[dict] = mapped_column(JSON, default=dict)
    status: Mapped[str] = mapped_column(String(30), default="not_synced")
    last_error: Mapped[str] = mapped_column(String(300), default="")
    synced_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    __table_args__ = (UniqueConstraint("tenant_id", "directory_id", name="uq_m365_tenant_directory"),)


class NetworkMonitor(Base):
    __tablename__ = "network_monitors"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: new_id("net"))
    tenant_id: Mapped[str] = mapped_column(String(32), index=True)
    name: Mapped[str] = mapped_column(String(200))
    address: Mapped[str] = mapped_column(String(64))
    port: Mapped[int] = mapped_column(Integer)
    configuration_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    interval_seconds: Mapped[int] = mapped_column(Integer, default=300)
    # Probe from this enrolled device (for services on the customer's LAN) instead of from the cloud.
    probe_device_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    state: Mapped[str] = mapped_column(String(20), default="unknown")
    samples: Mapped[list] = mapped_column(JSON, default=list)
    failures: Mapped[int] = mapped_column(Integer, default=0)
    checked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    next_check_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class GovernanceRecord(Base):
    __tablename__ = "governance_records"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: new_id("grc"))
    tenant_id: Mapped[str] = mapped_column(String(32), index=True)
    kind: Mapped[str] = mapped_column(String(20))
    title: Mapped[str] = mapped_column(String(300))
    description: Mapped[str] = mapped_column(Text, default="")
    framework: Mapped[str] = mapped_column(String(100), default="")
    control: Mapped[str] = mapped_column(String(200), default="")
    owner: Mapped[str] = mapped_column(String(200), default="")
    status: Mapped[str] = mapped_column(String(30), default="draft")
    likelihood: Mapped[int] = mapped_column(Integer, default=1)
    impact: Mapped[int] = mapped_column(Integer, default=1)
    review_due: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    document_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    evidence_url: Mapped[str] = mapped_column(String(2000), default="")
    approved_by: Mapped[str] = mapped_column(String(200), default="")
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class BackupPlan(Base):
    __tablename__ = "backup_plans"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: new_id("bkp"))
    tenant_id: Mapped[str] = mapped_column(String(32), index=True)
    name: Mapped[str] = mapped_column(String(200))
    provider: Mapped[str] = mapped_column(String(100))
    configuration_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    rpo_hours: Mapped[int] = mapped_column(Integer, default=24)
    rto_minutes: Mapped[int] = mapped_column(Integer, default=240)
    runbook_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    ingest_token_hash: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)  # backup tools push results with it
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class BackupRun(Base):
    __tablename__ = "backup_runs"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: new_id("bkr"))
    plan_id: Mapped[str] = mapped_column(String(32), index=True)
    tenant_id: Mapped[str] = mapped_column(String(32), index=True)
    external_id: Mapped[str] = mapped_column(String(200))
    status: Mapped[str] = mapped_column(String(30))
    completed_at: Mapped[datetime] = mapped_column(DateTime)
    bytes_protected: Mapped[int] = mapped_column(BigInteger, default=0)
    evidence: Mapped[str] = mapped_column(Text, default="")
    recorded_by: Mapped[str] = mapped_column(String(200))
    __table_args__ = (UniqueConstraint("plan_id", "external_id", name="uq_backup_run_external"),)


class RecoveryExercise(Base):
    __tablename__ = "recovery_exercises"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: new_id("rec"))
    plan_id: Mapped[str] = mapped_column(String(32), index=True)
    tenant_id: Mapped[str] = mapped_column(String(32), index=True)
    status: Mapped[str] = mapped_column(String(30), default="requested")
    requested_by: Mapped[str] = mapped_column(String(200))
    approved_by: Mapped[str] = mapped_column(String(200), default="")
    target: Mapped[str] = mapped_column(String(500))
    evidence: Mapped[str] = mapped_column(Text, default="")
    duration_minutes: Mapped[int | None] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class IncidentEvidence(Base):
    __tablename__ = "incident_evidence"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: new_id("evd"))
    incident_id: Mapped[str] = mapped_column(String(32), index=True)
    tenant_id: Mapped[str] = mapped_column(String(32), index=True)
    name: Mapped[str] = mapped_column(String(200))
    content: Mapped[str] = mapped_column(Text)
    sha256: Mapped[str] = mapped_column(String(64))
    author: Mapped[str] = mapped_column(String(200))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class AlertSuppression(Base):
    __tablename__ = "alert_suppressions"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: new_id("sup"))
    tenant_id: Mapped[str] = mapped_column(String(32), index=True)
    rule_id: Mapped[str] = mapped_column(String(64))
    reason: Mapped[str] = mapped_column(String(1000))
    expires_at: Mapped[datetime] = mapped_column(DateTime)
    created_by: Mapped[str] = mapped_column(String(200))


class M365Action(Base):
    """Reviewed provider operation. Running/unknown operations must never be replayed."""
    __tablename__ = "m365_actions"
    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=lambda: new_id("mact"))
    connection_id: Mapped[str] = mapped_column(String(32), index=True)
    tenant_id: Mapped[str] = mapped_column(String(32), index=True)
    request_id: Mapped[str] = mapped_column(String(36))
    operation: Mapped[str] = mapped_column(String(40))
    target_id: Mapped[str] = mapped_column(String(36))
    parameters: Mapped[dict] = mapped_column(JSON)
    preview: Mapped[dict] = mapped_column(JSON)
    status: Mapped[str] = mapped_column(String(40), default="prepared")
    result: Mapped[dict] = mapped_column(JSON, default=dict)
    requested_by: Mapped[str] = mapped_column(String(200))
    executed_by: Mapped[str] = mapped_column(String(200), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    __table_args__ = (UniqueConstraint("connection_id", "request_id", name="uq_m365_action_request"),)

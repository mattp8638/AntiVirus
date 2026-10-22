"""ORM models for every Fenrir Cloud module.

Kept in one file on purpose: the security, SIEM, and CRM sides reference each
other constantly (an incident opens a ticket, a ticket bills a contract, a
contract covers a tenant's devices) and one module avoids import cycles.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import JSON, Boolean, DateTime, Float, ForeignKey, Index, Integer, String, Text, UniqueConstraint
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
    enrolled_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


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


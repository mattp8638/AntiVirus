-- Unified Security & Operations Platform
-- PostgreSQL schema for MVP-1+ planning
-- NOTE: This is a forward-looking schema scaffold, not yet wired to services.

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Tenancy
CREATE TABLE tenants (
    tenant_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name TEXT NOT NULL,
    slug TEXT UNIQUE NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Identity & Access
CREATE TABLE identities (
    identity_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(tenant_id),
    identity_type TEXT NOT NULL, -- user, service, agent
    display_name TEXT NOT NULL,
    email TEXT,
    status TEXT NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE roles (
    role_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(tenant_id),
    name TEXT NOT NULL,
    description TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE permissions (
    permission_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name TEXT NOT NULL UNIQUE,
    description TEXT
);

CREATE TABLE role_permissions (
    role_id UUID NOT NULL REFERENCES roles(role_id),
    permission_id UUID NOT NULL REFERENCES permissions(permission_id),
    PRIMARY KEY (role_id, permission_id)
);

CREATE TABLE identity_roles (
    identity_id UUID NOT NULL REFERENCES identities(identity_id),
    role_id UUID NOT NULL REFERENCES roles(role_id),
    PRIMARY KEY (identity_id, role_id)
);

-- Assets
CREATE TABLE assets (
    asset_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(tenant_id),
    hostname TEXT NOT NULL,
    asset_type TEXT NOT NULL, -- server, workstation, network, cloud
    environment TEXT,
    status TEXT NOT NULL DEFAULT 'active',
    criticality TEXT DEFAULT 'medium',
    last_seen_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE asset_tags (
    asset_id UUID NOT NULL REFERENCES assets(asset_id),
    tag TEXT NOT NULL,
    PRIMARY KEY (asset_id, tag)
);

-- Agents
CREATE TABLE agents (
    agent_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(tenant_id),
    asset_id UUID NOT NULL REFERENCES assets(asset_id),
    identity_id UUID NOT NULL REFERENCES identities(identity_id),
    agent_version TEXT NOT NULL,
    trust_state TEXT NOT NULL DEFAULT 'unknown',
    status TEXT NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE agent_heartbeats (
    event_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    agent_id UUID NOT NULL REFERENCES agents(agent_id),
    hostname TEXT NOT NULL,
    os TEXT NOT NULL,
    uptime_seconds BIGINT NOT NULL,
    trust_state TEXT NOT NULL,
    received_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Inventory
CREATE TABLE hardware_inventory (
    asset_id UUID PRIMARY KEY REFERENCES assets(asset_id),
    manufacturer TEXT,
    model TEXT,
    serial_number TEXT,
    cpu_model TEXT,
    cpu_cores INTEGER,
    memory_mb INTEGER,
    storage_gb INTEGER,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE os_inventory (
    asset_id UUID PRIMARY KEY REFERENCES assets(asset_id),
    os_name TEXT NOT NULL,
    os_version TEXT NOT NULL,
    kernel_version TEXT,
    architecture TEXT,
    install_date DATE,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE software_inventory (
    software_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    asset_id UUID NOT NULL REFERENCES assets(asset_id),
    name TEXT NOT NULL,
    vendor TEXT,
    version TEXT,
    install_date DATE,
    source TEXT,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE local_users (
    user_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    asset_id UUID NOT NULL REFERENCES assets(asset_id),
    username TEXT NOT NULL,
    display_name TEXT,
    uid TEXT,
    is_admin BOOLEAN NOT NULL DEFAULT FALSE,
    last_login_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE local_groups (
    group_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    asset_id UUID NOT NULL REFERENCES assets(asset_id),
    name TEXT NOT NULL,
    gid TEXT,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE local_group_members (
    group_id UUID NOT NULL REFERENCES local_groups(group_id),
    member_name TEXT NOT NULL,
    PRIMARY KEY (group_id, member_name)
);

-- Telemetry Metrics
CREATE TABLE telemetry_metrics (
    metric_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name TEXT NOT NULL UNIQUE,
    unit TEXT,
    description TEXT
);

CREATE TABLE telemetry_samples (
    sample_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    asset_id UUID NOT NULL REFERENCES assets(asset_id),
    metric_id UUID NOT NULL REFERENCES telemetry_metrics(metric_id),
    value DOUBLE PRECISION NOT NULL,
    observed_at TIMESTAMPTZ NOT NULL,
    collected_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE telemetry_baselines (
    asset_id UUID NOT NULL REFERENCES assets(asset_id),
    metric_id UUID NOT NULL REFERENCES telemetry_metrics(metric_id),
    sample_count INTEGER NOT NULL DEFAULT 0,
    avg_value DOUBLE PRECISION NOT NULL DEFAULT 0,
    stddev_value DOUBLE PRECISION NOT NULL DEFAULT 0,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (asset_id, metric_id)
);

CREATE TABLE telemetry_anomalies (
    anomaly_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    asset_id UUID NOT NULL REFERENCES assets(asset_id),
    metric_id UUID NOT NULL REFERENCES telemetry_metrics(metric_id),
    observed_at TIMESTAMPTZ NOT NULL,
    value DOUBLE PRECISION NOT NULL,
    baseline_value DOUBLE PRECISION NOT NULL,
    deviation DOUBLE PRECISION NOT NULL,
    status TEXT NOT NULL DEFAULT 'open',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE telemetry_ingest_log (
    payload_id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(tenant_id),
    asset_id UUID NOT NULL REFERENCES assets(asset_id),
    status TEXT NOT NULL,
    received_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    processed_at TIMESTAMPTZ,
    reject_reason TEXT
);

-- Events (SIEM ledger)
CREATE TABLE events (
    event_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(tenant_id),
    asset_id UUID REFERENCES assets(asset_id),
    identity_id UUID REFERENCES identities(identity_id),
    event_type TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'info',
    source TEXT NOT NULL,
    message TEXT,
    raw_payload JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE event_enrichment (
    event_id UUID PRIMARY KEY REFERENCES events(event_id),
    geo_ip JSONB,
    asset_context JSONB,
    identity_context JSONB,
    enrichment_version TEXT,
    enriched_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Event Ledger (MVP-7)
CREATE TABLE event_ledger (
    event_id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(tenant_id),
    asset_id UUID NOT NULL REFERENCES assets(asset_id),
    event_type TEXT NOT NULL,
    event_category TEXT NOT NULL,
    source_module TEXT NOT NULL,
    trust_level TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'info',
    sequence_number BIGINT NOT NULL,
    timestamp_local TIMESTAMPTZ NOT NULL,
    timestamp_received TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    payload JSONB NOT NULL,
    payload_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE event_ingest_log (
    payload_id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(tenant_id),
    asset_id UUID NOT NULL REFERENCES assets(asset_id),
    status TEXT NOT NULL,
    received_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    processed_at TIMESTAMPTZ,
    event_count INTEGER NOT NULL DEFAULT 0,
    accepted_count INTEGER NOT NULL DEFAULT 0,
    rejected_count INTEGER NOT NULL DEFAULT 0,
    reject_reason TEXT,
    signature TEXT,
    signature_verified BOOLEAN NOT NULL DEFAULT FALSE,
    schema_version TEXT NOT NULL DEFAULT 'v1'
);

CREATE TABLE event_rejections (
    rejection_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    event_id UUID NOT NULL,
    payload_id UUID NOT NULL REFERENCES event_ingest_log(payload_id),
    tenant_id UUID NOT NULL REFERENCES tenants(tenant_id),
    asset_id UUID NOT NULL REFERENCES assets(asset_id),
    reason TEXT NOT NULL,
    detected_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE event_sequence_state (
    asset_id UUID NOT NULL REFERENCES assets(asset_id),
    source_module TEXT NOT NULL,
    last_sequence BIGINT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (asset_id, source_module)
);

CREATE TABLE event_gap_reports (
    gap_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    asset_id UUID NOT NULL REFERENCES assets(asset_id),
    source_module TEXT NOT NULL,
    missing_from BIGINT NOT NULL,
    missing_to BIGINT NOT NULL,
    detected_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE event_clock_drifts (
    drift_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    event_id UUID NOT NULL,
    asset_id UUID NOT NULL REFERENCES assets(asset_id),
    source_module TEXT NOT NULL,
    drift_seconds INTEGER NOT NULL,
    timestamp_local TIMESTAMPTZ NOT NULL,
    timestamp_received TIMESTAMPTZ NOT NULL,
    detected_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Detections & Findings
CREATE TABLE detections (
    detection_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(tenant_id),
    rule_id UUID,
    name TEXT NOT NULL,
    description TEXT,
    severity TEXT NOT NULL DEFAULT 'medium',
    status TEXT NOT NULL DEFAULT 'open',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE detection_events (
    detection_id UUID NOT NULL REFERENCES detections(detection_id),
    event_id UUID NOT NULL REFERENCES events(event_id),
    PRIMARY KEY (detection_id, event_id)
);

-- Remote Tasks
CREATE TABLE tasks (
    task_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(tenant_id),
    asset_id UUID NOT NULL REFERENCES assets(asset_id),
    requested_by UUID NOT NULL REFERENCES identities(identity_id),
    command TEXT NOT NULL,
    interpreter TEXT NOT NULL, -- bash, powershell
    execution_context TEXT NOT NULL, -- system/root only for MVP-5
    policy_reference TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'pending',
    allow_network BOOLEAN NOT NULL DEFAULT FALSE,
    signed_payload JSONB NOT NULL,
    signature TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE task_results (
    task_result_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    task_id UUID NOT NULL REFERENCES tasks(task_id),
    status TEXT NOT NULL,
    stdout TEXT,
    stderr TEXT,
    exit_code INTEGER,
    started_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ,
    duration_ms INTEGER,
    truncated BOOLEAN NOT NULL DEFAULT FALSE,
    executed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Patch Management
CREATE TABLE patches (
    patch_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    vendor TEXT NOT NULL,
    name TEXT NOT NULL,
    kb_reference TEXT,
    release_date DATE,
    severity TEXT
);

CREATE TABLE asset_patches (
    asset_id UUID NOT NULL REFERENCES assets(asset_id),
    patch_id UUID NOT NULL REFERENCES patches(patch_id),
    status TEXT NOT NULL, -- missing, installed, failed
    last_checked_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (asset_id, patch_id)
);

-- Vulnerabilities
CREATE TABLE vulnerabilities (
    vulnerability_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    cve_id TEXT NOT NULL,
    description TEXT,
    cvss_score NUMERIC(3,1),
    published_at TIMESTAMPTZ,
    last_modified_at TIMESTAMPTZ
);

CREATE TABLE asset_vulnerabilities (
    asset_id UUID NOT NULL REFERENCES assets(asset_id),
    vulnerability_id UUID NOT NULL REFERENCES vulnerabilities(vulnerability_id),
    status TEXT NOT NULL DEFAULT 'open',
    detected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (asset_id, vulnerability_id)
);

-- Risk Scoring
CREATE TABLE risk_scores (
    risk_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    asset_id UUID REFERENCES assets(asset_id),
    identity_id UUID REFERENCES identities(identity_id),
    score NUMERIC(5,2) NOT NULL,
    rationale TEXT,
    calculated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Tickets / PSA
CREATE TABLE tickets (
    ticket_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(tenant_id),
    source_type TEXT NOT NULL, -- finding, patch_failure, defence_action, vulnerability
    source_reference_id TEXT NOT NULL,
    asset_id UUID NOT NULL REFERENCES assets(asset_id),
    risk_score NUMERIC(5,2) NOT NULL,
    priority TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open',
    assigned_to UUID REFERENCES identities(identity_id),
    sla_deadline TIMESTAMPTZ NOT NULL,
    creation_timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    system_recommendation TEXT,
    UNIQUE (tenant_id, asset_id, source_type, source_reference_id)
);

CREATE TABLE ticket_actions (
    action_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    ticket_id UUID NOT NULL REFERENCES tickets(ticket_id),
    action_type TEXT NOT NULL, -- acknowledge, remediate, defer, accept_risk, escalate
    actor_identity UUID NOT NULL REFERENCES identities(identity_id),
    approver_identity UUID REFERENCES identities(identity_id),
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    justification TEXT,
    automation_request_id TEXT
);

CREATE TABLE ticket_evidence (
    evidence_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    ticket_id UUID NOT NULL REFERENCES tickets(ticket_id),
    linked_object_type TEXT NOT NULL, -- event, finding, vulnerability, patch, defence_action
    linked_object_id TEXT NOT NULL,
    immutable_reference TEXT NOT NULL,
    hash_sha256 TEXT NOT NULL,
    captured_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    payload JSONB
);

-- Compliance
CREATE TABLE compliance_frameworks (
    framework_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name TEXT NOT NULL,
    version TEXT,
    description TEXT
);

CREATE TABLE compliance_controls (
    control_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    framework_id UUID NOT NULL REFERENCES compliance_frameworks(framework_id),
    control_code TEXT NOT NULL,
    description TEXT,
    severity TEXT
);

CREATE TABLE compliance_evidence (
    evidence_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    control_id UUID NOT NULL REFERENCES compliance_controls(control_id),
    asset_id UUID REFERENCES assets(asset_id),
    event_id UUID REFERENCES events(event_id),
    collected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    payload JSONB
);

-- Audit & Integrations
CREATE TABLE audit_logs (
    audit_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(tenant_id),
    actor_identity_id UUID REFERENCES identities(identity_id),
    action TEXT NOT NULL,
    target_type TEXT,
    target_id UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    metadata JSONB
);

CREATE TABLE api_keys (
    api_key_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(tenant_id),
    identity_id UUID NOT NULL REFERENCES identities(identity_id),
    key_hash TEXT NOT NULL,
    name TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at TIMESTAMPTZ
);

CREATE TABLE certificates (
    certificate_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    identity_id UUID NOT NULL REFERENCES identities(identity_id),
    fingerprint_sha256 TEXT NOT NULL UNIQUE,
    issued_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ
);

CREATE TABLE certificate_revocations (
    revocation_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    certificate_id UUID NOT NULL REFERENCES certificates(certificate_id),
    reason TEXT NOT NULL,
    revoked_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_assets_tenant ON assets(tenant_id);
CREATE INDEX idx_agents_asset ON agents(asset_id);
CREATE INDEX idx_events_tenant_created ON events(tenant_id, created_at DESC);
CREATE INDEX idx_events_asset ON events(asset_id);
CREATE INDEX idx_event_ledger_asset_time ON event_ledger(asset_id, timestamp_received DESC);
CREATE INDEX idx_event_ledger_tenant_time ON event_ledger(tenant_id, timestamp_received DESC);
CREATE INDEX idx_event_ledger_category ON event_ledger(event_category);
CREATE INDEX idx_event_ledger_type ON event_ledger(event_type);
CREATE INDEX idx_event_ingest_log_asset ON event_ingest_log(asset_id, received_at DESC);
CREATE INDEX idx_event_gap_reports_asset ON event_gap_reports(asset_id, detected_at DESC);
CREATE INDEX idx_event_clock_drifts_asset ON event_clock_drifts(asset_id, detected_at DESC);
CREATE INDEX idx_telemetry_samples_asset ON telemetry_samples(asset_id, observed_at DESC);
CREATE INDEX idx_telemetry_samples_metric ON telemetry_samples(asset_id, metric_id, observed_at DESC);
CREATE INDEX idx_telemetry_anomalies_asset ON telemetry_anomalies(asset_id, observed_at DESC);
CREATE INDEX idx_telemetry_ingest_log_asset ON telemetry_ingest_log(asset_id, received_at DESC);
CREATE INDEX idx_tasks_asset ON tasks(asset_id);
CREATE INDEX idx_ticket_status ON tickets(status);
CREATE INDEX idx_ticket_priority ON tickets(priority);
CREATE INDEX idx_ticket_sla_deadline ON tickets(sla_deadline);

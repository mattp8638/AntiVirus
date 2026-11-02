--
-- Optional: Create database and user for SIEM platform
--
-- Run these as a superuser (e.g., postgres) before loading the schema.
--
-- CREATE DATABASE tamsilcmssiem;
-- CREATE USER tamsilsiem WITH PASSWORD '1792BigDirtyDykes!';
-- GRANT ALL PRIVILEGES ON DATABASE tamsilcmssiem TO tamsilsiem;
--
-- To allow connections from anywhere, edit postgresql.conf and pg_hba.conf as follows:
--   In postgresql.conf: listen_addresses = '*'
--   In pg_hba.conf: host  tamsilcmssiem  tamsilsiem  0.0.0.0/0  md5
-- Then reload/restart PostgreSQL.
--
-- After creating the database and user, connect as tamsilsiem and run the rest of this schema.

-- Merged PSA + Data-Model schema
-- PSA objects remain in the public schema; the data-model (long-form) is created in schema `datamodel`.
-- This file combines `psa_postgres_schema.sql` and `data-model/schema.sql`.

-- Ensure required extensions
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- === Begin PSA schema (public) ===

-- PSA PostgreSQL schema
-- Generated schema for PSA service (organisations, users, assets, cases, tasks, evidence, audit)

-- Use pgcrypto for UUID generation
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Organisations
CREATE TABLE IF NOT EXISTS organisations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    type TEXT,
    status TEXT NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at TIMESTAMPTZ NULL
);

CREATE INDEX IF NOT EXISTS organisations_name_idx ON organisations (name);

-- Users
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organisation_id UUID NOT NULL REFERENCES organisations(id) ON DELETE RESTRICT,
    email TEXT NOT NULL,
    display_name TEXT,
    status TEXT NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at TIMESTAMPTZ NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS users_email_org_idx ON users (organisation_id, email);

-- Roles and user_roles
CREATE TABLE IF NOT EXISTS roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    scope TEXT
);

CREATE TABLE IF NOT EXISTS user_roles (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, role_id)
);

-- Assets
CREATE TABLE IF NOT EXISTS assets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organisation_id UUID NOT NULL REFERENCES organisations(id) ON DELETE RESTRICT,
    asset_type TEXT,
    external_ref TEXT,
    name TEXT,
    status TEXT NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at TIMESTAMPTZ NULL
);
CREATE INDEX IF NOT EXISTS assets_external_ref_idx ON assets (external_ref);

-- Cases
CREATE TABLE IF NOT EXISTS cases (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organisation_id UUID NOT NULL REFERENCES organisations(id) ON DELETE RESTRICT,
    case_type TEXT,
    source_system TEXT,
    severity INTEGER NOT NULL DEFAULT 1,
    status TEXT NOT NULL DEFAULT 'open',
    opened_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    closed_at TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at TIMESTAMPTZ NULL
);
CREATE INDEX IF NOT EXISTS cases_org_idx ON cases (organisation_id);

-- Case assets (many-to-many)
CREATE TABLE IF NOT EXISTS case_assets (
    case_id UUID NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    asset_id UUID NOT NULL REFERENCES assets(id) ON DELETE RESTRICT,
    PRIMARY KEY (case_id, asset_id)
);

-- Case relationships
CREATE TABLE IF NOT EXISTS case_relationships (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    parent_case_id UUID NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    child_case_id UUID NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    relationship_type TEXT
);

-- Tasks
CREATE TABLE IF NOT EXISTS tasks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    case_id UUID NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    assigned_to UUID REFERENCES users(id) ON DELETE SET NULL,
    task_type TEXT,
    status TEXT NOT NULL DEFAULT 'pending',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at TIMESTAMPTZ NULL,
    deleted_at TIMESTAMPTZ NULL
);
CREATE INDEX IF NOT EXISTS tasks_case_idx ON tasks (case_id);

-- Task actions
CREATE TABLE IF NOT EXISTS task_actions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    task_id UUID NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    action_type TEXT,
    description TEXT,
    performed_by UUID REFERENCES users(id) ON DELETE SET NULL,
    performed_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- SLA policies and case_sla
CREATE TABLE IF NOT EXISTS sla_policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    response_minutes INTEGER,
    resolution_minutes INTEGER
);

CREATE TABLE IF NOT EXISTS case_sla (
    case_id UUID PRIMARY KEY REFERENCES cases(id) ON DELETE CASCADE,
    sla_id UUID NOT NULL REFERENCES sla_policies(id) ON DELETE RESTRICT,
    breached BOOLEAN NOT NULL DEFAULT false,
    breached_at TIMESTAMPTZ NULL
);

-- Evidence and evidence links (evidence is immutable)
CREATE TABLE IF NOT EXISTS evidence_items (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    case_id UUID NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    evidence_type TEXT,
    source_system TEXT,
    hash TEXT,
    stored_uri TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS evidence_case_idx ON evidence_items (case_id);

CREATE TABLE IF NOT EXISTS evidence_links (
    evidence_id UUID NOT NULL REFERENCES evidence_items(id) ON DELETE CASCADE,
    linked_entity TEXT NOT NULL,
    linked_id UUID NOT NULL,
    PRIMARY KEY (evidence_id, linked_entity, linked_id)
);

-- Audit log (append-only)
CREATE TABLE IF NOT EXISTS audit_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    actor_id UUID,
    action TEXT NOT NULL,
    entity_type TEXT,
    entity_id UUID,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT now(),
    metadata JSONB
);
CREATE INDEX IF NOT EXISTS audit_entity_idx ON audit_log (entity_type, entity_id);

-- Prevent updates/deletes on append-only tables: evidence_items and audit_log
CREATE OR REPLACE FUNCTION psa_prevent_modification()
RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'Table % is append-only; updates and deletes are not allowed', TG_TABLE_NAME;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS evidence_prevent_mod_trig ON evidence_items;
CREATE TRIGGER evidence_prevent_mod_trig
    BEFORE UPDATE OR DELETE ON evidence_items
    FOR EACH ROW EXECUTE FUNCTION psa_prevent_modification();

DROP TRIGGER IF EXISTS audit_prevent_mod_trig ON audit_log;
CREATE TRIGGER audit_prevent_mod_trig
    BEFORE UPDATE OR DELETE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION psa_prevent_modification();


-- BEGIN SIEM SCHEMA (PSA file continues)

-- Auditing / Compliance schema
BEGIN;

CREATE TABLE IF NOT EXISTS compliance_frameworks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    version TEXT,
    authority TEXT,
    description TEXT
);

CREATE TABLE IF NOT EXISTS compliance_controls (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    framework_id UUID NOT NULL REFERENCES compliance_frameworks(id),
    control_code TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    control_type TEXT
);

CREATE TABLE IF NOT EXISTS control_relationships (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    control_id UUID NOT NULL REFERENCES compliance_controls(id),
    related_control_id UUID NOT NULL REFERENCES compliance_controls(id),
    relationship_type TEXT
);

CREATE TABLE IF NOT EXISTS control_applicability (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organisation_id UUID NOT NULL,
    control_id UUID NOT NULL REFERENCES compliance_controls(id),
    applicable BOOLEAN DEFAULT TRUE,
    justification TEXT,
    decided_at TIMESTAMP WITH TIME ZONE DEFAULT now()
);

CREATE TABLE IF NOT EXISTS control_assessments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organisation_id UUID NOT NULL,
    control_id UUID NOT NULL REFERENCES compliance_controls(id),
    assessment_status TEXT,
    effectiveness TEXT,
    assessed_by UUID,
    assessed_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
    notes TEXT
);

CREATE TABLE IF NOT EXISTS control_evidence (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    control_id UUID NOT NULL REFERENCES compliance_controls(id),
    evidence_type TEXT,
    source_system TEXT,
    storage_uri TEXT,
    hash TEXT,
    valid_from TIMESTAMP WITH TIME ZONE,
    valid_to TIMESTAMP WITH TIME ZONE
);

CREATE TABLE IF NOT EXISTS evidence_sources (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    evidence_id UUID NOT NULL REFERENCES control_evidence(id),
    originating_entity TEXT,
    originating_id UUID
);

CREATE TABLE IF NOT EXISTS control_gaps (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    control_id UUID NOT NULL REFERENCES compliance_controls(id),
    organisation_id UUID NOT NULL,
    gap_description TEXT,
    severity INTEGER,
    identified_at TIMESTAMP WITH TIME ZONE DEFAULT now()
);

CREATE TABLE IF NOT EXISTS gap_cases (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    gap_id UUID NOT NULL REFERENCES control_gaps(id),
    psa_case_id UUID
);

CREATE TABLE IF NOT EXISTS control_attestations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    control_id UUID NOT NULL REFERENCES compliance_controls(id),
    organisation_id UUID NOT NULL,
    attested_by UUID,
    role TEXT,
    statement TEXT,
    attested_at TIMESTAMP WITH TIME ZONE DEFAULT now()
);

CREATE TABLE IF NOT EXISTS audit_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organisation_id UUID NOT NULL,
    framework_id UUID REFERENCES compliance_frameworks(id),
    started_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
    completed_at TIMESTAMP WITH TIME ZONE,
    status TEXT
);

CREATE TABLE IF NOT EXISTS audit_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    audit_session_id UUID NOT NULL REFERENCES audit_sessions(id),
    event_type TEXT,
    actor_id UUID,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT now(),
    metadata JSONB
);

-- Make evidence and audit_events append-only as a best-effort guard
CREATE OR REPLACE FUNCTION prevent_update_on_append_only() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'This table is append-only';
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER control_evidence_no_update BEFORE UPDATE ON control_evidence
FOR EACH ROW EXECUTE PROCEDURE prevent_update_on_append_only();

CREATE TRIGGER audit_events_no_update BEFORE UPDATE ON audit_events
FOR EACH ROW EXECUTE PROCEDURE prevent_update_on_append_only();

COMMIT;

-- Raw events (append-only)
CREATE TABLE IF NOT EXISTS raw_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source_system TEXT,
    received_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    event_time TIMESTAMPTZ NULL,
    payload JSONB,
    payload_hash TEXT,
    ingestion_node TEXT
);
CREATE INDEX IF NOT EXISTS raw_events_received_idx ON raw_events (received_at);

-- Normalised events
CREATE TABLE IF NOT EXISTS events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    raw_event_id UUID REFERENCES raw_events(id) ON DELETE SET NULL,
    event_category TEXT,
    event_type TEXT,
    severity INTEGER DEFAULT 1,
    asset_id UUID REFERENCES assets(id) ON DELETE SET NULL,
    user_id UUID,
    source_ip INET,
    destination_ip INET,
    event_time TIMESTAMPTZ NULL
);
CREATE INDEX IF NOT EXISTS events_asset_idx ON events (asset_id);

-- Event tags
CREATE TABLE IF NOT EXISTS event_tags (
    event_id UUID REFERENCES events(id) ON DELETE CASCADE,
    tag TEXT NOT NULL,
    PRIMARY KEY (event_id, tag)
);

-- Event enrichment
CREATE TABLE IF NOT EXISTS event_enrichment (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_id UUID REFERENCES events(id) ON DELETE CASCADE,
    enrichment_type TEXT,
    enrichment_data JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Correlation rules and hits
CREATE TABLE IF NOT EXISTS correlation_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT,
    description TEXT,
    logic JSONB,
    enabled BOOLEAN DEFAULT true,
    severity INTEGER DEFAULT 1
);

CREATE TABLE IF NOT EXISTS correlation_hits (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    rule_id UUID REFERENCES correlation_rules(id) ON DELETE CASCADE,
    triggered_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    event_ids UUID[],
    confidence INTEGER DEFAULT 50
);

-- SIEM findings and related events
CREATE TABLE IF NOT EXISTS siem_findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organisation_id UUID REFERENCES organisations(id) ON DELETE RESTRICT,
    finding_type TEXT,
    severity INTEGER DEFAULT 1,
    confidence INTEGER DEFAULT 50,
    status TEXT DEFAULT 'new',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    psa_case_id UUID
);

CREATE TABLE IF NOT EXISTS finding_events (
    finding_id UUID REFERENCES siem_findings(id) ON DELETE CASCADE,
    event_id UUID REFERENCES events(id) ON DELETE RESTRICT,
    PRIMARY KEY (finding_id, event_id)
);

-- Evidence packages for PSA ingestion
CREATE TABLE IF NOT EXISTS evidence_packages (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id UUID REFERENCES siem_findings(id) ON DELETE CASCADE,
    package_uri TEXT,
    hash TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Prevent modification on raw_events (append-only) and evidence_packages
DROP TRIGGER IF EXISTS raw_events_prevent_mod_trig ON raw_events;
CREATE TRIGGER raw_events_prevent_mod_trig
    BEFORE UPDATE OR DELETE ON raw_events
    FOR EACH ROW EXECUTE FUNCTION psa_prevent_modification();

DROP TRIGGER IF EXISTS evidence_packages_prevent_mod_trig ON evidence_packages;
CREATE TRIGGER evidence_packages_prevent_mod_trig
    BEFORE UPDATE OR DELETE ON evidence_packages
    FOR EACH ROW EXECUTE FUNCTION psa_prevent_modification();

-- END SIEM SCHEMA

-- Escalations table (shared for any producer that wants to record PSA handoff)
CREATE TABLE IF NOT EXISTS escalations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source_service TEXT NOT NULL,
    source_id UUID,
    organisation_id UUID,
    psa_case_id UUID,
    status TEXT DEFAULT 'pending',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS escalations_source_idx ON escalations (source_service, source_id);

-- === End PSA schema ===


-- === Begin data-model schema (namespaced under schema `datamodel`) ===
CREATE SCHEMA IF NOT EXISTS datamodel;
SET search_path TO datamodel, public;

-- Unified Security & Operations Platform (data-model)
-- PostgreSQL schema for MVP-1+ planning
-- NOTE: This is a forward-looking schema scaffold, not yet wired to services.

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Tenancy
CREATE TABLE IF NOT EXISTS tenants (
    tenant_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name TEXT NOT NULL,
    slug TEXT UNIQUE NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Identity & Access
CREATE TABLE IF NOT EXISTS identities (
    identity_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(tenant_id),
    identity_type TEXT NOT NULL, -- user, service, agent
    display_name TEXT NOT NULL,
    email TEXT,
    status TEXT NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS roles (
    role_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(tenant_id),
    name TEXT NOT NULL,
    description TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS permissions (
    permission_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name TEXT NOT NULL UNIQUE,
    description TEXT
);

CREATE TABLE IF NOT EXISTS role_permissions (
    role_id UUID NOT NULL REFERENCES roles(role_id),
    permission_id UUID NOT NULL REFERENCES permissions(permission_id),
    PRIMARY KEY (role_id, permission_id)
);

CREATE TABLE IF NOT EXISTS identity_roles (
    identity_id UUID NOT NULL REFERENCES identities(identity_id),
    role_id UUID NOT NULL REFERENCES roles(role_id),
    PRIMARY KEY (identity_id, role_id)
);

-- Assets (datamodel)
CREATE TABLE IF NOT EXISTS assets (
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

CREATE TABLE IF NOT EXISTS asset_tags (
    asset_id UUID NOT NULL REFERENCES assets(asset_id),
    tag TEXT NOT NULL,
    PRIMARY KEY (asset_id, tag)
);

-- Agents
CREATE TABLE IF NOT EXISTS agents (
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

-- (rest of data-model tables preserved)

-- Reset search_path (return to public as default)
SET search_path TO public;

-- === End data-model schema ===

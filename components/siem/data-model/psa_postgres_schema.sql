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


-- BEGIN SIEM SCHEMA

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

-- BEGIN EDR SCHEMA

-- Endpoint telemetry (append-only)
CREATE TABLE IF NOT EXISTS process_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    asset_id UUID REFERENCES assets(id) ON DELETE SET NULL,
    process_id INTEGER,
    parent_process_id INTEGER,
    image_path TEXT,
    command_line TEXT,
    user_context TEXT,
    event_type TEXT,
    event_time TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS file_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    asset_id UUID REFERENCES assets(id) ON DELETE SET NULL,
    process_event_id UUID REFERENCES process_events(id) ON DELETE CASCADE,
    file_path TEXT,
    action TEXT,
    hash TEXT,
    event_time TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS network_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    asset_id UUID REFERENCES assets(id) ON DELETE SET NULL,
    process_event_id UUID REFERENCES process_events(id) ON DELETE CASCADE,
    local_ip INET,
    remote_ip INET,
    remote_port INTEGER,
    protocol TEXT,
    event_time TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS process_events_asset_idx ON process_events (asset_id);

-- EDR detection rules and detections
CREATE TABLE IF NOT EXISTS edr_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT,
    description TEXT,
    logic JSONB,
    severity INTEGER DEFAULT 1,
    enabled BOOLEAN DEFAULT true
);

CREATE TABLE IF NOT EXISTS edr_detections (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    asset_id UUID REFERENCES assets(id) ON DELETE SET NULL,
    detection_type TEXT,
    severity INTEGER DEFAULT 1,
    confidence INTEGER DEFAULT 50,
    rule_id UUID REFERENCES edr_rules(id) ON DELETE SET NULL,
    status TEXT DEFAULT 'new',
    detected_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    siem_event_id UUID,
    psa_case_id UUID
);

CREATE TABLE IF NOT EXISTS detection_events (
    detection_id UUID REFERENCES edr_detections(id) ON DELETE CASCADE,
    related_event_id UUID NOT NULL,
    event_type TEXT,
    PRIMARY KEY (detection_id, related_event_id)
);

-- Response & isolation
CREATE TABLE IF NOT EXISTS response_actions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    detection_id UUID REFERENCES edr_detections(id) ON DELETE CASCADE,
    action_type TEXT,
    initiated_by TEXT,
    status TEXT DEFAULT 'pending',
    executed_at TIMESTAMPTZ NULL
);

CREATE TABLE IF NOT EXISTS endpoint_isolation_state (
    asset_id UUID PRIMARY KEY REFERENCES assets(id) ON DELETE CASCADE,
    isolated BOOLEAN DEFAULT false,
    reason TEXT,
    since TIMESTAMPTZ NULL
);

-- EDR evidence (append-only)
CREATE TABLE IF NOT EXISTS edr_evidence (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    detection_id UUID REFERENCES edr_detections(id) ON DELETE CASCADE,
    evidence_type TEXT,
    storage_uri TEXT,
    hash TEXT,
    captured_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Prevent modification on append-only EDR tables
DROP TRIGGER IF EXISTS process_events_prevent_mod_trig ON process_events;
CREATE TRIGGER process_events_prevent_mod_trig
    BEFORE UPDATE OR DELETE ON process_events
    FOR EACH ROW EXECUTE FUNCTION psa_prevent_modification();

DROP TRIGGER IF EXISTS edr_evidence_prevent_mod_trig ON edr_evidence;
CREATE TRIGGER edr_evidence_prevent_mod_trig
    BEFORE UPDATE OR DELETE ON edr_evidence
    FOR EACH ROW EXECUTE FUNCTION psa_prevent_modification();

-- END EDR SCHEMA

-- BEGIN PENTEST SCHEMA

CREATE TABLE IF NOT EXISTS pentest_engagements (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organisation_id UUID REFERENCES organisations(id) ON DELETE RESTRICT,
    name TEXT,
    engagement_type TEXT,
    start_date TIMESTAMPTZ,
    end_date TIMESTAMPTZ,
    status TEXT DEFAULT 'planned',
    authorised_by UUID
);

CREATE TABLE IF NOT EXISTS pentest_scope (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    engagement_id UUID REFERENCES pentest_engagements(id) ON DELETE CASCADE,
    asset_id UUID REFERENCES assets(id) ON DELETE RESTRICT,
    scope_type TEXT,
    notes TEXT
);

CREATE TABLE IF NOT EXISTS attack_surfaces (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    engagement_id UUID REFERENCES pentest_engagements(id) ON DELETE CASCADE,
    surface_type TEXT,
    description TEXT,
    discovered_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS attack_techniques (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    technique_id TEXT,
    name TEXT,
    category TEXT
);

CREATE TABLE IF NOT EXISTS pentest_tools (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT,
    version TEXT,
    tool_type TEXT
);

CREATE TABLE IF NOT EXISTS pentest_tool_runs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    engagement_id UUID REFERENCES pentest_engagements(id) ON DELETE CASCADE,
    tool_id UUID REFERENCES pentest_tools(id) ON DELETE RESTRICT,
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    status TEXT,
    raw_output_uri TEXT
);

CREATE TABLE IF NOT EXISTS pentest_findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    engagement_id UUID REFERENCES pentest_engagements(id) ON DELETE CASCADE,
    asset_id UUID REFERENCES assets(id) ON DELETE RESTRICT,
    finding_type TEXT,
    title TEXT,
    description TEXT,
    severity INTEGER,
    confidence INTEGER,
    exploit_proven BOOLEAN DEFAULT false,
    discovered_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS finding_vulnerabilities (
    finding_id UUID REFERENCES pentest_findings(id) ON DELETE CASCADE,
    vulnerability_id UUID NOT NULL,
    PRIMARY KEY (finding_id, vulnerability_id)
);

CREATE TABLE IF NOT EXISTS attack_chains (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    engagement_id UUID REFERENCES pentest_engagements(id) ON DELETE CASCADE,
    description TEXT,
    impact TEXT,
    created_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS attack_chain_steps (
    chain_id UUID REFERENCES attack_chains(id) ON DELETE CASCADE,
    step_order INTEGER,
    technique_id TEXT,
    finding_id UUID REFERENCES pentest_findings(id) ON DELETE SET NULL,
    notes TEXT,
    PRIMARY KEY (chain_id, step_order)
);

CREATE TABLE IF NOT EXISTS pentest_evidence (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id UUID REFERENCES pentest_findings(id) ON DELETE CASCADE,
    evidence_type TEXT,
    storage_uri TEXT,
    hash TEXT,
    captured_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS pentest_cases (
    finding_id UUID PRIMARY KEY REFERENCES pentest_findings(id) ON DELETE CASCADE,
    psa_case_id UUID,
    created_at TIMESTAMPTZ DEFAULT now()
);

-- Prevent modification on pentest_evidence and pentest_tool_runs (raw outputs)
DROP TRIGGER IF EXISTS pentest_evidence_prevent_mod_trig ON pentest_evidence;
CREATE TRIGGER pentest_evidence_prevent_mod_trig
    BEFORE UPDATE OR DELETE ON pentest_evidence
    FOR EACH ROW EXECUTE FUNCTION psa_prevent_modification();

DROP TRIGGER IF EXISTS pentest_tool_runs_prevent_mod_trig ON pentest_tool_runs;
CREATE TRIGGER pentest_tool_runs_prevent_mod_trig
    BEFORE UPDATE OR DELETE ON pentest_tool_runs
    FOR EACH ROW EXECUTE FUNCTION psa_prevent_modification();

-- END PENTEST SCHEMA

-- BEGIN VULNERABILITY MANAGEMENT SCHEMA

-- Canonical vulnerabilities table
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    cve_id TEXT,
    title TEXT,
    description TEXT,
    cvss_score NUMERIC,
    cvss_vector TEXT,
    severity INTEGER,
    published_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS vulnerability_references (
    vulnerability_id UUID REFERENCES vulnerabilities(id) ON DELETE CASCADE,
    reference_type TEXT,
    reference_url TEXT,
    PRIMARY KEY (vulnerability_id, reference_url)
);

-- Asset observations (asset_vulnerabilities)
CREATE TABLE IF NOT EXISTS asset_vulnerabilities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    asset_id UUID REFERENCES assets(id) ON DELETE CASCADE,
    vulnerability_id UUID REFERENCES vulnerabilities(id) ON DELETE SET NULL,
    detection_source TEXT,
    first_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
    status TEXT DEFAULT 'open',
    proof JSONB
);

CREATE INDEX IF NOT EXISTS asset_vulnerabilities_asset_idx ON asset_vulnerabilities (asset_id);

CREATE TABLE IF NOT EXISTS vulnerability_scans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_type TEXT,
    tool TEXT,
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    status TEXT
);

-- Risk assessments
CREATE TABLE IF NOT EXISTS risk_assessments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    asset_vulnerability_id UUID REFERENCES asset_vulnerabilities(id) ON DELETE CASCADE,
    exploitability INTEGER,
    impact INTEGER,
    exposure INTEGER,
    adjusted_risk INTEGER,
    assessed_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS risk_factors (
    risk_assessment_id UUID REFERENCES risk_assessments(id) ON DELETE CASCADE,
    factor_type TEXT,
    factor_value TEXT,
    PRIMARY KEY (risk_assessment_id, factor_type, factor_value)
);

-- Remediation recommendations
CREATE TABLE IF NOT EXISTS remediation_recommendations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    vulnerability_id UUID REFERENCES vulnerabilities(id) ON DELETE CASCADE,
    recommended_action TEXT,
    automation_possible BOOLEAN DEFAULT false,
    notes TEXT
);

-- Risk decisions
CREATE TABLE IF NOT EXISTS risk_decisions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    asset_vulnerability_id UUID REFERENCES asset_vulnerabilities(id) ON DELETE CASCADE,
    decision TEXT,
    justification TEXT,
    decided_by UUID,
    valid_until TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- PSA integration mapping
CREATE TABLE IF NOT EXISTS vulnerability_cases (
    asset_vulnerability_id UUID REFERENCES asset_vulnerabilities(id) ON DELETE CASCADE,
    psa_case_id UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (asset_vulnerability_id, psa_case_id)
);

-- Evidence
CREATE TABLE IF NOT EXISTS vulnerability_evidence (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    asset_vulnerability_id UUID REFERENCES asset_vulnerabilities(id) ON DELETE CASCADE,
    evidence_type TEXT,
    storage_uri TEXT,
    hash TEXT,
    captured_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Simple JSONB-backed vulnerability_records table for application-level storage (optional)
CREATE TABLE IF NOT EXISTS vulnerability_records (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    payload JSONB NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Prevent accidental deletion of evidence
DROP TRIGGER IF EXISTS vulnerability_evidence_prevent_mod_trig ON vulnerability_evidence;
CREATE TRIGGER vulnerability_evidence_prevent_mod_trig
    BEFORE UPDATE OR DELETE ON vulnerability_evidence
    FOR EACH ROW EXECUTE FUNCTION psa_prevent_modification();

-- END VULNERABILITY MANAGEMENT SCHEMA



-- BEGIN RMM SCHEMA

CREATE TABLE IF NOT EXISTS configuration_profiles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    profile_type TEXT,
    description TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS configuration_items (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    profile_id UUID NOT NULL REFERENCES configuration_profiles(id),
    config_key TEXT NOT NULL,
    desired_value TEXT,
    enforcement_mode TEXT
);

CREATE TABLE IF NOT EXISTS asset_configuration_profiles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    asset_id UUID NOT NULL,
    profile_id UUID NOT NULL REFERENCES configuration_profiles(id),
    assigned_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS patch_catalog (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    vendor TEXT,
    product TEXT,
    patch_id TEXT,
    release_date TIMESTAMPTZ,
    severity INTEGER
);

CREATE TABLE IF NOT EXISTS asset_patches (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    asset_id UUID NOT NULL,
    patch_id UUID NOT NULL REFERENCES patch_catalog(id),
    status TEXT,
    detected_at TIMESTAMPTZ,
    installed_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS patch_jobs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    psa_case_id UUID,
    scheduled_for TIMESTAMPTZ,
    reboot_policy TEXT,
    status TEXT
);

CREATE TABLE IF NOT EXISTS scripts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT,
    language TEXT,
    content TEXT,
    requires_approval BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS script_jobs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    script_id UUID REFERENCES scripts(id),
    asset_id UUID,
    psa_task_id UUID,
    status TEXT,
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS script_results (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    job_id UUID NOT NULL REFERENCES script_jobs(id),
    stdout TEXT,
    stderr TEXT,
    exit_code INTEGER,
    hash TEXT
);

CREATE TABLE IF NOT EXISTS software_packages (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT,
    version TEXT,
    installer_uri TEXT,
    hash TEXT
);

CREATE TABLE IF NOT EXISTS deployment_jobs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    package_id UUID REFERENCES software_packages(id),
    asset_id UUID,
    psa_case_id UUID,
    status TEXT,
    executed_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS remote_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    asset_id UUID,
    initiated_by UUID,
    session_type TEXT,
    started_at TIMESTAMPTZ,
    ended_at TIMESTAMPTZ,
    recorded BOOLEAN DEFAULT FALSE
);

CREATE TABLE IF NOT EXISTS rmm_evidence (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    asset_id UUID,
    evidence_type TEXT,
    related_entity TEXT,
    related_id UUID,
    storage_uri TEXT,
    hash TEXT,
    captured_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Append-only guards for evidence and script results
DROP TRIGGER IF EXISTS rmm_evidence_prevent_mod_trig ON rmm_evidence;
CREATE TRIGGER rmm_evidence_prevent_mod_trig
    BEFORE UPDATE OR DELETE ON rmm_evidence
    FOR EACH ROW EXECUTE FUNCTION psa_prevent_modification();

DROP TRIGGER IF EXISTS script_results_prevent_mod_trig ON script_results;
CREATE TRIGGER script_results_prevent_mod_trig
    BEFORE UPDATE OR DELETE ON script_results
    FOR EACH ROW EXECUTE FUNCTION psa_prevent_modification();

-- END RMM SCHEMA




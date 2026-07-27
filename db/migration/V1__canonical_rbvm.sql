BEGIN;

CREATE SCHEMA IF NOT EXISTS rbvm;

CREATE TABLE rbvm.tenant (
    id uuid PRIMARY KEY,
    tenant_key text NOT NULL UNIQUE,
    display_name text NOT NULL,
    created_at timestamptz NOT NULL
);

CREATE TABLE rbvm.source_profile (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    external_key text NOT NULL,
    source_type text NOT NULL CHECK (source_type = 'WAZUH_CSV'),
    contract_id text NOT NULL CHECK (contract_id = 'WAZUH_CSV_V1'),
    semantics text NOT NULL CHECK (semantics = 'POSITIVE_OBSERVATION_EXPORT'),
    enabled boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL,
    UNIQUE (tenant_id, id),
    UNIQUE (tenant_id, external_key),
    FOREIGN KEY (tenant_id) REFERENCES rbvm.tenant(id)
);

CREATE TABLE rbvm.import_run (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    source_profile_id uuid NOT NULL,
    status text NOT NULL CHECK (status IN (
        'UPLOADED', 'VALIDATING', 'PREVIEW_READY', 'IMPORTING', 'RECONCILING',
        'COMPLETED', 'PARTIAL', 'REJECTED', 'FAILED'
    )),
    contract_id text NOT NULL CHECK (contract_id = 'WAZUH_CSV_V1'),
    semantics text NOT NULL CHECK (semantics = 'POSITIVE_OBSERVATION_EXPORT'),
    commit_scope text NOT NULL CHECK (commit_scope = 'CANONICAL_DOMAIN_AND_RAW_EVIDENCE'),
    file_sha256 char(64) NOT NULL CHECK (file_sha256 ~ '^[a-f0-9]{64}$'),
    file_size_bytes bigint NOT NULL CHECK (file_size_bytes > 0),
    raw_evidence_uri text NOT NULL,
    logical_rows bigint CHECK (logical_rows >= 0),
    accepted_rows bigint CHECK (accepted_rows >= 0),
    deduplicated_rows bigint CHECK (deduplicated_rows >= 0),
    quarantined_rows bigint CHECK (quarantined_rows >= 0),
    terminal_reason text,
    created_at timestamptz NOT NULL,
    confirmed_at timestamptz,
    materialized_at timestamptz,
    UNIQUE (tenant_id, id),
    UNIQUE (tenant_id, source_profile_id, file_sha256),
    FOREIGN KEY (tenant_id, source_profile_id)
        REFERENCES rbvm.source_profile(tenant_id, id),
    CHECK (logical_rows IS NULL OR logical_rows =
        COALESCE(accepted_rows, 0) + COALESCE(deduplicated_rows, 0) + COALESCE(quarantined_rows, 0))
);

CREATE TABLE rbvm.api_idempotency_key (
    tenant_id uuid NOT NULL,
    operation_scope text NOT NULL,
    idempotency_key text NOT NULL CHECK (length(idempotency_key) BETWEEN 8 AND 128),
    request_sha256 char(64) NOT NULL CHECK (request_sha256 ~ '^[a-f0-9]{64}$'),
    resource_id uuid NOT NULL,
    created_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, operation_scope, idempotency_key),
    FOREIGN KEY (tenant_id) REFERENCES rbvm.tenant(id)
);

CREATE TABLE rbvm.asset (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    source_profile_id uuid NOT NULL,
    observed_name text NOT NULL,
    normalized_observed_name text NOT NULL,
    os_name_raw text NOT NULL DEFAULT '',
    identity_basis text NOT NULL CHECK (identity_basis = 'SOURCE_NAME_ONLY'),
    identity_confidence text NOT NULL CHECK (identity_confidence = 'LOW'),
    first_observed_at timestamptz NOT NULL,
    last_observed_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    UNIQUE (tenant_id, id),
    UNIQUE (tenant_id, source_profile_id, normalized_observed_name),
    FOREIGN KEY (tenant_id, source_profile_id)
        REFERENCES rbvm.source_profile(tenant_id, id),
    CHECK (first_observed_at <= last_observed_at)
);

CREATE TABLE rbvm.vulnerability (
    id uuid PRIMARY KEY,
    cve_id text NOT NULL UNIQUE CHECK (cve_id ~ '^CVE-[0-9]{4}-[0-9]{4,}$'),
    created_at timestamptz NOT NULL
);

CREATE TABLE rbvm.asset_component (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    asset_id uuid NOT NULL,
    observed_product_name text NOT NULL,
    normalized_product_name text NOT NULL,
    version_status text NOT NULL CHECK (version_status = 'UNKNOWN_FROM_SOURCE'),
    first_observed_at timestamptz NOT NULL,
    last_observed_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    UNIQUE (tenant_id, id),
    UNIQUE (tenant_id, asset_id, normalized_product_name),
    FOREIGN KEY (tenant_id, asset_id) REFERENCES rbvm.asset(tenant_id, id),
    CHECK (first_observed_at <= last_observed_at)
);

CREATE TABLE rbvm.observation (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    source_profile_id uuid NOT NULL,
    asset_id uuid NOT NULL,
    vulnerability_id uuid NOT NULL,
    component_id uuid NOT NULL,
    fingerprint char(64) NOT NULL CHECK (fingerprint ~ '^[a-f0-9]{64}$'),
    severity text NOT NULL CHECK (severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN')),
    source_severity_recognized boolean NOT NULL,
    description_snapshot text NOT NULL,
    references_raw text NOT NULL,
    os_name_raw text NOT NULL,
    detected_at timestamptz NOT NULL,
    first_ingested_at timestamptz NOT NULL,
    UNIQUE (tenant_id, id),
    UNIQUE (tenant_id, source_profile_id, fingerprint),
    FOREIGN KEY (tenant_id, source_profile_id)
        REFERENCES rbvm.source_profile(tenant_id, id),
    FOREIGN KEY (tenant_id, asset_id) REFERENCES rbvm.asset(tenant_id, id),
    FOREIGN KEY (vulnerability_id) REFERENCES rbvm.vulnerability(id),
    FOREIGN KEY (tenant_id, component_id) REFERENCES rbvm.asset_component(tenant_id, id)
);

CREATE TABLE rbvm.import_observation (
    tenant_id uuid NOT NULL,
    import_id uuid NOT NULL,
    observation_id uuid NOT NULL,
    source_row_number bigint NOT NULL CHECK (source_row_number >= 2),
    linked_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, import_id, observation_id),
    UNIQUE (tenant_id, import_id, source_row_number),
    FOREIGN KEY (tenant_id, import_id) REFERENCES rbvm.import_run(tenant_id, id),
    FOREIGN KEY (tenant_id, observation_id) REFERENCES rbvm.observation(tenant_id, id)
);

CREATE TABLE rbvm.observation_reference (
    tenant_id uuid NOT NULL,
    observation_id uuid NOT NULL,
    ordinal integer NOT NULL CHECK (ordinal >= 0),
    reference_uri text NOT NULL,
    is_http boolean NOT NULL,
    PRIMARY KEY (tenant_id, observation_id, ordinal),
    FOREIGN KEY (tenant_id, observation_id) REFERENCES rbvm.observation(tenant_id, id)
);

CREATE TABLE rbvm.vulnerability_case (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    source_profile_id uuid NOT NULL,
    asset_id uuid NOT NULL,
    vulnerability_id uuid NOT NULL,
    status text NOT NULL CHECK (status IN ('OPEN', 'ACCEPTED_RISK', 'FALSE_POSITIVE', 'CLOSED_MANUAL')),
    closure_policy text NOT NULL CHECK (closure_policy = 'POSITIVE_ONLY_NO_AUTO_CLOSE'),
    current_severity text NOT NULL CHECK (current_severity IN (
        'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'
    )),
    first_observed_at timestamptz NOT NULL,
    last_observed_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    UNIQUE (tenant_id, id),
    UNIQUE (tenant_id, source_profile_id, asset_id, vulnerability_id),
    FOREIGN KEY (tenant_id, source_profile_id)
        REFERENCES rbvm.source_profile(tenant_id, id),
    FOREIGN KEY (tenant_id, asset_id) REFERENCES rbvm.asset(tenant_id, id),
    FOREIGN KEY (vulnerability_id) REFERENCES rbvm.vulnerability(id),
    CHECK (first_observed_at <= last_observed_at)
);

CREATE TABLE rbvm.exposure (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    source_profile_id uuid NOT NULL,
    case_id uuid NOT NULL,
    asset_id uuid NOT NULL,
    vulnerability_id uuid NOT NULL,
    component_id uuid NOT NULL,
    status text NOT NULL CHECK (status = 'OPEN'),
    closure_policy text NOT NULL CHECK (closure_policy = 'POSITIVE_ONLY_NO_AUTO_CLOSE'),
    current_severity text NOT NULL CHECK (current_severity IN (
        'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'
    )),
    current_severity_observed_at timestamptz NOT NULL,
    first_observed_at timestamptz NOT NULL,
    last_observed_at timestamptz NOT NULL,
    observation_count bigint NOT NULL CHECK (observation_count > 0),
    severity_changed boolean NOT NULL DEFAULT false,
    timestamp_severity_conflict boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    UNIQUE (tenant_id, id),
    UNIQUE (tenant_id, source_profile_id, asset_id, vulnerability_id, component_id),
    FOREIGN KEY (tenant_id, source_profile_id)
        REFERENCES rbvm.source_profile(tenant_id, id),
    FOREIGN KEY (tenant_id, case_id) REFERENCES rbvm.vulnerability_case(tenant_id, id),
    FOREIGN KEY (tenant_id, asset_id) REFERENCES rbvm.asset(tenant_id, id),
    FOREIGN KEY (vulnerability_id) REFERENCES rbvm.vulnerability(id),
    FOREIGN KEY (tenant_id, component_id) REFERENCES rbvm.asset_component(tenant_id, id),
    CHECK (first_observed_at <= last_observed_at),
    CHECK (current_severity_observed_at BETWEEN first_observed_at AND last_observed_at)
);

CREATE TABLE rbvm.exposure_observation (
    tenant_id uuid NOT NULL,
    exposure_id uuid NOT NULL,
    observation_id uuid NOT NULL,
    PRIMARY KEY (tenant_id, exposure_id, observation_id),
    FOREIGN KEY (tenant_id, exposure_id) REFERENCES rbvm.exposure(tenant_id, id),
    FOREIGN KEY (tenant_id, observation_id) REFERENCES rbvm.observation(tenant_id, id)
);

CREATE TABLE rbvm.validation_issue (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    import_id uuid NOT NULL,
    source_row_number bigint NOT NULL CHECK (source_row_number >= 1),
    issue_level text NOT NULL CHECK (issue_level IN ('WARNING', 'ERROR')),
    issue_code text NOT NULL,
    issue_message text NOT NULL,
    raw_payload jsonb,
    created_at timestamptz NOT NULL,
    FOREIGN KEY (tenant_id, import_id) REFERENCES rbvm.import_run(tenant_id, id)
);

CREATE INDEX asset_last_observed_idx
    ON rbvm.asset (tenant_id, last_observed_at DESC);
CREATE INDEX observation_cve_time_idx
    ON rbvm.observation (vulnerability_id, detected_at DESC);
CREATE INDEX observation_asset_time_idx
    ON rbvm.observation (tenant_id, asset_id, detected_at DESC);
CREATE INDEX exposure_open_severity_idx
    ON rbvm.exposure (tenant_id, current_severity, last_observed_at DESC)
    WHERE status = 'OPEN';
CREATE INDEX case_open_severity_idx
    ON rbvm.vulnerability_case (tenant_id, current_severity, last_observed_at DESC)
    WHERE status = 'OPEN';
CREATE INDEX validation_issue_import_idx
    ON rbvm.validation_issue (tenant_id, import_id, source_row_number);

COMMENT ON COLUMN rbvm.asset.identity_basis IS
    'WAZUH_CSV_V1 has no stable Agent ID; assets are isolated per source profile and normalized name.';
COMMENT ON COLUMN rbvm.exposure.closure_policy IS
    'A positive-only export cannot prove absence. Automatic technical closure is forbidden.';
COMMENT ON COLUMN rbvm.vulnerability_case.closure_policy IS
    'Case remains open unless an explicit later workflow action changes it.';

COMMIT;

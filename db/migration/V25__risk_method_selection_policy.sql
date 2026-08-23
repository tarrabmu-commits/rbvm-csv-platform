BEGIN;

-- V25 records immutable tenant-scoped primary risk-method selection policy revisions.
-- It deliberately creates no current/latest/default view: downstream decisions must carry an exact
-- policy revision and SHA, and therefore an exact selected method family, ID, version, and SHA.
CREATE TABLE rbvm.risk_method_selection_policy (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    contract_id text NOT NULL CHECK (
        contract_id = 'RBVM_RISK_METHOD_SELECTION_POLICY_V1'
    ),
    semantics text NOT NULL CHECK (
        semantics = 'TENANT_SCOPED_EXPLICIT_PRIMARY_RISK_METHOD_EXACT_IDENTITY'
    ),
    revision integer NOT NULL CHECK (revision > 0),
    policy_sha256 char(64) NOT NULL CHECK (policy_sha256 ~ '^[a-f0-9]{64}$'),
    canonical_payload_format text NOT NULL CHECK (
        canonical_payload_format = 'RBVM_RISK_METHOD_SELECTION_POLICY_CANONICAL_BINARY_V1'
    ),
    canonical_payload bytea NOT NULL CHECK (octet_length(canonical_payload) > 0),
    selection_role text NOT NULL CHECK (selection_role = 'PRIMARY'),
    method_family text NOT NULL CHECK (
        method_family IN ('RBVM_FORMULA', 'STANDARD_DERIVED')
    ),
    method_id text NOT NULL CHECK (
        length(trim(method_id)) > 0 AND method_id = trim(method_id)
    ),
    method_version integer NOT NULL CHECK (method_version > 0),
    method_sha256 char(64) NOT NULL CHECK (method_sha256 ~ '^[a-f0-9]{64}$'),
    installed_at timestamptz NOT NULL,
    UNIQUE (tenant_id, id),
    CONSTRAINT risk_method_selection_one_revision
        UNIQUE (tenant_id, contract_id, revision),
    CONSTRAINT risk_method_selection_policy_sha_unique
        UNIQUE (tenant_id, policy_sha256),
    FOREIGN KEY (tenant_id) REFERENCES rbvm.tenant(id)
);

CREATE INDEX risk_method_selection_policy_lookup_idx
    ON rbvm.risk_method_selection_policy (tenant_id, contract_id, revision);

CREATE INDEX risk_method_selection_policy_method_identity_idx
    ON rbvm.risk_method_selection_policy (
        tenant_id,
        method_family,
        method_id,
        method_version,
        method_sha256
    );

COMMENT ON TABLE rbvm.risk_method_selection_policy IS
    'Immutable tenant-scoped primary risk-method selection policy revisions. Each row binds one exact Formula or STANDARD_DERIVED identity. There is no implicit current/latest/default policy and no result averaging, Priority, Treatment, or SLA semantic.';

COMMIT;

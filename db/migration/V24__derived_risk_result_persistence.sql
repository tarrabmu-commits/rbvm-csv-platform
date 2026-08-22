BEGIN;

ALTER TABLE rbvm.decision_input_snapshot
    ADD CONSTRAINT decision_input_snapshot_derived_risk_identity
        UNIQUE (tenant_id, snapshot_sha256, finding_id);

CREATE TABLE rbvm.derived_risk_result (
    id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    input_snapshot_sha256 char(64) NOT NULL
        CHECK (input_snapshot_sha256 ~ '^[a-f0-9]{64}$'),
    finding_id uuid NOT NULL,
    methodology_id text NOT NULL CHECK (length(trim(methodology_id)) > 0),
    methodology_version integer NOT NULL CHECK (methodology_version > 0),
    methodology_sha256 char(64) NOT NULL
        CHECK (methodology_sha256 ~ '^[a-f0-9]{64}$'),
    result_state text NOT NULL
        CHECK (result_state IN ('COMPUTED', 'NOT_APPLICABLE', 'NON_COMPUTABLE')),
    reason_code text,
    numeric_score numeric,
    numeric_scale text,
    rating text,
    canonical_payload_format text NOT NULL
        CHECK (canonical_payload_format = 'RBVM_DERIVED_RISK_RESULT_CANONICAL_BINARY_V1'),
    result_sha256 char(64) NOT NULL
        CHECK (result_sha256 ~ '^[a-f0-9]{64}$'),
    canonical_payload bytea NOT NULL CHECK (octet_length(canonical_payload) > 0),
    persisted_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, id),
    UNIQUE (
        tenant_id,
        input_snapshot_sha256,
        methodology_id,
        methodology_version,
        methodology_sha256
    ),
    UNIQUE (tenant_id, result_sha256),
    FOREIGN KEY (tenant_id, input_snapshot_sha256, finding_id)
        REFERENCES rbvm.decision_input_snapshot(tenant_id, snapshot_sha256, finding_id),
    CHECK (
        (result_state = 'COMPUTED'
            AND reason_code IS NULL
            AND numeric_score IS NOT NULL
            AND numeric_scale IS NOT NULL
            AND length(trim(numeric_scale)) > 0)
        OR
        (result_state IN ('NOT_APPLICABLE', 'NON_COMPUTABLE')
            AND reason_code IS NOT NULL
            AND length(trim(reason_code)) > 0
            AND numeric_score IS NULL
            AND numeric_scale IS NULL
            AND rating IS NULL)
    )
);

CREATE INDEX derived_risk_result_finding_history_idx
    ON rbvm.derived_risk_result (
        tenant_id,
        finding_id,
        methodology_id,
        persisted_at DESC
    );

COMMENT ON TABLE rbvm.derived_risk_result IS
    'Append-only persisted canonical result for one exact Decision Input V3 snapshot and one exact derived risk methodology identity.';
COMMENT ON COLUMN rbvm.derived_risk_result.numeric_score IS
    'Methodology-native numeric score only for COMPUTED results. This is not Priority, SLA, Treatment, or a cross-methodology normalized score.';
COMMENT ON COLUMN rbvm.derived_risk_result.rating IS
    'Optional methodology-native/derived rating. NULL when the methodology does not define one; never remediation Priority.';
COMMENT ON COLUMN rbvm.derived_risk_result.canonical_payload IS
    'Exact RBVM_DERIVED_RISK_RESULT_CANONICAL_BINARY_V1 bytes; result_sha256 is their immutable identity.';

COMMIT;

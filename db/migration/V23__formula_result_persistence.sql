BEGIN;

ALTER TABLE rbvm.decision_input_snapshot
    ADD CONSTRAINT decision_input_snapshot_formula_identity_unique
        UNIQUE (
            tenant_id,
            snapshot_sha256,
            finding_id,
            methodology_revision,
            methodology_policy_sha256,
            evaluated_at
        );

CREATE TABLE rbvm.formula_result (
    id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    input_snapshot_sha256 char(64) NOT NULL
        CHECK (input_snapshot_sha256 ~ '^[a-f0-9]{64}$'),
    finding_id uuid NOT NULL,
    evaluated_at timestamptz NOT NULL,
    methodology_revision integer NOT NULL CHECK (methodology_revision > 0),
    methodology_policy_sha256 char(64) NOT NULL
        CHECK (methodology_policy_sha256 ~ '^[a-f0-9]{64}$'),
    formula_id text NOT NULL CHECK (formula_id = 'RBVM_FORMULA_V1'),
    formula_version integer NOT NULL CHECK (formula_version = 1),
    formula_sha256 char(64) NOT NULL
        CHECK (formula_sha256 = '88bf31f510089b4209b1ffcf1c15b39fef60548209875334f084888316e9028e'),
    result_state text NOT NULL
        CHECK (result_state IN ('COMPUTED', 'NOT_APPLICABLE', 'NON_COMPUTABLE')),
    reason_codes text[] NOT NULL,
    relative_risk_index numeric(5,2),
    explanation_payload_format text NOT NULL
        CHECK (explanation_payload_format = 'RBVM_FORMULA_EXPLANATION_CANONICAL_BINARY_V1'),
    explanation_sha256 char(64) NOT NULL
        CHECK (explanation_sha256 ~ '^[a-f0-9]{64}$'),
    explanation_payload bytea NOT NULL CHECK (octet_length(explanation_payload) > 0),
    persisted_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, id),
    UNIQUE (
        tenant_id,
        input_snapshot_sha256,
        formula_id,
        formula_version,
        formula_sha256
    ),
    UNIQUE (tenant_id, explanation_sha256),
    FOREIGN KEY (
        tenant_id,
        input_snapshot_sha256,
        finding_id,
        methodology_revision,
        methodology_policy_sha256,
        evaluated_at
    ) REFERENCES rbvm.decision_input_snapshot(
        tenant_id,
        snapshot_sha256,
        finding_id,
        methodology_revision,
        methodology_policy_sha256,
        evaluated_at
    ),
    CHECK (
        (result_state = 'COMPUTED'
            AND cardinality(reason_codes) = 0
            AND relative_risk_index IS NOT NULL
            AND relative_risk_index >= 0
            AND relative_risk_index <= 100)
        OR
        (result_state IN ('NOT_APPLICABLE', 'NON_COMPUTABLE')
            AND cardinality(reason_codes) >= 1
            AND relative_risk_index IS NULL)
    )
);

CREATE INDEX formula_result_finding_history_idx
    ON rbvm.formula_result (tenant_id, finding_id, evaluated_at DESC, persisted_at DESC);

COMMENT ON TABLE rbvm.formula_result IS
    'Append-only persisted Formula result and exact canonical explanation bytes for one immutable Decision Input snapshot and exact Formula identity.';
COMMENT ON COLUMN rbvm.formula_result.relative_risk_index IS
    'Dimensionless RBVM Relative Risk Index. NULL for NOT_APPLICABLE and NON_COMPUTABLE; never a Priority, SLA, or Treatment value.';
COMMENT ON COLUMN rbvm.formula_result.reason_codes IS
    'Ordered canonical terminal reason identifiers. Empty only for COMPUTED results.';
COMMENT ON COLUMN rbvm.formula_result.explanation_payload IS
    'Exact RBVM_FORMULA_EXPLANATION_CANONICAL_BINARY_V1 bytes; SHA-256 is stored separately for identity/integrity verification.';

COMMIT;

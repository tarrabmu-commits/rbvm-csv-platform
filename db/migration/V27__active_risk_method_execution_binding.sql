BEGIN;

-- V27 persists the exact provenance of one risk-method execution. The binding is never keyed by
-- "current": callers must supply an exact activation revision + activation event SHA and an exact
-- already-persisted Decision Input snapshot SHA.
ALTER TABLE rbvm.risk_method_selection_policy_activation_event
    ADD CONSTRAINT risk_method_selection_activation_execution_identity
        UNIQUE (
            tenant_id,
            activation_revision,
            event_sha256,
            policy_revision,
            policy_sha256
        );

-- Result-side composite identities let the binding prove in PostgreSQL that the referenced result
-- came from the same exact Decision Input and exact method identity selected by the policy.
ALTER TABLE rbvm.formula_result
    ADD CONSTRAINT formula_result_execution_binding_identity
        UNIQUE (
            tenant_id,
            explanation_sha256,
            input_snapshot_sha256,
            formula_id,
            formula_version,
            formula_sha256
        );

ALTER TABLE rbvm.derived_risk_result
    ADD CONSTRAINT derived_risk_result_execution_binding_identity
        UNIQUE (
            tenant_id,
            result_sha256,
            input_snapshot_sha256,
            methodology_id,
            methodology_version,
            methodology_sha256
        );

CREATE TABLE rbvm.active_risk_method_execution_binding (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    contract_id text NOT NULL CHECK (
        contract_id = 'RBVM_ACTIVE_RISK_METHOD_EXECUTION_BINDING_V1'
    ),
    semantics text NOT NULL CHECK (
        semantics =
            'EXACT_ACTIVATION_EVENT_EXACT_POLICY_EXACT_PRIMARY_METHOD_EXACT_DECISION_INPUT_EXACT_RESULT'
    ),
    activation_revision integer NOT NULL CHECK (activation_revision > 0),
    activation_event_sha256 char(64) NOT NULL CHECK (
        activation_event_sha256 ~ '^[a-f0-9]{64}$'
    ),
    policy_revision integer NOT NULL CHECK (policy_revision > 0),
    policy_sha256 char(64) NOT NULL CHECK (policy_sha256 ~ '^[a-f0-9]{64}$'),
    selection_role text NOT NULL CHECK (selection_role = 'PRIMARY'),
    method_family text NOT NULL CHECK (
        method_family IN ('RBVM_FORMULA', 'STANDARD_DERIVED')
    ),
    method_id text NOT NULL CHECK (
        length(trim(method_id)) > 0 AND method_id = trim(method_id)
    ),
    method_version integer NOT NULL CHECK (method_version > 0),
    method_sha256 char(64) NOT NULL CHECK (method_sha256 ~ '^[a-f0-9]{64}$'),
    input_snapshot_sha256 char(64) NOT NULL CHECK (
        input_snapshot_sha256 ~ '^[a-f0-9]{64}$'
    ),
    result_family text NOT NULL CHECK (
        result_family IN ('RBVM_FORMULA_RESULT', 'DERIVED_RISK_RESULT')
    ),
    result_sha256 char(64) NOT NULL CHECK (result_sha256 ~ '^[a-f0-9]{64}$'),
    formula_explanation_sha256 char(64),
    derived_result_sha256 char(64),
    canonical_payload_format text NOT NULL CHECK (
        canonical_payload_format =
            'RBVM_ACTIVE_RISK_METHOD_EXECUTION_BINDING_CANONICAL_BINARY_V1'
    ),
    canonical_payload bytea NOT NULL CHECK (octet_length(canonical_payload) > 0),
    binding_sha256 char(64) NOT NULL CHECK (binding_sha256 ~ '^[a-f0-9]{64}$'),
    persisted_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (tenant_id, id),
    CONSTRAINT active_risk_method_execution_one_activation_input
        UNIQUE (tenant_id, activation_event_sha256, input_snapshot_sha256),
    CONSTRAINT active_risk_method_execution_binding_sha_unique
        UNIQUE (tenant_id, binding_sha256),
    CONSTRAINT active_risk_method_execution_result_shape CHECK (
        (
            result_family = 'RBVM_FORMULA_RESULT'
            AND method_family = 'RBVM_FORMULA'
            AND formula_explanation_sha256 IS NOT NULL
            AND formula_explanation_sha256 ~ '^[a-f0-9]{64}$'
            AND formula_explanation_sha256 = result_sha256
            AND derived_result_sha256 IS NULL
        )
        OR
        (
            result_family = 'DERIVED_RISK_RESULT'
            AND method_family = 'STANDARD_DERIVED'
            AND derived_result_sha256 IS NOT NULL
            AND derived_result_sha256 ~ '^[a-f0-9]{64}$'
            AND derived_result_sha256 = result_sha256
            AND formula_explanation_sha256 IS NULL
        )
    ),
    FOREIGN KEY (tenant_id) REFERENCES rbvm.tenant(id),
    FOREIGN KEY (
        tenant_id,
        activation_revision,
        activation_event_sha256,
        policy_revision,
        policy_sha256
    ) REFERENCES rbvm.risk_method_selection_policy_activation_event(
        tenant_id,
        activation_revision,
        event_sha256,
        policy_revision,
        policy_sha256
    ),
    FOREIGN KEY (tenant_id, policy_revision, policy_sha256)
        REFERENCES rbvm.risk_method_selection_policy(tenant_id, revision, policy_sha256),
    FOREIGN KEY (tenant_id, input_snapshot_sha256)
        REFERENCES rbvm.decision_input_snapshot(tenant_id, snapshot_sha256),
    FOREIGN KEY (
        tenant_id,
        formula_explanation_sha256,
        input_snapshot_sha256,
        method_id,
        method_version,
        method_sha256
    ) REFERENCES rbvm.formula_result(
        tenant_id,
        explanation_sha256,
        input_snapshot_sha256,
        formula_id,
        formula_version,
        formula_sha256
    ),
    FOREIGN KEY (
        tenant_id,
        derived_result_sha256,
        input_snapshot_sha256,
        method_id,
        method_version,
        method_sha256
    ) REFERENCES rbvm.derived_risk_result(
        tenant_id,
        result_sha256,
        input_snapshot_sha256,
        methodology_id,
        methodology_version,
        methodology_sha256
    )
);

CREATE INDEX active_risk_method_execution_activation_idx
    ON rbvm.active_risk_method_execution_binding (
        tenant_id,
        activation_revision,
        activation_event_sha256,
        persisted_at DESC
    );

CREATE INDEX active_risk_method_execution_input_idx
    ON rbvm.active_risk_method_execution_binding (
        tenant_id,
        input_snapshot_sha256,
        persisted_at DESC
    );

COMMENT ON TABLE rbvm.active_risk_method_execution_binding IS
    'Immutable provenance binding from one exact ACTIVE Risk Method Selection activation event and policy to one exact Decision Input V3 snapshot and exact native result identity. No current/latest/default, Priority, Treatment, or SLA semantic.';
COMMENT ON COLUMN rbvm.active_risk_method_execution_binding.activation_event_sha256 IS
    'Exact historical activation event identity. Persisted execution provenance must never replace this with a current pointer.';
COMMENT ON COLUMN rbvm.active_risk_method_execution_binding.result_sha256 IS
    'Canonical native result identity: Formula explanation SHA for RBVM_FORMULA_RESULT or derived canonical result SHA for DERIVED_RISK_RESULT.';

COMMIT;

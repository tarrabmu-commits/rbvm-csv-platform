BEGIN;

-- Decision-input snapshots bind one canonical Finding to one explicit methodology revision at one
-- evaluation time. V17 persists selection state/references only; it does not materialize evidence
-- values or derive any decision, score, priority, treatment, SLA, or Case roll-up.
ALTER TABLE rbvm.decision_methodology_policy
    ADD CONSTRAINT decision_methodology_snapshot_identity
    UNIQUE (tenant_id, id, revision, policy_sha256);

CREATE TABLE rbvm.decision_input_snapshot (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    finding_id uuid NOT NULL,
    methodology_policy_id uuid NOT NULL,
    methodology_revision integer NOT NULL CHECK (methodology_revision > 0),
    methodology_policy_sha256 char(64) NOT NULL CHECK (
        methodology_policy_sha256 ~ '^[a-f0-9]{64}$'
    ),
    contract_id text NOT NULL CHECK (contract_id = 'RBVM_DECISION_INPUT_SNAPSHOT_V1'),
    semantics text NOT NULL CHECK (
        semantics = 'FINDING_SCOPED_POLICY_BOUND_EVIDENCE_REFERENCE_SNAPSHOT'
    ),
    snapshot_sha256 char(64) NOT NULL CHECK (snapshot_sha256 ~ '^[a-f0-9]{64}$'),
    canonical_payload_format text NOT NULL CHECK (
        canonical_payload_format = 'RBVM_DECISION_INPUT_SNAPSHOT_CANONICAL_BINARY_V1'
    ),
    canonical_payload bytea NOT NULL CHECK (octet_length(canonical_payload) > 0),
    evaluated_at timestamptz NOT NULL,
    persisted_at timestamptz NOT NULL,
    UNIQUE (tenant_id, id),
    CONSTRAINT decision_input_one_evaluation
        UNIQUE (tenant_id, finding_id, methodology_policy_id, evaluated_at),
    CONSTRAINT decision_input_one_snapshot_content
        UNIQUE (tenant_id, snapshot_sha256),
    FOREIGN KEY (tenant_id) REFERENCES rbvm.tenant(id),
    FOREIGN KEY (tenant_id, finding_id) REFERENCES rbvm.exposure(tenant_id, id),
    FOREIGN KEY (
        tenant_id,
        methodology_policy_id,
        methodology_revision,
        methodology_policy_sha256
    ) REFERENCES rbvm.decision_methodology_policy(
        tenant_id,
        id,
        revision,
        policy_sha256
    )
);

CREATE INDEX decision_input_snapshot_lookup_idx
    ON rbvm.decision_input_snapshot (
        tenant_id,
        finding_id,
        methodology_revision,
        evaluated_at DESC
    );

CREATE TABLE rbvm.decision_input_dimension (
    tenant_id uuid NOT NULL,
    snapshot_id uuid NOT NULL,
    evidence_dimension text NOT NULL CHECK (
        evidence_dimension IN (
            'APPLICABILITY',
            'TECHNICAL_SEVERITY',
            'KNOWN_EXPLOITATION',
            'EXPLOITATION_PROBABILITY',
            'ASSET_CONTEXT',
            'NETWORK_REACHABILITY',
            'BUSINESS_MISSION_IMPACT'
        )
    ),
    dimension_state text NOT NULL CHECK (
        dimension_state IN ('PRESENT', 'MISSING', 'AMBIGUOUS', 'STALE')
    ),
    PRIMARY KEY (tenant_id, snapshot_id, evidence_dimension),
    FOREIGN KEY (tenant_id, snapshot_id)
        REFERENCES rbvm.decision_input_snapshot(tenant_id, id)
);

CREATE TABLE rbvm.decision_input_evidence_reference (
    tenant_id uuid NOT NULL,
    snapshot_id uuid NOT NULL,
    evidence_dimension text NOT NULL,
    evidence_id uuid NOT NULL,
    evidence_sha256 char(64) NOT NULL CHECK (evidence_sha256 ~ '^[a-f0-9]{64}$'),
    evidence_source text NOT NULL CHECK (length(trim(evidence_source)) > 0),
    observed_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, snapshot_id, evidence_dimension, evidence_id),
    FOREIGN KEY (tenant_id, snapshot_id, evidence_dimension)
        REFERENCES rbvm.decision_input_dimension(tenant_id, snapshot_id, evidence_dimension)
);

COMMENT ON TABLE rbvm.decision_input_snapshot IS
    'Immutable Finding-scoped, methodology-bound decision-input provenance. Contains evidence selection state only and no RBVM formula output.';
COMMENT ON TABLE rbvm.decision_input_dimension IS
    'Exactly one PRESENT|MISSING|AMBIGUOUS|STALE classification per evidence dimension. Application persistence validates all seven dimensions and state/reference cardinality.';
COMMENT ON TABLE rbvm.decision_input_evidence_reference IS
    'Immutable pointers to native evidence UUIDs with evidence-row SHA/source/time. Evidence values remain in native tables and no cross-dimension winner is inferred.';

COMMIT;

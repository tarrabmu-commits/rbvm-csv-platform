BEGIN;

-- RBVM decision methodology policies are immutable configuration provenance, not vulnerability
-- evidence and not decisions. V16 deliberately has no "current" or "active" policy view: choosing
-- a policy revision is an explicit later control-plane action rather than max(revision) inference.
CREATE TABLE rbvm.decision_methodology_policy (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    contract_id text NOT NULL CHECK (contract_id = 'RBVM_DECISION_METHODOLOGY_V1'),
    semantics text NOT NULL CHECK (
        semantics = 'FINDING_SCOPED_EXPLICIT_EVIDENCE_SELECTION_POLICY'
    ),
    revision integer NOT NULL CHECK (revision > 0),
    policy_sha256 char(64) NOT NULL CHECK (policy_sha256 ~ '^[a-f0-9]{64}$'),
    canonical_payload_format text NOT NULL CHECK (
        canonical_payload_format = 'RBVM_DECISION_METHODOLOGY_CANONICAL_BINARY_V1'
    ),
    canonical_payload bytea NOT NULL CHECK (octet_length(canonical_payload) > 0),
    subject_scope text NOT NULL CHECK (subject_scope = 'FINDING'),
    missing_evidence_handling text NOT NULL CHECK (
        missing_evidence_handling = 'PRESERVE_UNKNOWN'
    ),
    ambiguity_handling text NOT NULL CHECK (
        ambiguity_handling = 'PRESERVE_AMBIGUOUS'
    ),
    legacy_priority_handling text NOT NULL CHECK (
        legacy_priority_handling = 'EXCLUDE_LEGACY_PRIORITY_TIER'
    ),
    installed_at timestamptz NOT NULL,
    UNIQUE (tenant_id, id),
    CONSTRAINT decision_methodology_one_revision
        UNIQUE (tenant_id, contract_id, revision),
    CONSTRAINT decision_methodology_one_content
        UNIQUE (tenant_id, contract_id, policy_sha256),
    FOREIGN KEY (tenant_id) REFERENCES rbvm.tenant(id)
);

CREATE INDEX decision_methodology_policy_lookup_idx
    ON rbvm.decision_methodology_policy (tenant_id, contract_id, revision);

CREATE TABLE rbvm.decision_methodology_evidence_policy (
    tenant_id uuid NOT NULL,
    methodology_policy_id uuid NOT NULL,
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
    source_selection_mode text NOT NULL CHECK (
        source_selection_mode IN ('ALL_SOURCES', 'EXPLICIT_ALLOWLIST')
    ),
    freshness_mode text NOT NULL CHECK (
        freshness_mode IN ('NO_AGE_LIMIT', 'MAX_AGE_SECONDS')
    ),
    maximum_age_seconds bigint,
    PRIMARY KEY (tenant_id, methodology_policy_id, evidence_dimension),
    CONSTRAINT decision_methodology_freshness_check CHECK (
        (freshness_mode = 'NO_AGE_LIMIT' AND maximum_age_seconds IS NULL) OR
        (freshness_mode = 'MAX_AGE_SECONDS'
            AND maximum_age_seconds IS NOT NULL AND maximum_age_seconds > 0)
    ),
    FOREIGN KEY (tenant_id, methodology_policy_id)
        REFERENCES rbvm.decision_methodology_policy(tenant_id, id)
);

CREATE TABLE rbvm.decision_methodology_source_allowlist (
    tenant_id uuid NOT NULL,
    methodology_policy_id uuid NOT NULL,
    evidence_dimension text NOT NULL,
    source_identifier text NOT NULL CHECK (length(trim(source_identifier)) > 0),
    PRIMARY KEY (
        tenant_id,
        methodology_policy_id,
        evidence_dimension,
        source_identifier
    ),
    FOREIGN KEY (tenant_id, methodology_policy_id, evidence_dimension)
        REFERENCES rbvm.decision_methodology_evidence_policy(
            tenant_id,
            methodology_policy_id,
            evidence_dimension
        )
);

COMMENT ON TABLE rbvm.decision_methodology_policy IS
    'Immutable tenant-scoped RBVM methodology policy registry with canonical non-self-referential SHA-256 provenance. No policy is implicitly active.';
COMMENT ON TABLE rbvm.decision_methodology_evidence_policy IS
    'Explicit per-dimension source-selection and freshness eligibility rules. Contains no weights, scores, priority, SLA, thresholds, multipliers, or source precedence.';
COMMENT ON TABLE rbvm.decision_methodology_source_allowlist IS
    'Exact admissible source identifiers for EXPLICIT_ALLOWLIST selection. Row order carries no precedence semantic.';

COMMIT;

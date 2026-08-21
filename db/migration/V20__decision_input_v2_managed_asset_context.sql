BEGIN;

-- V22 evolves Decision Input references so exact resolution remains unambiguous when
-- ASSET_CONTEXT can reference either V13 native evidence or a linked managed-asset revision.
-- Historical V1 snapshots remain byte-for-byte canonical; this migration only adds typed
-- persistence metadata and permits the V2 contract for new snapshots.

ALTER TABLE rbvm.decision_input_snapshot
    DROP CONSTRAINT IF EXISTS decision_input_snapshot_contract_id_check,
    DROP CONSTRAINT IF EXISTS decision_input_snapshot_semantics_check,
    DROP CONSTRAINT IF EXISTS decision_input_snapshot_canonical_payload_format_check;

ALTER TABLE rbvm.decision_input_snapshot
    ADD CONSTRAINT decision_input_snapshot_contract_id_check CHECK (
        contract_id IN (
            'RBVM_DECISION_INPUT_SNAPSHOT_V1',
            'RBVM_DECISION_INPUT_SNAPSHOT_V2'
        )
    ),
    ADD CONSTRAINT decision_input_snapshot_semantics_check CHECK (
        semantics IN (
            'FINDING_SCOPED_POLICY_BOUND_EVIDENCE_REFERENCE_SNAPSHOT',
            'FINDING_SCOPED_POLICY_BOUND_TYPED_EVIDENCE_REFERENCE_SNAPSHOT'
        )
    ),
    ADD CONSTRAINT decision_input_snapshot_canonical_payload_format_check CHECK (
        canonical_payload_format IN (
            'RBVM_DECISION_INPUT_SNAPSHOT_CANONICAL_BINARY_V1',
            'RBVM_DECISION_INPUT_SNAPSHOT_CANONICAL_BINARY_V2'
        )
    ),
    ADD CONSTRAINT decision_input_snapshot_contract_tuple_check CHECK (
        (
            contract_id = 'RBVM_DECISION_INPUT_SNAPSHOT_V1'
            AND semantics = 'FINDING_SCOPED_POLICY_BOUND_EVIDENCE_REFERENCE_SNAPSHOT'
            AND canonical_payload_format =
                'RBVM_DECISION_INPUT_SNAPSHOT_CANONICAL_BINARY_V1'
        )
        OR
        (
            contract_id = 'RBVM_DECISION_INPUT_SNAPSHOT_V2'
            AND semantics =
                'FINDING_SCOPED_POLICY_BOUND_TYPED_EVIDENCE_REFERENCE_SNAPSHOT'
            AND canonical_payload_format =
                'RBVM_DECISION_INPUT_SNAPSHOT_CANONICAL_BINARY_V2'
        )
    );

ALTER TABLE rbvm.decision_input_evidence_reference
    ADD COLUMN native_evidence_kind text,
    ADD COLUMN binding_kind text,
    ADD COLUMN binding_id uuid,
    ADD COLUMN binding_sha256 char(64),
    ADD COLUMN binding_source text,
    ADD COLUMN binding_observed_at timestamptz;

UPDATE rbvm.decision_input_evidence_reference
SET native_evidence_kind = CASE evidence_dimension
    WHEN 'APPLICABILITY' THEN 'APPLICABILITY_ASSESSMENT'
    WHEN 'TECHNICAL_SEVERITY' THEN 'CVSS_V31_BASE_EVIDENCE'
    WHEN 'KNOWN_EXPLOITATION' THEN 'CISA_KEV_EVIDENCE'
    WHEN 'EXPLOITATION_PROBABILITY' THEN 'EPSS_EVIDENCE'
    WHEN 'ASSET_CONTEXT' THEN 'ASSET_CONTEXT_EVIDENCE'
    WHEN 'NETWORK_REACHABILITY' THEN 'NETWORK_REACHABILITY_EVIDENCE'
    WHEN 'BUSINESS_MISSION_IMPACT' THEN 'BUSINESS_IMPACT_EVIDENCE'
END;

ALTER TABLE rbvm.decision_input_evidence_reference
    ALTER COLUMN native_evidence_kind SET NOT NULL,
    DROP CONSTRAINT decision_input_evidence_reference_pkey,
    ADD CONSTRAINT decision_input_evidence_reference_pkey PRIMARY KEY (
        tenant_id,
        snapshot_id,
        evidence_dimension,
        native_evidence_kind,
        evidence_id
    ),
    ADD CONSTRAINT decision_input_native_kind_check CHECK (
        (
            evidence_dimension = 'APPLICABILITY'
            AND native_evidence_kind = 'APPLICABILITY_ASSESSMENT'
        )
        OR (
            evidence_dimension = 'TECHNICAL_SEVERITY'
            AND native_evidence_kind = 'CVSS_V31_BASE_EVIDENCE'
        )
        OR (
            evidence_dimension = 'KNOWN_EXPLOITATION'
            AND native_evidence_kind = 'CISA_KEV_EVIDENCE'
        )
        OR (
            evidence_dimension = 'EXPLOITATION_PROBABILITY'
            AND native_evidence_kind = 'EPSS_EVIDENCE'
        )
        OR (
            evidence_dimension = 'ASSET_CONTEXT'
            AND native_evidence_kind IN (
                'ASSET_CONTEXT_EVIDENCE',
                'MANAGED_ASSET_REVISION'
            )
        )
        OR (
            evidence_dimension = 'NETWORK_REACHABILITY'
            AND native_evidence_kind = 'NETWORK_REACHABILITY_EVIDENCE'
        )
        OR (
            evidence_dimension = 'BUSINESS_MISSION_IMPACT'
            AND native_evidence_kind = 'BUSINESS_IMPACT_EVIDENCE'
        )
    ),
    ADD CONSTRAINT decision_input_binding_shape_check CHECK (
        (
            native_evidence_kind <> 'MANAGED_ASSET_REVISION'
            AND binding_kind IS NULL
            AND binding_id IS NULL
            AND binding_sha256 IS NULL
            AND binding_source IS NULL
            AND binding_observed_at IS NULL
        )
        OR (
            native_evidence_kind = 'MANAGED_ASSET_REVISION'
            AND binding_kind = 'SCANNER_MANAGED_ASSET_LINK_EVENT'
            AND binding_id IS NOT NULL
            AND binding_sha256 IS NOT NULL
            AND binding_sha256 ~ '^[a-f0-9]{64}$'
            AND binding_source IS NOT NULL
            AND length(trim(binding_source)) > 0
            AND binding_observed_at IS NOT NULL
        )
    );

COMMENT ON COLUMN rbvm.decision_input_evidence_reference.native_evidence_kind IS
    'V22 typed native store identity. Together with evidence_id it prevents ambiguous cross-table UUID dereference.';
COMMENT ON COLUMN rbvm.decision_input_evidence_reference.binding_id IS
    'For MANAGED_ASSET_REVISION only: exact immutable scanner_managed_asset_link_event UUID authorizing the Finding-to-managed-asset context join.';

COMMIT;

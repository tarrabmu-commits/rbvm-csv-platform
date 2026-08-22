BEGIN;

-- Decision Input V3 makes the exact Finding-specific association event part of provenance
-- for Network Reachability and Business/Mission Impact references. No new data columns are
-- needed: V20 already introduced generic immutable binding metadata. V22 only widens the
-- snapshot contract tuple and the binding-shape constraint while preserving V1/V2 rows.

ALTER TABLE rbvm.decision_input_snapshot
    DROP CONSTRAINT decision_input_snapshot_contract_id_check,
    DROP CONSTRAINT decision_input_snapshot_semantics_check,
    DROP CONSTRAINT decision_input_snapshot_canonical_payload_format_check,
    DROP CONSTRAINT decision_input_snapshot_contract_tuple_check;

ALTER TABLE rbvm.decision_input_snapshot
    ADD CONSTRAINT decision_input_snapshot_contract_id_check CHECK (
        contract_id IN (
            'RBVM_DECISION_INPUT_SNAPSHOT_V1',
            'RBVM_DECISION_INPUT_SNAPSHOT_V2',
            'RBVM_DECISION_INPUT_SNAPSHOT_V3'
        )
    ),
    ADD CONSTRAINT decision_input_snapshot_semantics_check CHECK (
        semantics IN (
            'FINDING_SCOPED_POLICY_BOUND_EVIDENCE_REFERENCE_SNAPSHOT',
            'FINDING_SCOPED_POLICY_BOUND_TYPED_EVIDENCE_REFERENCE_SNAPSHOT',
            'FINDING_SCOPED_POLICY_BOUND_TYPED_ASSOCIATION_PROVENANCE_SNAPSHOT'
        )
    ),
    ADD CONSTRAINT decision_input_snapshot_canonical_payload_format_check CHECK (
        canonical_payload_format IN (
            'RBVM_DECISION_INPUT_SNAPSHOT_CANONICAL_BINARY_V1',
            'RBVM_DECISION_INPUT_SNAPSHOT_CANONICAL_BINARY_V2',
            'RBVM_DECISION_INPUT_SNAPSHOT_CANONICAL_BINARY_V3'
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
        OR
        (
            contract_id = 'RBVM_DECISION_INPUT_SNAPSHOT_V3'
            AND semantics =
                'FINDING_SCOPED_POLICY_BOUND_TYPED_ASSOCIATION_PROVENANCE_SNAPSHOT'
            AND canonical_payload_format =
                'RBVM_DECISION_INPUT_SNAPSHOT_CANONICAL_BINARY_V3'
        )
    );

ALTER TABLE rbvm.decision_input_evidence_reference
    DROP CONSTRAINT decision_input_binding_shape_check;

ALTER TABLE rbvm.decision_input_evidence_reference
    ADD CONSTRAINT decision_input_binding_shape_check CHECK (
        (
            native_evidence_kind IN (
                'APPLICABILITY_ASSESSMENT',
                'CVSS_V31_BASE_EVIDENCE',
                'CISA_KEV_EVIDENCE',
                'EPSS_EVIDENCE',
                'ASSET_CONTEXT_EVIDENCE'
            )
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
        OR (
            native_evidence_kind = 'NETWORK_REACHABILITY_EVIDENCE'
            AND (
                (
                    binding_kind IS NULL
                    AND binding_id IS NULL
                    AND binding_sha256 IS NULL
                    AND binding_source IS NULL
                    AND binding_observed_at IS NULL
                )
                OR (
                    binding_kind = 'FINDING_REACHABILITY_SCOPE_LINK_EVENT'
                    AND binding_id IS NOT NULL
                    AND binding_sha256 IS NOT NULL
                    AND binding_sha256 ~ '^[a-f0-9]{64}$'
                    AND binding_source IS NOT NULL
                    AND length(trim(binding_source)) > 0
                    AND binding_observed_at IS NOT NULL
                )
            )
        )
        OR (
            native_evidence_kind = 'BUSINESS_IMPACT_EVIDENCE'
            AND (
                (
                    binding_kind IS NULL
                    AND binding_id IS NULL
                    AND binding_sha256 IS NULL
                    AND binding_source IS NULL
                    AND binding_observed_at IS NULL
                )
                OR (
                    binding_kind = 'FINDING_BUSINESS_SERVICE_LINK_EVENT'
                    AND binding_id IS NOT NULL
                    AND binding_sha256 IS NOT NULL
                    AND binding_sha256 ~ '^[a-f0-9]{64}$'
                    AND binding_source IS NOT NULL
                    AND length(trim(binding_source)) > 0
                    AND binding_observed_at IS NOT NULL
                )
            )
        )
    );

COMMENT ON CONSTRAINT decision_input_binding_shape_check
    ON rbvm.decision_input_evidence_reference IS
    'V22 permits V3 Finding-specific association provenance while retaining unbound V1/V2 reachability and business-impact references for historical replay.';

COMMIT;

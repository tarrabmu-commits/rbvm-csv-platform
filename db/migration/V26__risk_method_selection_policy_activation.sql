BEGIN;

-- V26 introduces a separate append-only activation stream for immutable Risk Method
-- Selection Policy revisions. Policy revision order does not establish activation order.
-- Only explicit activation_revision orders activation events.
ALTER TABLE rbvm.risk_method_selection_policy
    ADD CONSTRAINT risk_method_selection_policy_exact_identity
    UNIQUE (tenant_id, revision, policy_sha256);

CREATE TABLE rbvm.risk_method_selection_policy_activation_event (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    contract_id text NOT NULL CHECK (
        contract_id = 'RBVM_RISK_METHOD_SELECTION_POLICY_ACTIVATION_EVENT_V1'
    ),
    semantics text NOT NULL CHECK (
        semantics = 'TENANT_SCOPED_EXPLICIT_ACTIVE_POLICY_POINTER_APPEND_ONLY'
    ),
    activation_revision integer NOT NULL CHECK (activation_revision > 0),
    activation_state text NOT NULL CHECK (activation_state IN ('ACTIVE', 'CLEARED')),
    policy_revision integer,
    policy_sha256 char(64),
    event_sha256 char(64) NOT NULL CHECK (event_sha256 ~ '^[a-f0-9]{64}$'),
    canonical_payload_format text NOT NULL CHECK (
        canonical_payload_format =
            'RBVM_RISK_METHOD_SELECTION_POLICY_ACTIVATION_EVENT_CANONICAL_BINARY_V1'
    ),
    canonical_payload bytea NOT NULL CHECK (octet_length(canonical_payload) > 0),
    changed_by text NOT NULL CHECK (length(trim(changed_by)) > 0),
    change_note text NOT NULL DEFAULT '',
    recorded_at timestamptz NOT NULL,
    persisted_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (tenant_id, id),
    CONSTRAINT risk_method_selection_activation_one_revision
        UNIQUE (tenant_id, activation_revision),
    CONSTRAINT risk_method_selection_activation_one_event_sha
        UNIQUE (tenant_id, event_sha256),
    CONSTRAINT risk_method_selection_activation_state_shape CHECK (
        (activation_state = 'ACTIVE'
            AND policy_revision IS NOT NULL
            AND policy_revision > 0
            AND policy_sha256 IS NOT NULL
            AND policy_sha256 ~ '^[a-f0-9]{64}$')
        OR
        (activation_state = 'CLEARED'
            AND policy_revision IS NULL
            AND policy_sha256 IS NULL)
    ),
    FOREIGN KEY (tenant_id, policy_revision, policy_sha256)
        REFERENCES rbvm.risk_method_selection_policy(tenant_id, revision, policy_sha256)
);

CREATE INDEX risk_method_selection_activation_history_idx
    ON rbvm.risk_method_selection_policy_activation_event (
        tenant_id, activation_revision DESC, recorded_at DESC
    );

-- Current means the greatest explicit activation revision. It never means the greatest
-- policy revision, most recently installed policy, or first/last methodology catalog entry.
-- A current CLEARED row is retained so explicit clearing remains distinct from never activated.
CREATE VIEW rbvm.current_risk_method_selection_policy_activation AS
SELECT DISTINCT ON (tenant_id)
    tenant_id,
    id AS activation_event_id,
    contract_id,
    semantics,
    activation_revision,
    activation_state,
    policy_revision,
    policy_sha256,
    event_sha256,
    canonical_payload_format,
    canonical_payload,
    changed_by,
    change_note,
    recorded_at,
    persisted_at
FROM rbvm.risk_method_selection_policy_activation_event
ORDER BY tenant_id, activation_revision DESC;

-- Only an explicit current ACTIVE event produces an active policy. Exact revision+SHA is
-- joined back to the immutable policy; policy revision order has no activation semantics.
CREATE VIEW rbvm.active_risk_method_selection_policy AS
SELECT
    a.tenant_id,
    a.activation_event_id,
    a.activation_revision,
    a.event_sha256 AS activation_event_sha256,
    a.changed_by,
    a.change_note,
    a.recorded_at,
    p.id AS policy_id,
    p.contract_id AS policy_contract_id,
    p.revision AS policy_revision,
    p.policy_sha256,
    p.selection_role,
    p.method_family,
    p.method_id,
    p.method_version,
    p.method_sha256
FROM rbvm.current_risk_method_selection_policy_activation a
JOIN rbvm.risk_method_selection_policy p
  ON p.tenant_id = a.tenant_id
 AND p.revision = a.policy_revision
 AND p.policy_sha256 = a.policy_sha256
WHERE a.activation_state = 'ACTIVE';

COMMENT ON TABLE rbvm.risk_method_selection_policy_activation_event IS
    'Append-only explicit activation/clear decisions for exact immutable Risk Method Selection Policy revision+SHA identities.';
COMMENT ON COLUMN rbvm.risk_method_selection_policy_activation_event.activation_revision IS
    'Explicit activation-event ordering only. It must never be derived from or interpreted as policy revision order.';
COMMENT ON VIEW rbvm.current_risk_method_selection_policy_activation IS
    'Greatest explicit activation revision per tenant, including CLEARED. This view does not choose a policy by policy revision or catalog order.';
COMMENT ON VIEW rbvm.active_risk_method_selection_policy IS
    'Exact policy referenced by the current explicit ACTIVE event; empty after explicit CLEARED or before any activation event.';

COMMIT;

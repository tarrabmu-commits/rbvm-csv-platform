BEGIN;

ALTER TABLE rbvm.vulnerability_case
    ADD COLUMN workflow_version bigint NOT NULL DEFAULT 0 CHECK (workflow_version >= 0),
    ADD COLUMN risk_accepted_until timestamptz,
    ADD COLUMN decision_reason text,
    ADD COLUMN decision_evidence text,
    ADD COLUMN last_workflow_at timestamptz;

CREATE TABLE rbvm.case_audit_event (
    sequence_number bigint PRIMARY KEY CHECK (sequence_number > 0),
    id uuid NOT NULL UNIQUE,
    tenant_id uuid NOT NULL,
    case_id uuid NOT NULL,
    case_version bigint NOT NULL CHECK (case_version > 0),
    idempotency_key text NOT NULL CHECK (length(idempotency_key) BETWEEN 8 AND 128),
    request_sha256 char(64) NOT NULL CHECK (request_sha256 ~ '^[a-f0-9]{64}$'),
    action_type text NOT NULL CHECK (action_type IN (
        'ACCEPT_RISK', 'MARK_FALSE_POSITIVE', 'CLOSE_MANUAL', 'REOPEN', 'COMMENT'
    )),
    from_status text NOT NULL CHECK (from_status IN (
        'OPEN', 'ACCEPTED_RISK', 'FALSE_POSITIVE', 'CLOSED_MANUAL'
    )),
    to_status text NOT NULL CHECK (to_status IN (
        'OPEN', 'ACCEPTED_RISK', 'FALSE_POSITIVE', 'CLOSED_MANUAL'
    )),
    reason text NOT NULL CHECK (length(reason) BETWEEN 1 AND 2000),
    expires_at timestamptz,
    evidence_reference text,
    actor_id text NOT NULL,
    actor_assurance text NOT NULL CHECK (actor_assurance IN (
        'UNAUTHENTICATED_LOCAL', 'AUTHENTICATED', 'SERVICE_ACCOUNT'
    )),
    occurred_at timestamptz NOT NULL,
    UNIQUE (tenant_id, case_id, case_version),
    UNIQUE (tenant_id, case_id, idempotency_key),
    FOREIGN KEY (tenant_id, case_id) REFERENCES rbvm.vulnerability_case(tenant_id, id),
    CHECK (action_type <> 'ACCEPT_RISK' OR expires_at IS NOT NULL),
    CHECK (action_type <> 'ACCEPT_RISK' OR expires_at > occurred_at),
    CHECK (action_type <> 'CLOSE_MANUAL'
        OR (evidence_reference IS NOT NULL AND length(trim(evidence_reference)) > 0)),
    CHECK (action_type <> 'COMMENT' OR from_status = to_status)
);

CREATE INDEX case_audit_event_case_time_idx
    ON rbvm.case_audit_event (tenant_id, case_id, occurred_at DESC);
CREATE INDEX case_risk_acceptance_expiry_idx
    ON rbvm.vulnerability_case (tenant_id, risk_accepted_until)
    WHERE status = 'ACCEPTED_RISK';

CREATE VIEW rbvm.case_workflow_reconciliation AS
SELECT
    c.tenant_id,
    c.id AS case_id,
    c.status,
    c.workflow_version,
    count(e.id) AS audit_event_count,
    COALESCE(max(e.case_version), 0) AS maximum_event_version,
    CASE
        WHEN c.workflow_version = count(e.id)
         AND c.workflow_version = COALESCE(max(e.case_version), 0)
            THEN 'RECONCILED'
        ELSE 'INVALID_EVENT_SEQUENCE'
    END AS reconciliation_state
FROM rbvm.vulnerability_case c
LEFT JOIN rbvm.case_audit_event e
  ON e.tenant_id = c.tenant_id AND e.case_id = c.id
GROUP BY c.tenant_id, c.id, c.status, c.workflow_version;

COMMENT ON TABLE rbvm.case_audit_event IS
    'Append-only decision history. Application roles must not receive UPDATE or DELETE.';
COMMENT ON COLUMN rbvm.case_audit_event.actor_assurance IS
    'UNAUTHENTICATED_LOCAL is explicit until authentication and RBAC are implemented.';
COMMENT ON COLUMN rbvm.vulnerability_case.risk_accepted_until IS
    'Expiry is reported but never silently changes status; expiration requires an audited event.';

COMMIT;

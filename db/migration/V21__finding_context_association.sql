BEGIN;

-- V21 persists explicit, customer-confirmed Finding-specific associations for the two
-- scoped evidence families that cannot safely be inherited from an entire scanner asset.
-- Both streams are append-only; missing history means never assessed, while UNLINKED is
-- an explicit customer decision.
CREATE TABLE rbvm.finding_reachability_scope_link_event (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    finding_id uuid NOT NULL,
    revision integer NOT NULL CHECK (revision > 0),
    link_status text NOT NULL CHECK (link_status IN ('LINKED', 'UNLINKED')),
    origin_scope text NOT NULL CHECK (origin_scope IN (
        'INTERNET', 'EXTERNAL_PARTNER', 'INTERNAL_ENTERPRISE',
        'LOCAL_SEGMENT', 'OTHER', 'UNKNOWN'
    )),
    origin_label_normalized text NOT NULL CHECK (length(trim(origin_label_normalized)) > 0),
    transport_protocol text NOT NULL CHECK (transport_protocol IN (
        'TCP', 'UDP', 'ICMP', 'OTHER', 'UNKNOWN'
    )),
    target_port integer,
    target_port_key integer GENERATED ALWAYS AS (COALESCE(target_port, 0)) STORED,
    link_method text NOT NULL CHECK (link_method = 'CUSTOMER_CONFIRMED'),
    evidence_sha256 char(64) NOT NULL CHECK (evidence_sha256 ~ '^[a-f0-9]{64}$'),
    changed_by text NOT NULL CHECK (length(trim(changed_by)) > 0),
    change_note text NOT NULL DEFAULT '',
    recorded_at timestamptz NOT NULL,
    UNIQUE (tenant_id, id),
    CONSTRAINT finding_reachability_scope_link_port CHECK (
        (transport_protocol IN ('TCP', 'UDP') AND target_port BETWEEN 1 AND 65535)
        OR (transport_protocol = 'ICMP' AND target_port IS NULL)
        OR (transport_protocol IN ('OTHER', 'UNKNOWN')
            AND (target_port IS NULL OR target_port BETWEEN 1 AND 65535))
    ),
    CONSTRAINT finding_reachability_scope_link_one_revision UNIQUE (
        tenant_id, finding_id, origin_scope, origin_label_normalized,
        transport_protocol, target_port_key, revision
    ),
    FOREIGN KEY (tenant_id, finding_id)
        REFERENCES rbvm.exposure(tenant_id, id)
);

CREATE INDEX finding_reachability_scope_link_history_idx
    ON rbvm.finding_reachability_scope_link_event (
        tenant_id, finding_id, origin_scope, origin_label_normalized,
        transport_protocol, target_port_key, revision DESC, recorded_at DESC
    );

-- Latest explicit decision per Finding + stable reachability scope. UNLINKED is retained so
-- it remains distinct from a scope that has never been assessed for the Finding.
CREATE VIEW rbvm.current_finding_reachability_scope_link AS
SELECT DISTINCT ON (
    tenant_id, finding_id, origin_scope, origin_label_normalized,
    transport_protocol, target_port_key
)
    tenant_id,
    id AS link_event_id,
    finding_id,
    revision,
    link_status,
    origin_scope,
    origin_label_normalized,
    transport_protocol,
    target_port,
    link_method,
    evidence_sha256,
    changed_by,
    change_note,
    recorded_at
FROM rbvm.finding_reachability_scope_link_event
ORDER BY
    tenant_id, finding_id, origin_scope, origin_label_normalized,
    transport_protocol, target_port_key, revision DESC;

CREATE VIEW rbvm.active_finding_reachability_scope_link AS
SELECT *
FROM rbvm.current_finding_reachability_scope_link
WHERE link_status = 'LINKED';

CREATE TABLE rbvm.finding_business_service_link_event (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    finding_id uuid NOT NULL,
    revision integer NOT NULL CHECK (revision > 0),
    link_status text NOT NULL CHECK (link_status IN ('LINKED', 'UNLINKED')),
    business_service_normalized text NOT NULL
        CHECK (length(trim(business_service_normalized)) > 0),
    link_method text NOT NULL CHECK (link_method = 'CUSTOMER_CONFIRMED'),
    evidence_sha256 char(64) NOT NULL CHECK (evidence_sha256 ~ '^[a-f0-9]{64}$'),
    changed_by text NOT NULL CHECK (length(trim(changed_by)) > 0),
    change_note text NOT NULL DEFAULT '',
    recorded_at timestamptz NOT NULL,
    UNIQUE (tenant_id, id),
    CONSTRAINT finding_business_service_link_one_revision UNIQUE (
        tenant_id, finding_id, business_service_normalized, revision
    ),
    FOREIGN KEY (tenant_id, finding_id)
        REFERENCES rbvm.exposure(tenant_id, id)
);

CREATE INDEX finding_business_service_link_history_idx
    ON rbvm.finding_business_service_link_event (
        tenant_id, finding_id, business_service_normalized, revision DESC, recorded_at DESC
    );

-- Latest explicit decision per Finding + normalized business service, including UNLINKED.
CREATE VIEW rbvm.current_finding_business_service_link AS
SELECT DISTINCT ON (tenant_id, finding_id, business_service_normalized)
    tenant_id,
    id AS link_event_id,
    finding_id,
    revision,
    link_status,
    business_service_normalized,
    link_method,
    evidence_sha256,
    changed_by,
    change_note,
    recorded_at
FROM rbvm.finding_business_service_link_event
ORDER BY tenant_id, finding_id, business_service_normalized, revision DESC;

CREATE VIEW rbvm.active_finding_business_service_link AS
SELECT *
FROM rbvm.current_finding_business_service_link
WHERE link_status = 'LINKED';

COMMENT ON TABLE rbvm.finding_reachability_scope_link_event IS
    'Append-only customer-confirmed Finding to reachability-scope association events. No asset-wide inheritance or hostname/product/port inference is permitted.';
COMMENT ON TABLE rbvm.finding_business_service_link_event IS
    'Append-only customer-confirmed Finding to normalized business-service association events. No asset-wide business-impact inheritance is permitted.';
COMMENT ON VIEW rbvm.current_finding_reachability_scope_link IS
    'Latest explicit decision per Finding/reachability scope, including UNLINKED so missing history remains distinct.';
COMMENT ON VIEW rbvm.current_finding_business_service_link IS
    'Latest explicit decision per Finding/business-service scope, including UNLINKED so missing history remains distinct.';

COMMIT;

BEGIN;

-- V21 links the existing scanner/source-profile asset identity to the existing
-- customer-managed asset identity. It does not merge or replace either identity.
-- Link state is customer-confirmed only and append-only.
CREATE TABLE rbvm.scanner_managed_asset_link_event (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    scanner_asset_id uuid NOT NULL,
    revision integer NOT NULL CHECK (revision > 0),
    link_status text NOT NULL CHECK (link_status IN ('LINKED', 'UNLINKED')),
    managed_asset_id uuid,
    link_method text NOT NULL CHECK (link_method = 'CUSTOMER_CONFIRMED'),
    evidence_sha256 char(64) NOT NULL CHECK (evidence_sha256 ~ '^[a-f0-9]{64}$'),
    changed_by text NOT NULL CHECK (length(trim(changed_by)) > 0),
    change_note text NOT NULL DEFAULT '',
    recorded_at timestamptz NOT NULL,
    UNIQUE (tenant_id, id),
    CONSTRAINT scanner_managed_asset_link_one_revision
        UNIQUE (tenant_id, scanner_asset_id, revision),
    CONSTRAINT scanner_managed_asset_link_state CHECK (
        (link_status = 'LINKED' AND managed_asset_id IS NOT NULL)
        OR
        (link_status = 'UNLINKED' AND managed_asset_id IS NULL)
    ),
    FOREIGN KEY (tenant_id, scanner_asset_id)
        REFERENCES rbvm.asset(tenant_id, id),
    FOREIGN KEY (tenant_id, managed_asset_id)
        REFERENCES rbvm.managed_asset(tenant_id, id)
);

CREATE INDEX scanner_managed_asset_link_history_idx
    ON rbvm.scanner_managed_asset_link_event (
        tenant_id, scanner_asset_id, revision DESC, recorded_at DESC
    );

-- Latest explicit customer decision per scanner asset. A latest UNLINKED event is
-- preserved here so "explicitly unlinked" remains distinguishable from "never linked".
CREATE VIEW rbvm.current_scanner_managed_asset_link AS
SELECT DISTINCT ON (tenant_id, scanner_asset_id)
    tenant_id,
    id AS link_event_id,
    scanner_asset_id,
    revision,
    link_status,
    managed_asset_id,
    link_method,
    evidence_sha256,
    changed_by,
    change_note,
    recorded_at
FROM rbvm.scanner_managed_asset_link_event
ORDER BY tenant_id, scanner_asset_id, revision DESC;

-- Only current active links. Many scanner identities may point to one managed asset;
-- one scanner identity cannot have more than one current target because its state is
-- represented by one ordered event stream.
CREATE VIEW rbvm.active_scanner_managed_asset_link AS
SELECT *
FROM rbvm.current_scanner_managed_asset_link
WHERE link_status = 'LINKED';

COMMENT ON TABLE rbvm.scanner_managed_asset_link_event IS
    'Append-only explicit customer decisions linking scanner rbvm.asset identity to durable rbvm.managed_asset identity. No hostname/OS/product inference is permitted.';
COMMENT ON COLUMN rbvm.scanner_managed_asset_link_event.link_method IS
    'V21 supports CUSTOMER_CONFIRMED only; link inference is outside this contract.';
COMMENT ON VIEW rbvm.current_scanner_managed_asset_link IS
    'Latest explicit link decision per scanner asset, including UNLINKED, so missing and explicit unlink remain distinct.';
COMMENT ON VIEW rbvm.active_scanner_managed_asset_link IS
    'Current explicit LINKED scanner-to-managed-asset mappings only.';

COMMIT;

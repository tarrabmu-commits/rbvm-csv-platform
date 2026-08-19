# CISA KEV Canonical Safe Handoff

This increment connects the existing `CISA_KEV_CSV_V1` generation path to the platform without creating a second persistence path.

## Trust boundary

The allowed path is:

```text
Official CISA JSON
        |
        v
fetch-cisa-kev-snapshot.py
        |
        v
CISA_KEV_VALIDATED_SNAPSHOT
        |
        v
build-cisa-kev-csv.py
        |
        v
CISA_KEV_CSV_V1
        |
        v
Authenticated HTTP handoff
        |
        v
POST /api/v1/cisa-kev-imports
        |
        v
Existing CISA KEV contract validation
        |
        v
Existing tenant/CVE resolution
        |
        v
Existing transactional PostgreSQL V11 importer
        |
        v
Immutable KEV snapshot/evidence history
```

The forbidden shortcut remains:

```text
CISA collector -> PostgreSQL
```

The acquisition/build layer therefore cannot bypass the canonical CSV validation, tenant/CVE resolution, snapshot conflict detection, replay handling, or append-only persistence rules.

## `scripts/import-cisa-kev.py`

The handoff client sends one already-generated `CISA_KEV_CSV_V1` file to:

```text
POST /api/v1/cisa-kev-imports
```

It requires a platform OPERATOR credential in:

```text
RBVM_KEV_API_KEY
```

The client verifies a successful response is still bound to:

```text
contractId = CISA_KEV_CSV_V1
semantics  = CVE_SCOPED_CISA_KEV_SNAPSHOT_MEMBERSHIP_EVIDENCE
```

It also validates basic response accounting before declaring success:

```text
acceptedRows = insertedEvidence + replayedEvidence + persistenceQuarantinedRows

totalQuarantinedRows = contractQuarantinedRows + persistenceQuarantinedRows
```

This does not replace server-side validation. It is a fail-closed client check that prevents an automation caller from treating a malformed or incompatible HTTP response as a successful canonical import.

## Transport and secret policy

The client follows the same transport boundary used by the CVSS handoff:

- loopback (`127.0.0.1`, `localhost`, `::1`) may use HTTP;
- non-local endpoints must use HTTPS;
- credentials embedded in the API URL are rejected;
- query strings and fragments on the configured API base are rejected;
- bearer credentials are never included in diagnostic output;
- remote HTTP response bodies are not echoed into logs.

The input must be a bounded regular non-symlink file. The default bound is 32 MiB and can be changed with:

```text
RBVM_KEV_MAX_BYTES
```

Successful response bodies are also bounded before JSON parsing.

## Evidence semantics are unchanged

This handoff does not create or reinterpret KEV evidence.

```text
LISTED
```

still means the CVE was present in the validated complete snapshot identified by the row provenance.

```text
NOT_LISTED
```

still means only that the CVE was absent from that complete observed snapshot.

```text
UNKNOWN
```

still means no usable membership evidence is available and remains represented by absence of a persisted KEV evidence row, not by fabrication of an UNKNOWN row.

## Replay and conflict behavior

The client delegates persistence semantics to the existing transactional importer. Therefore retries retain the established rules:

- identical snapshot/evidence submissions replay safely rather than inserting duplicate history;
- conflicting snapshot identity or persisted evidence is quarantined by the canonical importer;
- the handoff never updates or deletes immutable KEV history directly.

## Current boundary

Implemented by this increment:

- authenticated KEV CSV -> HTTP importer handoff;
- remote HTTPS enforcement;
- bounded input and response handling;
- response contract/semantics verification;
- response accounting verification;
- atomic optional import-report writing;
- verification that the client has no direct PostgreSQL/JDBC/psql path.

Not implemented by this increment:

- periodic scheduling;
- automatic CISA snapshot acquisition cadence;
- freshness thresholds;
- EPSS;
- source arbitration;
- risk score;
- remediation priority;
- asset/business context;
- organizational SLA.

The next increment can compose `fetch-cisa-kev-snapshot.py`, `build-cisa-kev-csv.py`, and this handoff client into an atomic scheduled refresh while preserving this canonical boundary.

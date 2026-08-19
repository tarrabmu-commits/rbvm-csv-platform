# EPSS Safe Handoff

This increment connects canonical `EPSS_CSV_V1` evidence to the already-existing authenticated
runtime API without creating a second persistence route.

## Trust boundary

```text
FIRST_EPSS_VALIDATED_SNAPSHOT
        ↓
build-first-epss-csv.py
        ↓
EPSS_CSV_V1
        ↓
import-epss.py
        ↓
POST /api/v1/epss-imports
        ↓
PostgresEpssImporter
        ↓
PostgreSQL V12
```

`import-epss.py` does not fetch FIRST data, open a JDBC/psql connection, or write PostgreSQL.
The platform API remains the only runtime persistence boundary for the generated EPSS CSV.

## Preflight validation

Before the bearer token is sent anywhere, the client requires:

- a regular non-symlink input file within the configured byte bound;
- valid UTF-8 CSV;
- the exact eight `EPSS_CSV_V1` headers in canonical order;
- at least one evidence row;
- canonical CVE identifiers;
- probability and percentile values in `[0,1]`;
- a valid EPSS model version and ISO score date;
- the pinned FIRST daily bulk-feed semantic source;
- timezone-aware observation timestamps;
- a lowercase 64-character source-byte SHA-256.

This is a handoff guard, not an alternate source parser. The server still runs the canonical Java
`EPSS_CSV_V1` analyzer and the transactional PostgreSQL importer.

## Transport and secret handling

The client reads the bearer token only from:

```text
RBVM_EPSS_API_KEY
```

The API origin defaults to local loopback and may be overridden with `--api-base` or
`RBVM_API_BASE_URL`. Plain HTTP is permitted only for loopback hosts. Remote origins must use
HTTPS, and the API-base URL may not contain embedded credentials, a query, a fragment, or an
application path.

Remote error bodies are not echoed into operator/scheduler logs. Import responses are bounded and
must be valid JSON.

## Response verification

A handoff is considered complete only when the API response proves:

```text
contractId = EPSS_CSV_V1
semantics  = CVE_SCOPED_FIRST_EPSS_PROBABILITY_EVIDENCE
```

and its accounting is internally consistent:

```text
acceptedRows
  = insertedEvidence
  + replayedEvidence
  + persistenceQuarantinedRows

totalQuarantinedRows
  = contractQuarantinedRows
  + persistenceQuarantinedRows
```

The client also validates snapshot/evidence counters as non-negative integers before publishing an
optional atomic JSON report.

## Example

```bash
export RBVM_EPSS_API_KEY="$(cat ~/.config/rbvm/operator.token)"

python3 scripts/import-epss.py \
  /var/lib/rbvm/epss/epss.csv \
  --api-base https://rbvm.example \
  --report /var/lib/rbvm/epss/import-result.json
```

## Methodology boundary

This handoff does not introduce:

- EPSS thresholds;
- priority or risk score;
- CVSS/KEV combination logic;
- asset criticality or reachability weighting;
- business impact;
- organizational SLA;
- automatic scheduling.

Scheduling remains a separate increment so failure/retention/publication semantics can be reviewed
without changing the canonical import boundary.

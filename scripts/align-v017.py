#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def one(path, old, new, label):
    p = ROOT / path
    text = p.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"{label}: expected one anchor, found {count}")
    p.write_text(text.replace(old, new, 1), encoding="utf-8")


def release_metadata():
    p = ROOT / "build.gradle.kts"
    p.write_text(p.read_text().replace('version = "0.16.0-SNAPSHOT"', 'version = "0.17.0-SNAPSHOT"'))
    p = ROOT / "scripts/build-distribution.sh"
    p.write_text(p.read_text().replace("VERSION=0.16.0", "VERSION=0.17.0"))
    p = ROOT / "scripts/verify-reproducible-build.sh"
    p.write_text(p.read_text().replace("VERSION=0.16.0", "VERSION=0.17.0").replace(
        "Implementation-Version: 0.16.0", "Implementation-Version: 0.17.0"))
    for name in (".github/workflows/verify.yml", ".github/workflows/release.yml"):
        p = ROOT / name
        p.write_text(p.read_text().replace("0.16.0", "0.17.0"))


def openapi():
    p = ROOT / "api/openapi.yaml"
    s = p.read_text(encoding="utf-8")
    if s.count("  version: 0.16.0\n") != 1:
        raise RuntimeError("OpenAPI version anchor mismatch")
    s = s.replace("  version: 0.16.0\n", "  version: 0.17.0\n", 1)
    old = """    independent asset-scoped organizational context evidence, explicit case
    decisions, an append-only workflow audit trail, and optional
"""
    new = """    independent asset-scoped organizational context evidence, independent scoped
    network reachability evidence, explicit case decisions, an append-only workflow
    audit trail, and optional
"""
    if old in s:
        s = s.replace(old, new, 1)

    paths = """  /network-reachability-evidence:
    get:
      operationId: listNetworkReachabilityEvidence
      summary: Read current scoped network reachability evidence per source and endpoint
      description: >-
        Returns latest observations independently per evidence source, origin scope/label,
        transport protocol, and endpoint for already-canonical tenant assets. NOT_REACHABLE
        remains scoped negative evidence; missing rows are not converted to NOT_REACHABLE.
        INTERNET + REACHABLE remains technical endpoint evidence and is not an asset-wide
        exposure verdict, Risk Score, priority, or SLA.
      parameters:
        - name: limit
          in: query
          schema: {type: integer, minimum: 1, maximum: 500, default: 100}
        - name: asset
          in: query
          schema: {type: string, maxLength: 160}
        - name: sourceProfile
          in: query
          schema:
            type: string
            maxLength: 128
            pattern: '^[A-Za-z0-9._:-]+$'
        - name: evidenceSource
          in: query
          schema: {type: string, maxLength: 256}
        - name: originScope
          in: query
          schema:
            enum: [INTERNET, EXTERNAL_PARTNER, INTERNAL_ENTERPRISE, LOCAL_SEGMENT, OTHER, UNKNOWN]
        - name: reachabilityStatus
          in: query
          schema:
            enum: [REACHABLE, NOT_REACHABLE, UNKNOWN]
      responses:
        '200':
          description: Current tenant-scoped per-source/origin/endpoint reachability evidence
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/NetworkReachabilityEvidencePage'
        '400': {$ref: '#/components/responses/Problem'}
        '401': {$ref: '#/components/responses/AuthenticationRequired'}
        '429': {$ref: '#/components/responses/RateLimited'}
        '503': {$ref: '#/components/responses/Problem'}
  /network-reachability-imports:
    post:
      operationId: importNetworkReachabilityCsv
      summary: Validate and persist NETWORK_REACHABILITY_CSV_V1 evidence
      description: >-
        Parses origin- and endpoint-scoped connectivity evidence and appends safe rows through
        the transactional PostgreSQL V14 importer. Rows must resolve to existing canonical
        assets; reachability import never creates scanner inventory. Source-snapshot or
        persisted scoped-endpoint conflicts are quarantined rather than overwritten.
      requestBody:
        required: true
        content:
          text/csv:
            schema: {type: string, format: binary}
          application/csv:
            schema: {type: string, format: binary}
          application/octet-stream:
            schema: {type: string, format: binary}
      responses:
        '200':
          description: Network reachability evidence file processed transactionally
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/NetworkReachabilityImportResult'
        '401': {$ref: '#/components/responses/AuthenticationRequired'}
        '403': {$ref: '#/components/responses/InsufficientRole'}
        '413': {$ref: '#/components/responses/Problem'}
        '415': {$ref: '#/components/responses/Problem'}
        '422': {$ref: '#/components/responses/Problem'}
        '429': {$ref: '#/components/responses/RateLimited'}
        '503': {$ref: '#/components/responses/Problem'}
"""
    if "/network-reachability-evidence:" not in s:
        if s.count("  /cases:\n") != 1:
            raise RuntimeError("OpenAPI cases path anchor mismatch")
        s = s.replace("  /cases:\n", paths + "  /cases:\n", 1)

    if "        - networkReachability\n" not in s:
        one_old = """        - epss
        - assetContext
        - storedImports
"""
        one_new = """        - epss
        - assetContext
        - networkReachability
        - storedImports
"""
        if s.count(one_old) != 1:
            raise RuntimeError("OpenAPI Health.required anchor mismatch")
        s = s.replace(one_old, one_new, 1)
    health_old = """        assetContext:
          $ref: '#/components/schemas/AssetContextCapability'
        storedImports:
"""
    health_new = """        assetContext:
          $ref: '#/components/schemas/AssetContextCapability'
        networkReachability:
          $ref: '#/components/schemas/NetworkReachabilityCapability'
        storedImports:
"""
    if "networkReachability:\n          $ref: '#/components/schemas/NetworkReachabilityCapability'" not in s:
        if s.count(health_old) != 1:
            raise RuntimeError("OpenAPI Health property anchor mismatch")
        s = s.replace(health_old, health_new, 1)
    capability = """    NetworkReachabilityCapability:
      type: object
      additionalProperties: false
      required: [importEnabled, evidenceReadEnabled]
      properties:
        importEnabled: {type: boolean}
        evidenceReadEnabled: {type: boolean}
"""
    if "    NetworkReachabilityCapability:\n" not in s:
        if s.count("    CanonicalProjectionHealth:\n") != 1:
            raise RuntimeError("OpenAPI capability schema anchor mismatch")
        s = s.replace("    CanonicalProjectionHealth:\n", capability + "    CanonicalProjectionHealth:\n", 1)

    schemas = """    NetworkReachabilityEvidencePage:
      type: object
      additionalProperties: false
      required: [semantics, limit, assetPrefix, sourceProfileKey, evidenceSource, originScope, reachabilityStatus, count, items]
      properties:
        semantics: {const: CURRENT_PER_SOURCE_SCOPED_NETWORK_REACHABILITY_EVIDENCE}
        limit: {type: integer, minimum: 1, maximum: 500}
        assetPrefix: {type: [string, 'null'], maxLength: 160}
        sourceProfileKey:
          type: [string, 'null']
          maxLength: 128
          pattern: '^[A-Za-z0-9._:-]+$'
        evidenceSource: {type: [string, 'null'], maxLength: 256}
        originScope: {type: [string, 'null']}
        reachabilityStatus: {type: [string, 'null']}
        count: {type: integer, minimum: 0, maximum: 500}
        items:
          type: array
          maxItems: 500
          items: {$ref: '#/components/schemas/NetworkReachabilityEvidenceItem'}
    NetworkReachabilityEvidenceItem:
      type: object
      additionalProperties: false
      required: [sourceProfileKey, assetIdentityBasis, assetName, assetSourceId, originScope, originLabel, transportProtocol, targetPort, targetService, reachabilityStatus, reachabilityMethod, evidenceSource, evidenceSourceSha256, evidenceObservedAt, evidenceIngestedAt, snapshotIngestedAt]
      properties:
        sourceProfileKey:
          type: string
          minLength: 1
          maxLength: 128
          pattern: '^[A-Za-z0-9._:-]+$'
        assetIdentityBasis: {enum: [SOURCE_NAME_ONLY, SOURCE_STABLE_ID]}
        assetName: {type: string, minLength: 1, maxLength: 160}
        assetSourceId: {type: [string, 'null'], maxLength: 160}
        originScope: {enum: [INTERNET, EXTERNAL_PARTNER, INTERNAL_ENTERPRISE, LOCAL_SEGMENT, OTHER, UNKNOWN]}
        originLabel: {type: string, minLength: 1}
        transportProtocol: {enum: [TCP, UDP, ICMP, OTHER, UNKNOWN]}
        targetPort: {type: [integer, 'null'], minimum: 1, maximum: 65535}
        targetService: {type: string, minLength: 1}
        reachabilityStatus: {enum: [REACHABLE, NOT_REACHABLE, UNKNOWN]}
        reachabilityMethod: {enum: [ACTIVE_PROBE, CONTROL_PLANE, FIREWALL_POLICY, CLOUD_CONFIGURATION, PASSIVE_OBSERVATION, OTHER, UNKNOWN]}
        evidenceSource: {type: string, minLength: 1, maxLength: 256}
        evidenceSourceSha256: {type: string, pattern: '^[a-f0-9]{64}$'}
        evidenceObservedAt: {type: string, format: date-time}
        evidenceIngestedAt: {type: string, format: date-time}
        snapshotIngestedAt: {type: string, format: date-time}
    NetworkReachabilityImportResult:
      type: object
      additionalProperties: false
      required: [contractId, semantics, logicalRows, acceptedRows, insertedSnapshots, replayedSnapshots, snapshotConflictGroups, insertedEvidence, replayedEvidence, contractDeduplicatedRows, persistenceQuarantinedRows, contractQuarantinedRows, totalDeduplicatedRows, totalQuarantinedRows, originScopeDistribution, protocolDistribution, reachabilityStatusDistribution, reachabilityMethodDistribution, contractIssues, persistenceIssues]
      properties:
        contractId: {const: NETWORK_REACHABILITY_CSV_V1}
        semantics: {const: ASSET_ENDPOINT_ORIGIN_SCOPED_NETWORK_REACHABILITY_EVIDENCE}
        logicalRows: {type: integer, format: int64, minimum: 0}
        acceptedRows: {type: integer, format: int64, minimum: 0}
        insertedSnapshots: {type: integer, format: int64, minimum: 0}
        replayedSnapshots: {type: integer, format: int64, minimum: 0}
        snapshotConflictGroups: {type: integer, format: int64, minimum: 0}
        insertedEvidence: {type: integer, format: int64, minimum: 0}
        replayedEvidence: {type: integer, format: int64, minimum: 0}
        contractDeduplicatedRows: {type: integer, format: int64, minimum: 0}
        persistenceQuarantinedRows: {type: integer, format: int64, minimum: 0}
        contractQuarantinedRows: {type: integer, format: int64, minimum: 0}
        totalDeduplicatedRows: {type: integer, format: int64, minimum: 0}
        totalQuarantinedRows: {type: integer, format: int64, minimum: 0}
        originScopeDistribution: {$ref: '#/components/schemas/NetworkReachabilityOriginScopeDistribution'}
        protocolDistribution: {$ref: '#/components/schemas/NetworkReachabilityProtocolDistribution'}
        reachabilityStatusDistribution: {$ref: '#/components/schemas/NetworkReachabilityStatusDistribution'}
        reachabilityMethodDistribution: {$ref: '#/components/schemas/NetworkReachabilityMethodDistribution'}
        contractIssues:
          type: array
          maxItems: 100
          items: {$ref: '#/components/schemas/NetworkReachabilityIssue'}
        persistenceIssues:
          type: array
          maxItems: 100
          items: {$ref: '#/components/schemas/NetworkReachabilityIssue'}
    NetworkReachabilityOriginScopeDistribution:
      type: object
      additionalProperties: false
      required: [INTERNET, EXTERNAL_PARTNER, INTERNAL_ENTERPRISE, LOCAL_SEGMENT, OTHER, UNKNOWN]
      properties:
        INTERNET: {type: integer, format: int64, minimum: 0}
        EXTERNAL_PARTNER: {type: integer, format: int64, minimum: 0}
        INTERNAL_ENTERPRISE: {type: integer, format: int64, minimum: 0}
        LOCAL_SEGMENT: {type: integer, format: int64, minimum: 0}
        OTHER: {type: integer, format: int64, minimum: 0}
        UNKNOWN: {type: integer, format: int64, minimum: 0}
    NetworkReachabilityProtocolDistribution:
      type: object
      additionalProperties: false
      required: [TCP, UDP, ICMP, OTHER, UNKNOWN]
      properties:
        TCP: {type: integer, format: int64, minimum: 0}
        UDP: {type: integer, format: int64, minimum: 0}
        ICMP: {type: integer, format: int64, minimum: 0}
        OTHER: {type: integer, format: int64, minimum: 0}
        UNKNOWN: {type: integer, format: int64, minimum: 0}
    NetworkReachabilityStatusDistribution:
      type: object
      additionalProperties: false
      required: [REACHABLE, NOT_REACHABLE, UNKNOWN]
      properties:
        REACHABLE: {type: integer, format: int64, minimum: 0}
        NOT_REACHABLE: {type: integer, format: int64, minimum: 0}
        UNKNOWN: {type: integer, format: int64, minimum: 0}
    NetworkReachabilityMethodDistribution:
      type: object
      additionalProperties: false
      required: [ACTIVE_PROBE, CONTROL_PLANE, FIREWALL_POLICY, CLOUD_CONFIGURATION, PASSIVE_OBSERVATION, OTHER, UNKNOWN]
      properties:
        ACTIVE_PROBE: {type: integer, format: int64, minimum: 0}
        CONTROL_PLANE: {type: integer, format: int64, minimum: 0}
        FIREWALL_POLICY: {type: integer, format: int64, minimum: 0}
        CLOUD_CONFIGURATION: {type: integer, format: int64, minimum: 0}
        PASSIVE_OBSERVATION: {type: integer, format: int64, minimum: 0}
        OTHER: {type: integer, format: int64, minimum: 0}
        UNKNOWN: {type: integer, format: int64, minimum: 0}
    NetworkReachabilityIssue:
      type: object
      additionalProperties: false
      required: [rowNumber, level, code, message]
      properties:
        rowNumber: {type: integer, format: int64, minimum: 1}
        level: {enum: [WARNING, ERROR]}
        code: {type: string}
        message: {type: string}
"""
    if "    NetworkReachabilityEvidencePage:\n" not in s:
        if s.count("    CaseAuditEvent:\n") != 1:
            raise RuntimeError("OpenAPI schema anchor mismatch")
        s = s.replace("    CaseAuditEvent:\n", schemas + "    CaseAuditEvent:\n", 1)
    p.write_text(s, encoding="utf-8")


def verifier():
    p = ROOT / "scripts/verify-api.py"
    s = p.read_text(encoding="utf-8")
    s = s.replace('document.get("info", {}).get("version") != "0.16.0"',
                  'document.get("info", {}).get("version") != "0.17.0"')
    s = s.replace("OpenAPI info.version must match Increment 16",
                  "OpenAPI info.version must match Increment 17")
    if '"/network-reachability-evidence"' not in s:
        old = '        "/asset-context-imports",\n        "/cases",\n'
        new = ('        "/asset-context-imports",\n'
               '        "/network-reachability-evidence",\n'
               '        "/network-reachability-imports",\n'
               '        "/cases",\n')
        if s.count(old) != 1:
            raise RuntimeError("API verifier path anchor mismatch")
        s = s.replace(old, new, 1)
    anchor = '''    if set(asset_context_capability.get("required", [])) != {
        "importEnabled", "evidenceReadEnabled"
    }:
        raise AssertionError("Asset Context capability schema is incomplete")
'''
    if "Network Reachability capability schema is incomplete" not in s:
        if s.count(anchor) != 1:
            raise RuntimeError("API verifier capability anchor mismatch")
        s = s.replace(anchor, anchor + '''
    if "networkReachability" not in health_required:
        raise AssertionError("Health schema must expose Network Reachability runtime capability")
    reachability_capability = schemas.get("NetworkReachabilityCapability", {})
    if set(reachability_capability.get("required", [])) != {
        "importEnabled", "evidenceReadEnabled"
    }:
        raise AssertionError("Network Reachability capability schema is incomplete")
''', 1)
    marker = '    applicability = schemas.get("ApplicabilityImportResult", {})\n'
    block = '''    reachability_import = schemas.get("NetworkReachabilityImportResult", {})
    required_reachability_import_fields = {
        "insertedSnapshots", "replayedSnapshots", "snapshotConflictGroups",
        "insertedEvidence", "replayedEvidence", "persistenceQuarantinedRows",
        "contractQuarantinedRows", "totalQuarantinedRows", "originScopeDistribution",
        "protocolDistribution", "reachabilityStatusDistribution", "reachabilityMethodDistribution",
    }
    if not required_reachability_import_fields.issubset(set(reachability_import.get("required", []))):
        raise AssertionError("Network Reachability import result schema is incomplete")
    reachability_import_properties = reachability_import.get("properties", {})
    if reachability_import_properties.get("contractId", {}).get("const") != "NETWORK_REACHABILITY_CSV_V1":
        raise AssertionError("Network Reachability import result must bind to NETWORK_REACHABILITY_CSV_V1")
    if reachability_import_properties.get("semantics", {}).get("const") != \
            "ASSET_ENDPOINT_ORIGIN_SCOPED_NETWORK_REACHABILITY_EVIDENCE":
        raise AssertionError("Network Reachability import semantics are incorrect")

    reachability_page = schemas.get("NetworkReachabilityEvidencePage", {})
    if reachability_page.get("properties", {}).get("semantics", {}).get("const") != \
            "CURRENT_PER_SOURCE_SCOPED_NETWORK_REACHABILITY_EVIDENCE":
        raise AssertionError("Network Reachability read semantics must remain scoped current-per-source")
    reachability_item = schemas.get("NetworkReachabilityEvidenceItem", {}).get("properties", {})
    if set(reachability_item.get("assetIdentityBasis", {}).get("enum", [])) != {"SOURCE_NAME_ONLY", "SOURCE_STABLE_ID"}:
        raise AssertionError("Network Reachability API must preserve canonical asset identity basis")
    if set(reachability_item.get("originScope", {}).get("enum", [])) != {"INTERNET", "EXTERNAL_PARTNER", "INTERNAL_ENTERPRISE", "LOCAL_SEGMENT", "OTHER", "UNKNOWN"}:
        raise AssertionError("Network Reachability origin vocabulary is incomplete")
    if set(reachability_item.get("transportProtocol", {}).get("enum", [])) != {"TCP", "UDP", "ICMP", "OTHER", "UNKNOWN"}:
        raise AssertionError("Network Reachability protocol vocabulary is incomplete")
    if set(reachability_item.get("reachabilityStatus", {}).get("enum", [])) != {"REACHABLE", "NOT_REACHABLE", "UNKNOWN"}:
        raise AssertionError("Network Reachability status vocabulary is incomplete")
    if set(reachability_item.get("reachabilityMethod", {}).get("enum", [])) != {"ACTIVE_PROBE", "CONTROL_PLANE", "FIREWALL_POLICY", "CLOUD_CONFIGURATION", "PASSIVE_OBSERVATION", "OTHER", "UNKNOWN"}:
        raise AssertionError("Network Reachability method vocabulary is incomplete")
    target_port = reachability_item.get("targetPort", {})
    if target_port.get("minimum") != 1 or target_port.get("maximum") != 65535:
        raise AssertionError("Network Reachability targetPort must preserve 1..65535 bounds")
    if target_port.get("type") != ["integer", "null"]:
        raise AssertionError("Network Reachability targetPort must preserve portless evidence as null")
    if reachability_item.get("evidenceSourceSha256", {}).get("pattern") != "^[a-f0-9]{64}$":
        raise AssertionError("Network Reachability API must expose exact source-artifact SHA-256 provenance")
    for timestamp in ("evidenceObservedAt", "evidenceIngestedAt", "snapshotIngestedAt"):
        if reachability_item.get(timestamp, {}).get("format") != "date-time":
            raise AssertionError(f"Network Reachability API must expose {timestamp} as date-time")
    forbidden_reachability_fields = {
        "internetExposed", "internet_exposed", "riskScore", "priority", "priorityTier",
        "slaDays", "businessCriticality", "criticalityWeight", "cvssBaseScore",
        "epssProbability", "knownExploited", "applicabilityStatus", "attackPathScore"
    }
    if forbidden_reachability_fields.intersection(reachability_item):
        raise AssertionError("Independent Network Reachability evidence must not contain decision fields")

'''
    if 'reachability_import = schemas.get("NetworkReachabilityImportResult"' not in s:
        if s.count(marker) != 1:
            raise RuntimeError("API verifier Reachability insertion anchor mismatch")
        s = s.replace(marker, block + marker, 1)
    p.write_text(s, encoding="utf-8")


def readme():
    p = ROOT / "README.md"
    s = p.read_text(encoding="utf-8")
    s = s.replace("# RBVM CSV Platform — Increment 16", "# RBVM CSV Platform — Increment 17", 1)
    s = s.replace("0.16.0", "0.17.0")
    s = s.replace("V1–V13", "V1–V14")
    asset = "- Asset Context مستقلة عبر `ASSET_CONTEXT_CSV_V1` كدليل تنظيمي على مستوى الـAsset، مع Environment وBusiness Service وOwner وqualitative Business Criticality وsource SHA-256؛ ولا تتحول هذه القيم تلقائياً إلى risk أوpriority.\n"
    reach = "- Network Reachability مستقلة عبر `NETWORK_REACHABILITY_CSV_V1` كدليل تقني scoped حسب origin + endpoint + source + time؛ غياب row لا يعني `NOT_REACHABLE`، و`NOT_REACHABLE` لا يعني global isolation.\n"
    if reach not in s and asset in s:
        s = s.replace(asset, asset + reach, 1)
    s = s.replace(
        "وV13 يحفظ immutable Asset Context snapshots/evidence.",
        "وV13 يحفظ immutable Asset Context snapshots/evidence، وV14 يحفظ immutable scoped Network Reachability snapshots/evidence.",
        1,
    )
    s = s.replace(
        "وAsset Context وقراءة current evidence، مع صفحات تشغيل مستقلة على `/cvss` و`/kev` و`/epss` و`/asset-context`.",
        "وAsset Context وNetwork Reachability وقراءة current evidence، مع صفحات تشغيل مستقلة على `/cvss` و`/kev` و`/epss` و`/asset-context` و`/reachability`.",
        1,
    )
    s = s.replace("current CVSS/KEV/EPSS وAsset Context evidence تبقى per-source",
                  "current CVSS/KEV/EPSS وAsset Context وNetwork Reachability evidence تبقى per-source", 1)
    s = s.replace("OpenAPI 0.17.0 موحّد مع runtime Applicability/CVSS/CISA KEV/EPSS/Asset Context الحالي",
                  "OpenAPI 0.17.0 موحّد مع runtime Applicability/CVSS/CISA KEV/EPSS/Asset Context/Network Reachability الحالي", 1)
    asset_ui = "واجهة Asset Context المستقلة:\n\n```text\nhttp://127.0.0.1:8080/asset-context\n```\n"
    reach_ui = "\nواجهة Network Reachability المستقلة:\n\n```text\nhttp://127.0.0.1:8080/reachability\n```\n"
    if reach_ui.strip() not in s and asset_ui in s:
        s = s.replace(asset_ui, asset_ui + reach_ui, 1)
    v13 = "- [`db/migration/V13__asset_context_persistence.sql`](db/migration/V13__asset_context_persistence.sql)\n"
    v14 = "- [`db/migration/V14__network_reachability_persistence.sql`](db/migration/V14__network_reachability_persistence.sql)\n"
    if v14 not in s and v13 in s:
        s = s.replace(v13, v13 + v14, 1)
    adoc = "- [`docs/ASSET_CONTEXT_PERSISTENCE.md`](docs/ASSET_CONTEXT_PERSISTENCE.md)\n"
    ndocs = "- [`docs/NETWORK_REACHABILITY_CONTRACT.md`](docs/NETWORK_REACHABILITY_CONTRACT.md)\n- [`docs/NETWORK_REACHABILITY_PERSISTENCE.md`](docs/NETWORK_REACHABILITY_PERSISTENCE.md)\n"
    if "docs/NETWORK_REACHABILITY_CONTRACT.md" not in s and adoc in s:
        s = s.replace(adoc, adoc + ndocs, 1)
    api = '''### Network Reachability evidence

استيراد evidence تقنية scoped:

```bash
curl -H "Authorization: Bearer $RBVM_API_KEY" \\
  -H 'Content-Type: text/csv' \\
  --data-binary @network-reachability.csv \\
  http://127.0.0.1:8080/api/v1/network-reachability-imports
```

قراءة current scoped evidence مع filters تشغيلية فقط:

```bash
curl -H "Authorization: Bearer $RBVM_API_KEY" \\
  'http://127.0.0.1:8080/api/v1/network-reachability-evidence?asset=web-&originScope=INTERNET&reachabilityStatus=REACHABLE&limit=100'
```

القراءة لا تشتق `internetExposed` على مستوى asset ولا تختار source winner ولا تحسب Risk/Priority/SLA.

'''
    if "### Network Reachability evidence" not in s and "## API\n" in s:
        s = s.replace("## API\n", "## API\n\n" + api, 1)
    boundary = '''
## حد Network Reachability الحالي

Network Reachability أصبحت evidence كاملة من العقد حتى V14 وAPI/UI، لكنها **ليست RBVM score**.
`NOT_REACHABLE` تبقى scoped negative evidence فقط، وغياب row يبقى absence، و`INTERNET + REACHABLE`
تبقى technical endpoint evidence. لا يوجد في 0.17.0 asset-wide `internetExposed` verdict أو source arbitration
أو attack-path score أو CVSS+KEV+EPSS+Asset+Reachability formula. المرحلة التالية هي Business/Mission
Impact evidence مستقلة، وبعدها فقط methodology القرار والTreatment/SLA.
'''
    if "## حد Network Reachability الحالي" not in s:
        s = s.rstrip() + boundary + "\n"
    p.write_text(s, encoding="utf-8")


def main():
    release_metadata()
    openapi()
    verifier()
    readme()
    print("v0.17.0 Reachability contract alignment applied")


if __name__ == "__main__":
    main()

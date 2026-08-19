#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def replace_once(path: str, old: str, new: str, label: str) -> None:
    p = ROOT / path
    text = p.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"{label}: expected one anchor, found {count}")
    p.write_text(text.replace(old, new, 1), encoding="utf-8")


def release_metadata() -> None:
    for name in (
        "build.gradle.kts",
        "scripts/build-distribution.sh",
        "scripts/verify-reproducible-build.sh",
        ".github/workflows/verify.yml",
        ".github/workflows/release.yml",
    ):
        p = ROOT / name
        text = p.read_text(encoding="utf-8")
        if "0.17.0" not in text:
            raise RuntimeError(f"{name}: expected 0.17.0 after Reachability alignment")
        p.write_text(text.replace("0.17.0", "0.18.0"), encoding="utf-8")


def openapi() -> None:
    p = ROOT / "api/openapi.yaml"
    s = p.read_text(encoding="utf-8")
    if s.count("  version: 0.17.0\n") != 1:
        raise RuntimeError("OpenAPI 0.17.0 version anchor mismatch")
    s = s.replace("  version: 0.17.0\n", "  version: 0.18.0\n", 1)

    old_desc = """    independent asset-scoped organizational context evidence, independent scoped
    network reachability evidence, explicit case decisions, an append-only workflow
    audit trail, and optional
"""
    new_desc = """    independent asset-scoped organizational context evidence, independent scoped
    network reachability evidence, independent qualitative Business/Mission Impact
    evidence, explicit case decisions, an append-only workflow audit trail, and optional
"""
    if s.count(old_desc) != 1:
        raise RuntimeError("OpenAPI description catch-up anchor mismatch")
    s = s.replace(old_desc, new_desc, 1)

    paths = """  /business-impact-evidence:
    get:
      operationId: listBusinessImpactEvidence
      summary: Read current qualitative Business and Mission Impact evidence per source, service, and dimension
      description: >-
        Returns latest source-reported qualitative impact observations independently per
        impact source, normalized Business Service, and impact dimension for already-canonical
        tenant assets. Missing rows remain absence. Impact levels remain source classifications;
        the API does not choose a source winner, derive a numeric weight, aggregate impact score,
        Risk Score, priority, or SLA, or map Asset Context Business Criticality automatically.
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
        - name: businessService
          in: query
          schema: {type: string, maxLength: 256}
        - name: impactSource
          in: query
          schema: {type: string, maxLength: 256}
        - name: impactDimension
          in: query
          schema:
            enum: [AVAILABILITY, INTEGRITY, CONFIDENTIALITY, SAFETY, FINANCIAL, REGULATORY, OPERATIONAL, REPUTATIONAL, MISSION, OTHER, UNKNOWN]
        - name: impactLevel
          in: query
          schema:
            enum: [SEVERE, HIGH, MODERATE, LOW, NEGLIGIBLE, UNKNOWN]
      responses:
        '200':
          description: Current tenant-scoped per-source/service/dimension qualitative impact evidence
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/BusinessImpactEvidencePage'
        '400': {$ref: '#/components/responses/Problem'}
        '401': {$ref: '#/components/responses/AuthenticationRequired'}
        '429': {$ref: '#/components/responses/RateLimited'}
        '503': {$ref: '#/components/responses/Problem'}
  /business-impact-imports:
    post:
      operationId: importBusinessImpactCsv
      summary: Validate and persist BUSINESS_IMPACT_CSV_V1 evidence
      description: >-
        Parses source-reported qualitative Business/Mission Impact evidence and appends safe
        rows through the transactional PostgreSQL V15 importer. Rows must resolve to existing
        canonical assets. Source-snapshot or persisted asset/service/dimension conflicts are
        quarantined rather than overwritten. No numeric impact weighting is introduced.
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
          description: Business/Mission Impact evidence file processed transactionally
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/BusinessImpactImportResult'
        '401': {$ref: '#/components/responses/AuthenticationRequired'}
        '403': {$ref: '#/components/responses/InsufficientRole'}
        '413': {$ref: '#/components/responses/Problem'}
        '415': {$ref: '#/components/responses/Problem'}
        '422': {$ref: '#/components/responses/Problem'}
        '429': {$ref: '#/components/responses/RateLimited'}
        '503': {$ref: '#/components/responses/Problem'}
"""
    if "/business-impact-evidence:" not in s:
        if s.count("  /cases:\n") != 1:
            raise RuntimeError("OpenAPI cases path anchor mismatch")
        s = s.replace("  /cases:\n", paths + "  /cases:\n", 1)

    required_old = """        - assetContext
        - networkReachability
        - storedImports
"""
    required_new = """        - assetContext
        - networkReachability
        - businessImpact
        - storedImports
"""
    if "        - businessImpact\n" not in s:
        if s.count(required_old) != 1:
            raise RuntimeError("OpenAPI Health.required Business Impact anchor mismatch")
        s = s.replace(required_old, required_new, 1)

    health_old = """        networkReachability:
          $ref: '#/components/schemas/NetworkReachabilityCapability'
        storedImports:
"""
    health_new = """        networkReachability:
          $ref: '#/components/schemas/NetworkReachabilityCapability'
        businessImpact:
          $ref: '#/components/schemas/BusinessImpactCapability'
        storedImports:
"""
    if "businessImpact:\n          $ref: '#/components/schemas/BusinessImpactCapability'" not in s:
        if s.count(health_old) != 1:
            raise RuntimeError("OpenAPI Health Business Impact property anchor mismatch")
        s = s.replace(health_old, health_new, 1)

    capability = """    BusinessImpactCapability:
      type: object
      additionalProperties: false
      required: [importEnabled, evidenceReadEnabled]
      properties:
        importEnabled: {type: boolean}
        evidenceReadEnabled: {type: boolean}
"""
    if "    BusinessImpactCapability:\n" not in s:
        if s.count("    CanonicalProjectionHealth:\n") != 1:
            raise RuntimeError("OpenAPI Business Impact capability schema anchor mismatch")
        s = s.replace("    CanonicalProjectionHealth:\n", capability + "    CanonicalProjectionHealth:\n", 1)

    schemas = """    BusinessImpactEvidencePage:
      type: object
      additionalProperties: false
      required: [semantics, limit, assetPrefix, sourceProfileKey, businessService, impactSource, impactDimension, impactLevel, count, items]
      properties:
        semantics: {const: CURRENT_PER_SOURCE_ASSET_SERVICE_BUSINESS_MISSION_IMPACT_EVIDENCE}
        limit: {type: integer, minimum: 1, maximum: 500}
        assetPrefix: {type: [string, 'null'], maxLength: 160}
        sourceProfileKey:
          type: [string, 'null']
          maxLength: 128
          pattern: '^[A-Za-z0-9._:-]+$'
        businessService: {type: [string, 'null'], maxLength: 256}
        impactSource: {type: [string, 'null'], maxLength: 256}
        impactDimension: {type: [string, 'null']}
        impactLevel: {type: [string, 'null']}
        count: {type: integer, minimum: 0, maximum: 500}
        items:
          type: array
          maxItems: 500
          items: {$ref: '#/components/schemas/BusinessImpactEvidenceItem'}
    BusinessImpactEvidenceItem:
      type: object
      additionalProperties: false
      required: [sourceProfileKey, assetIdentityBasis, assetName, assetSourceId, businessService, impactDimension, impactLevel, impactMethod, impactStatement, impactSource, impactSourceSha256, impactObservedAt, evidenceIngestedAt, snapshotIngestedAt]
      properties:
        sourceProfileKey:
          type: string
          minLength: 1
          maxLength: 128
          pattern: '^[A-Za-z0-9._:-]+$'
        assetIdentityBasis: {enum: [SOURCE_NAME_ONLY, SOURCE_STABLE_ID]}
        assetName: {type: string, minLength: 1, maxLength: 160}
        assetSourceId: {type: [string, 'null'], maxLength: 160}
        businessService: {type: string, minLength: 1, maxLength: 256}
        impactDimension: {enum: [AVAILABILITY, INTEGRITY, CONFIDENTIALITY, SAFETY, FINANCIAL, REGULATORY, OPERATIONAL, REPUTATIONAL, MISSION, OTHER, UNKNOWN]}
        impactLevel: {enum: [SEVERE, HIGH, MODERATE, LOW, NEGLIGIBLE, UNKNOWN]}
        impactMethod: {enum: [BUSINESS_IMPACT_ANALYSIS, SERVICE_OWNER_ATTESTATION, POLICY_CLASSIFICATION, INCIDENT_ANALYSIS, OTHER, UNKNOWN]}
        impactStatement: {type: string, minLength: 1}
        impactSource: {type: string, minLength: 1, maxLength: 256}
        impactSourceSha256: {type: string, pattern: '^[a-f0-9]{64}$'}
        impactObservedAt: {type: string, format: date-time}
        evidenceIngestedAt: {type: string, format: date-time}
        snapshotIngestedAt: {type: string, format: date-time}
    BusinessImpactImportResult:
      type: object
      additionalProperties: false
      required: [contractId, semantics, logicalRows, acceptedRows, insertedSnapshots, replayedSnapshots, snapshotConflictGroups, insertedEvidence, replayedEvidence, contractDeduplicatedRows, persistenceQuarantinedRows, contractQuarantinedRows, totalDeduplicatedRows, totalQuarantinedRows, impactDimensionDistribution, impactLevelDistribution, impactMethodDistribution, contractIssues, persistenceIssues]
      properties:
        contractId: {const: BUSINESS_IMPACT_CSV_V1}
        semantics: {const: ASSET_SERVICE_SCOPED_BUSINESS_MISSION_IMPACT_EVIDENCE}
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
        impactDimensionDistribution: {$ref: '#/components/schemas/BusinessImpactDimensionDistribution'}
        impactLevelDistribution: {$ref: '#/components/schemas/BusinessImpactLevelDistribution'}
        impactMethodDistribution: {$ref: '#/components/schemas/BusinessImpactMethodDistribution'}
        contractIssues:
          type: array
          maxItems: 100
          items: {$ref: '#/components/schemas/BusinessImpactIssue'}
        persistenceIssues:
          type: array
          maxItems: 100
          items: {$ref: '#/components/schemas/BusinessImpactIssue'}
    BusinessImpactDimensionDistribution:
      type: object
      additionalProperties: false
      required: [AVAILABILITY, INTEGRITY, CONFIDENTIALITY, SAFETY, FINANCIAL, REGULATORY, OPERATIONAL, REPUTATIONAL, MISSION, OTHER, UNKNOWN]
      properties:
        AVAILABILITY: {type: integer, format: int64, minimum: 0}
        INTEGRITY: {type: integer, format: int64, minimum: 0}
        CONFIDENTIALITY: {type: integer, format: int64, minimum: 0}
        SAFETY: {type: integer, format: int64, minimum: 0}
        FINANCIAL: {type: integer, format: int64, minimum: 0}
        REGULATORY: {type: integer, format: int64, minimum: 0}
        OPERATIONAL: {type: integer, format: int64, minimum: 0}
        REPUTATIONAL: {type: integer, format: int64, minimum: 0}
        MISSION: {type: integer, format: int64, minimum: 0}
        OTHER: {type: integer, format: int64, minimum: 0}
        UNKNOWN: {type: integer, format: int64, minimum: 0}
    BusinessImpactLevelDistribution:
      type: object
      additionalProperties: false
      required: [SEVERE, HIGH, MODERATE, LOW, NEGLIGIBLE, UNKNOWN]
      properties:
        SEVERE: {type: integer, format: int64, minimum: 0}
        HIGH: {type: integer, format: int64, minimum: 0}
        MODERATE: {type: integer, format: int64, minimum: 0}
        LOW: {type: integer, format: int64, minimum: 0}
        NEGLIGIBLE: {type: integer, format: int64, minimum: 0}
        UNKNOWN: {type: integer, format: int64, minimum: 0}
    BusinessImpactMethodDistribution:
      type: object
      additionalProperties: false
      required: [BUSINESS_IMPACT_ANALYSIS, SERVICE_OWNER_ATTESTATION, POLICY_CLASSIFICATION, INCIDENT_ANALYSIS, OTHER, UNKNOWN]
      properties:
        BUSINESS_IMPACT_ANALYSIS: {type: integer, format: int64, minimum: 0}
        SERVICE_OWNER_ATTESTATION: {type: integer, format: int64, minimum: 0}
        POLICY_CLASSIFICATION: {type: integer, format: int64, minimum: 0}
        INCIDENT_ANALYSIS: {type: integer, format: int64, minimum: 0}
        OTHER: {type: integer, format: int64, minimum: 0}
        UNKNOWN: {type: integer, format: int64, minimum: 0}
    BusinessImpactIssue:
      type: object
      additionalProperties: false
      required: [rowNumber, level, code, message]
      properties:
        rowNumber: {type: integer, format: int64, minimum: 1}
        level: {enum: [WARNING, ERROR]}
        code: {type: string}
        message: {type: string}
"""
    if "    BusinessImpactEvidencePage:\n" not in s:
        if s.count("    CaseAuditEvent:\n") != 1:
            raise RuntimeError("OpenAPI Business Impact schema anchor mismatch")
        s = s.replace("    CaseAuditEvent:\n", schemas + "    CaseAuditEvent:\n", 1)

    p.write_text(s, encoding="utf-8")


def verifier() -> None:
    p = ROOT / "scripts/verify-api.py"
    s = p.read_text(encoding="utf-8")
    if 'document.get("info", {}).get("version") != "0.17.0"' not in s:
        raise RuntimeError("API verifier 0.17.0 version anchor missing")
    s = s.replace(
        'document.get("info", {}).get("version") != "0.17.0"',
        'document.get("info", {}).get("version") != "0.18.0"',
        1,
    )
    s = s.replace("OpenAPI info.version must match Increment 17", "OpenAPI info.version must match Increment 18", 1)

    path_old = '        "/network-reachability-imports",\n        "/cases",\n'
    path_new = ('        "/network-reachability-imports",\n'
                '        "/business-impact-evidence",\n'
                '        "/business-impact-imports",\n'
                '        "/cases",\n')
    if '"/business-impact-evidence"' not in s:
        if s.count(path_old) != 1:
            raise RuntimeError("API verifier Business Impact path anchor mismatch")
        s = s.replace(path_old, path_new, 1)

    capability_anchor = '''    if set(reachability_capability.get("required", [])) != {
        "importEnabled", "evidenceReadEnabled"
    }:
        raise AssertionError("Network Reachability capability schema is incomplete")
'''
    capability_block = '''
    if "businessImpact" not in health_required:
        raise AssertionError("Health schema must expose Business Impact runtime capability")
    business_impact_capability = schemas.get("BusinessImpactCapability", {})
    if set(business_impact_capability.get("required", [])) != {
        "importEnabled", "evidenceReadEnabled"
    }:
        raise AssertionError("Business Impact capability schema is incomplete")
'''
    if "Business Impact capability schema is incomplete" not in s:
        if s.count(capability_anchor) != 1:
            raise RuntimeError("API verifier Business Impact capability anchor mismatch")
        s = s.replace(capability_anchor, capability_anchor + capability_block, 1)

    marker = '    applicability = schemas.get("ApplicabilityImportResult", {})\n'
    block = '''    business_impact_import = schemas.get("BusinessImpactImportResult", {})
    required_business_impact_import_fields = {
        "insertedSnapshots", "replayedSnapshots", "snapshotConflictGroups",
        "insertedEvidence", "replayedEvidence", "persistenceQuarantinedRows",
        "contractQuarantinedRows", "totalQuarantinedRows", "impactDimensionDistribution",
        "impactLevelDistribution", "impactMethodDistribution",
    }
    if not required_business_impact_import_fields.issubset(set(business_impact_import.get("required", []))):
        raise AssertionError("Business Impact import result schema is incomplete")
    business_impact_import_properties = business_impact_import.get("properties", {})
    if business_impact_import_properties.get("contractId", {}).get("const") != "BUSINESS_IMPACT_CSV_V1":
        raise AssertionError("Business Impact import result must bind to BUSINESS_IMPACT_CSV_V1")
    if business_impact_import_properties.get("semantics", {}).get("const") != \
            "ASSET_SERVICE_SCOPED_BUSINESS_MISSION_IMPACT_EVIDENCE":
        raise AssertionError("Business Impact import semantics are incorrect")

    business_impact_page = schemas.get("BusinessImpactEvidencePage", {})
    if business_impact_page.get("properties", {}).get("semantics", {}).get("const") != \
            "CURRENT_PER_SOURCE_ASSET_SERVICE_BUSINESS_MISSION_IMPACT_EVIDENCE":
        raise AssertionError("Business Impact read semantics must remain current-per-source/service/dimension")
    business_impact_item = schemas.get("BusinessImpactEvidenceItem", {}).get("properties", {})
    if set(business_impact_item.get("assetIdentityBasis", {}).get("enum", [])) != {"SOURCE_NAME_ONLY", "SOURCE_STABLE_ID"}:
        raise AssertionError("Business Impact API must preserve canonical asset identity basis")
    if set(business_impact_item.get("impactDimension", {}).get("enum", [])) != {
        "AVAILABILITY", "INTEGRITY", "CONFIDENTIALITY", "SAFETY", "FINANCIAL",
        "REGULATORY", "OPERATIONAL", "REPUTATIONAL", "MISSION", "OTHER", "UNKNOWN"
    }:
        raise AssertionError("Business Impact dimension vocabulary is incomplete")
    if set(business_impact_item.get("impactLevel", {}).get("enum", [])) != {
        "SEVERE", "HIGH", "MODERATE", "LOW", "NEGLIGIBLE", "UNKNOWN"
    }:
        raise AssertionError("Business Impact qualitative level vocabulary is incomplete")
    if set(business_impact_item.get("impactMethod", {}).get("enum", [])) != {
        "BUSINESS_IMPACT_ANALYSIS", "SERVICE_OWNER_ATTESTATION", "POLICY_CLASSIFICATION",
        "INCIDENT_ANALYSIS", "OTHER", "UNKNOWN"
    }:
        raise AssertionError("Business Impact evidence-method vocabulary is incomplete")
    if business_impact_item.get("impactSourceSha256", {}).get("pattern") != "^[a-f0-9]{64}$":
        raise AssertionError("Business Impact API must expose exact source-artifact SHA-256 provenance")
    for timestamp in ("impactObservedAt", "evidenceIngestedAt", "snapshotIngestedAt"):
        if business_impact_item.get(timestamp, {}).get("format") != "date-time":
            raise AssertionError(f"Business Impact API must expose {timestamp} as date-time")
    forbidden_business_impact_fields = {
        "impactWeight", "numericImpact", "aggregateImpactScore", "monetaryLoss", "lossAmount",
        "riskScore", "priority", "priorityTier", "slaDays", "businessCriticalityWeight",
        "internetExposed", "attackPathScore", "cvssBaseScore", "epssProbability",
        "knownExploited", "applicabilityStatus"
    }
    if forbidden_business_impact_fields.intersection(business_impact_item):
        raise AssertionError("Independent Business Impact evidence must not contain decision fields")

'''
    if 'business_impact_import = schemas.get("BusinessImpactImportResult"' not in s:
        if s.count(marker) != 1:
            raise RuntimeError("API verifier Business Impact insertion anchor mismatch")
        s = s.replace(marker, block + marker, 1)

    p.write_text(s, encoding="utf-8")


def readme() -> None:
    p = ROOT / "README.md"
    s = p.read_text(encoding="utf-8")
    s = s.replace("# RBVM CSV Platform — Increment 17", "# RBVM CSV Platform — Increment 18", 1)
    s = s.replace("0.17.0", "0.18.0")
    s = s.replace("V1–V14", "V1–V15")

    reach = "- Network Reachability مستقلة عبر `NETWORK_REACHABILITY_CSV_V1` كدليل تقني scoped حسب origin + endpoint + source + time؛ غياب row لا يعني `NOT_REACHABLE`، و`NOT_REACHABLE` لا يعني global isolation.\n"
    impact = "- Business/Mission Impact مستقلة عبر `BUSINESS_IMPACT_CSV_V1` كدليل نوعي source-reported على مستوى Asset + Business Service + impact dimension؛ `SEVERE|HIGH|MODERATE|LOW|NEGLIGIBLE|UNKNOWN` تبقى classifications بلا numeric weight.\n"
    if impact not in s:
        if s.count(reach) != 1:
            raise RuntimeError("README Business Impact bullet anchor mismatch")
        s = s.replace(reach, reach + impact, 1)

    s = s.replace(
        "وV14 يحفظ immutable scoped Network Reachability snapshots/evidence.",
        "وV14 يحفظ immutable scoped Network Reachability snapshots/evidence، وV15 يحفظ immutable qualitative Business/Mission Impact snapshots/evidence.",
        1,
    )
    s = s.replace(
        "وAsset Context وNetwork Reachability وقراءة current evidence، مع صفحات تشغيل مستقلة على `/cvss` و`/kev` و`/epss` و`/asset-context` و`/reachability`.",
        "وAsset Context وNetwork Reachability وBusiness/Mission Impact وقراءة current evidence، مع صفحات تشغيل مستقلة على `/cvss` و`/kev` و`/epss` و`/asset-context` و`/reachability` و`/business-impact`.",
        1,
    )
    s = s.replace(
        "current CVSS/KEV/EPSS وAsset Context وNetwork Reachability evidence تبقى per-source",
        "current CVSS/KEV/EPSS وAsset Context وNetwork Reachability وBusiness/Mission Impact evidence تبقى per-source",
        1,
    )
    s = s.replace(
        "Applicability/CVSS/CISA KEV/EPSS/Asset Context/Network Reachability الحالي",
        "Applicability/CVSS/CISA KEV/EPSS/Asset Context/Network Reachability/Business Impact الحالي",
        1,
    )

    reach_ui = "واجهة Network Reachability المستقلة:\n\n```text\nhttp://127.0.0.1:8080/reachability\n```\n"
    impact_ui = "\nواجهة Business/Mission Impact المستقلة:\n\n```text\nhttp://127.0.0.1:8080/business-impact\n```\n"
    if impact_ui.strip() not in s:
        if s.count(reach_ui) != 1:
            raise RuntimeError("README Business Impact UI anchor mismatch")
        s = s.replace(reach_ui, reach_ui + impact_ui, 1)

    v14 = "- [`db/migration/V14__network_reachability_persistence.sql`](db/migration/V14__network_reachability_persistence.sql)\n"
    v15 = "- [`db/migration/V15__business_impact_persistence.sql`](db/migration/V15__business_impact_persistence.sql)\n"
    if v15 not in s and v14 in s:
        s = s.replace(v14, v14 + v15, 1)

    ndocs = "- [`docs/NETWORK_REACHABILITY_PERSISTENCE.md`](docs/NETWORK_REACHABILITY_PERSISTENCE.md)\n"
    bdocs = "- [`docs/BUSINESS_IMPACT_CONTRACT.md`](docs/BUSINESS_IMPACT_CONTRACT.md)\n- [`docs/BUSINESS_IMPACT_PERSISTENCE.md`](docs/BUSINESS_IMPACT_PERSISTENCE.md)\n"
    if "docs/BUSINESS_IMPACT_CONTRACT.md" not in s and ndocs in s:
        s = s.replace(ndocs, ndocs + bdocs, 1)

    api = '''### Business/Mission Impact evidence

استيراد evidence نوعية source-reported:

```bash
curl -H "Authorization: Bearer $RBVM_API_KEY" \\
  -H 'Content-Type: text/csv' \\
  --data-binary @business-impact.csv \\
  http://127.0.0.1:8080/api/v1/business-impact-imports
```

قراءة current evidence مع filters تشغيلية فقط:

```bash
curl -H "Authorization: Bearer $RBVM_API_KEY" \\
  'http://127.0.0.1:8080/api/v1/business-impact-evidence?businessService=checkout&impactDimension=MISSION&impactLevel=SEVERE&limit=100'
```

القراءة لا تختار source winner، ولا تحوّل `Impact_Level` إلى وزن رقمي، ولا تجمع Business Impact مع Asset Context أوReachability أوCVSS/KEV/EPSS إلى Risk/Priority/SLA.

'''
    if "### Business/Mission Impact evidence" not in s:
        network_heading = "### Network Reachability evidence\n"
        if network_heading not in s:
            raise RuntimeError("README API catch-up anchor mismatch")
        s = s.replace(network_heading, api + network_heading, 1)

    old_boundary = '''
## حد Network Reachability الحالي

Network Reachability أصبحت evidence كاملة من العقد حتى V14 وAPI/UI، لكنها **ليست RBVM score**.
`NOT_REACHABLE` تبقى scoped negative evidence فقط، وغياب row يبقى absence، و`INTERNET + REACHABLE`
تبقى technical endpoint evidence. لا يوجد في 0.18.0 asset-wide `internetExposed` verdict أو source arbitration
أو attack-path score أو CVSS+KEV+EPSS+Asset+Reachability formula. المرحلة التالية هي Business/Mission
Impact evidence مستقلة، وبعدها فقط methodology القرار والTreatment/SLA.
'''
    new_boundary = '''
## حد Evidence Foundation الحالي

Network Reachability وBusiness/Mission Impact أصبحتا evidence مستقلتين كاملتين من العقد حتى PostgreSQL وAPI/UI،
لكن **لا توجد بعد RBVM decision formula**. `NOT_REACHABLE` تبقى scoped negative evidence فقط، وغياب reachability
أوimpact row يبقى absence. `Impact_Level` يبقى source-reported qualitative classification ولا يتحول إلى multiplier.
لا يوجد في 0.18.0 source arbitration أوasset-wide `internetExposed` verdict أوaggregate impact score أوattack-path score
أوCVSS+KEV+EPSS+Applicability+Asset Context+Reachability+Business Impact formula. المنهجية والTreatment/SLA طبقة لاحقة صريحة.
'''
    if "## حد Network Reachability الحالي" in s:
        if old_boundary not in s:
            # tolerate whitespace drift by replacing from heading to EOF, because the old transformer appends it last.
            start = s.index("\n## حد Network Reachability الحالي\n")
            s = s[:start] + new_boundary + "\n"
        else:
            s = s.replace(old_boundary, new_boundary, 1)
    elif "## حد Evidence Foundation الحالي" not in s:
        s = s.rstrip() + new_boundary + "\n"

    p.write_text(s, encoding="utf-8")


def main() -> None:
    release_metadata()
    openapi()
    verifier()
    readme()
    print("v0.18.0 Business Impact + Reachability catch-up alignment applied")


if __name__ == "__main__":
    main()

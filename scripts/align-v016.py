#!/usr/bin/env python3
"""One-shot deterministic source transformation for the 0.16.0 contract-alignment branch."""

from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OPENAPI = ROOT / "api/openapi.yaml"
README = ROOT / "README.md"


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"{label}: expected exactly one anchor, found {count}")
    return text.replace(old, new, 1)


def align_openapi() -> None:
    text = OPENAPI.read_text(encoding="utf-8")
    text = replace_once(text, "  version: 0.15.0\n", "  version: 0.16.0\n", "OpenAPI version")
    text = replace_once(
        text,
        "    threat evidence, independent FIRST EPSS exploitation-probability evidence,\n"
        "    explicit case decisions, an append-only workflow audit trail, and optional\n",
        "    threat evidence, independent FIRST EPSS exploitation-probability evidence,\n"
        "    independent asset-scoped organizational context evidence, explicit case\n"
        "    decisions, an append-only workflow audit trail, and optional\n",
        "OpenAPI description",
    )

    asset_paths = """  /asset-context-evidence:
    get:
      operationId: listAssetContextEvidence
      summary: Read current organizational Asset Context evidence per source
      description: >-
        Returns the latest organizational context observation independently for every
        context source attached to an existing tenant asset. Environment, business service,
        owner, and Business Criticality remain source evidence. This API does not select a
        winning context source or derive criticality weights, reachability, risk, priority,
        SLA, CVSS/KEV/EPSS combinations, or business-loss conclusions.
      parameters:
        - name: limit
          in: query
          description: Maximum number of current source-evidence rows to return
          schema:
            type: integer
            minimum: 1
            maximum: 500
            default: 100
        - name: asset
          in: query
          description: Optional case-insensitive prefix for observed asset name or source ID
          schema:
            type: string
            maxLength: 160
        - name: sourceProfile
          in: query
          description: Optional exact source-profile external key
          schema:
            type: string
            maxLength: 128
            pattern: '^[A-Za-z0-9._:-]+$'
        - name: contextSource
          in: query
          description: Optional exact organizational-context source identifier
          schema:
            type: string
            maxLength: 256
      responses:
        '200':
          description: Current tenant-scoped per-source organizational Asset Context evidence
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/AssetContextEvidencePage'
        '400':
          $ref: '#/components/responses/Problem'
        '401':
          $ref: '#/components/responses/AuthenticationRequired'
        '429':
          $ref: '#/components/responses/RateLimited'
        '503':
          $ref: '#/components/responses/Problem'
  /asset-context-imports:
    post:
      operationId: importAssetContextCsv
      summary: Validate and persist ASSET_CONTEXT_CSV_V1 evidence
      description: >-
        Parses asset-scoped organizational context evidence and appends safe rows through
        the transactional PostgreSQL V13 importer. Rows must resolve to existing canonical
        assets; context import never creates scanner assets. Same-observation source-artifact
        conflicts and persisted evidence conflicts are quarantined rather than overwritten.
      requestBody:
        required: true
        content:
          text/csv:
            schema:
              type: string
              format: binary
          application/csv:
            schema:
              type: string
              format: binary
          application/octet-stream:
            schema:
              type: string
              format: binary
      responses:
        '200':
          description: Asset Context evidence file processed transactionally
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/AssetContextImportResult'
        '401':
          $ref: '#/components/responses/AuthenticationRequired'
        '403':
          $ref: '#/components/responses/InsufficientRole'
        '413':
          $ref: '#/components/responses/Problem'
        '415':
          $ref: '#/components/responses/Problem'
        '422':
          $ref: '#/components/responses/Problem'
        '429':
          $ref: '#/components/responses/RateLimited'
        '503':
          $ref: '#/components/responses/Problem'
"""
    text = replace_once(text, "  /cases:\n", asset_paths + "  /cases:\n", "Asset Context paths")

    text = replace_once(
        text,
        "        - cisaKev\n        - epss\n        - storedImports\n",
        "        - cisaKev\n        - epss\n        - assetContext\n        - storedImports\n",
        "Health required capability",
    )
    text = replace_once(
        text,
        "        epss:\n          $ref: '#/components/schemas/EpssCapability'\n        storedImports:\n",
        "        epss:\n          $ref: '#/components/schemas/EpssCapability'\n"
        "        assetContext:\n          $ref: '#/components/schemas/AssetContextCapability'\n"
        "        storedImports:\n",
        "Health Asset Context property",
    )
    capability = """    AssetContextCapability:
      type: object
      additionalProperties: false
      required: [importEnabled, evidenceReadEnabled]
      properties:
        importEnabled:
          type: boolean
        evidenceReadEnabled:
          type: boolean
"""
    text = replace_once(
        text,
        "    CanonicalProjectionHealth:\n",
        capability + "    CanonicalProjectionHealth:\n",
        "Asset Context capability schema",
    )

    asset_schemas = """    AssetContextEvidencePage:
      type: object
      additionalProperties: false
      required:
        - semantics
        - limit
        - assetPrefix
        - sourceProfileKey
        - contextSource
        - count
        - items
      properties:
        semantics:
          const: CURRENT_PER_SOURCE_ASSET_ORGANIZATIONAL_CONTEXT_EVIDENCE
        limit:
          type: integer
          minimum: 1
          maximum: 500
        assetPrefix:
          type: [string, 'null']
          maxLength: 160
        sourceProfileKey:
          type: [string, 'null']
          maxLength: 128
          pattern: '^[A-Za-z0-9._:-]+$'
        contextSource:
          type: [string, 'null']
          maxLength: 256
        count:
          type: integer
          minimum: 0
          maximum: 500
        items:
          type: array
          maxItems: 500
          items:
            $ref: '#/components/schemas/AssetContextEvidenceItem'
    AssetContextEvidenceItem:
      type: object
      additionalProperties: false
      required:
        - sourceProfileKey
        - assetIdentityBasis
        - assetName
        - assetSourceId
        - environment
        - businessService
        - businessOwner
        - businessCriticality
        - contextSource
        - contextSourceSha256
        - contextObservedAt
        - evidenceIngestedAt
        - snapshotIngestedAt
      properties:
        sourceProfileKey:
          type: string
          minLength: 1
          maxLength: 128
          pattern: '^[A-Za-z0-9._:-]+$'
        assetIdentityBasis:
          enum: [SOURCE_NAME_ONLY, SOURCE_STABLE_ID]
        assetName:
          type: string
          minLength: 1
          maxLength: 160
        assetSourceId:
          type: [string, 'null']
          maxLength: 160
        environment:
          enum: [PRODUCTION, PRE_PRODUCTION, DEVELOPMENT, TEST, SANDBOX, DISASTER_RECOVERY, UNKNOWN]
        businessService:
          type: string
          minLength: 1
          maxLength: 256
        businessOwner:
          type: string
          minLength: 1
          maxLength: 256
        businessCriticality:
          enum: [MISSION_CRITICAL, HIGH, MODERATE, LOW, UNKNOWN]
        contextSource:
          type: string
          minLength: 1
          maxLength: 256
        contextSourceSha256:
          type: string
          pattern: '^[a-f0-9]{64}$'
        contextObservedAt:
          type: string
          format: date-time
        evidenceIngestedAt:
          type: string
          format: date-time
        snapshotIngestedAt:
          type: string
          format: date-time
    AssetContextImportResult:
      type: object
      additionalProperties: false
      required:
        - contractId
        - semantics
        - logicalRows
        - acceptedRows
        - insertedSnapshots
        - replayedSnapshots
        - snapshotConflictGroups
        - insertedEvidence
        - replayedEvidence
        - contractDeduplicatedRows
        - persistenceQuarantinedRows
        - contractQuarantinedRows
        - totalDeduplicatedRows
        - totalQuarantinedRows
        - environmentDistribution
        - criticalityDistribution
        - contractIssues
        - persistenceIssues
      properties:
        contractId:
          const: ASSET_CONTEXT_CSV_V1
        semantics:
          const: ASSET_SCOPED_ORGANIZATIONAL_CONTEXT_EVIDENCE
        logicalRows:
          type: integer
          format: int64
          minimum: 0
        acceptedRows:
          type: integer
          format: int64
          minimum: 0
        insertedSnapshots:
          type: integer
          format: int64
          minimum: 0
        replayedSnapshots:
          type: integer
          format: int64
          minimum: 0
        snapshotConflictGroups:
          type: integer
          format: int64
          minimum: 0
        insertedEvidence:
          type: integer
          format: int64
          minimum: 0
        replayedEvidence:
          type: integer
          format: int64
          minimum: 0
        contractDeduplicatedRows:
          type: integer
          format: int64
          minimum: 0
        persistenceQuarantinedRows:
          type: integer
          format: int64
          minimum: 0
        contractQuarantinedRows:
          type: integer
          format: int64
          minimum: 0
        totalDeduplicatedRows:
          type: integer
          format: int64
          minimum: 0
        totalQuarantinedRows:
          type: integer
          format: int64
          minimum: 0
        environmentDistribution:
          $ref: '#/components/schemas/AssetContextEnvironmentDistribution'
        criticalityDistribution:
          $ref: '#/components/schemas/AssetContextCriticalityDistribution'
        contractIssues:
          type: array
          maxItems: 100
          items:
            $ref: '#/components/schemas/AssetContextIssue'
        persistenceIssues:
          type: array
          maxItems: 100
          items:
            $ref: '#/components/schemas/AssetContextIssue'
    AssetContextEnvironmentDistribution:
      type: object
      additionalProperties: false
      required: [PRODUCTION, PRE_PRODUCTION, DEVELOPMENT, TEST, SANDBOX, DISASTER_RECOVERY, UNKNOWN]
      properties:
        PRODUCTION: {type: integer, format: int64, minimum: 0}
        PRE_PRODUCTION: {type: integer, format: int64, minimum: 0}
        DEVELOPMENT: {type: integer, format: int64, minimum: 0}
        TEST: {type: integer, format: int64, minimum: 0}
        SANDBOX: {type: integer, format: int64, minimum: 0}
        DISASTER_RECOVERY: {type: integer, format: int64, minimum: 0}
        UNKNOWN: {type: integer, format: int64, minimum: 0}
    AssetContextCriticalityDistribution:
      type: object
      additionalProperties: false
      required: [MISSION_CRITICAL, HIGH, MODERATE, LOW, UNKNOWN]
      properties:
        MISSION_CRITICAL: {type: integer, format: int64, minimum: 0}
        HIGH: {type: integer, format: int64, minimum: 0}
        MODERATE: {type: integer, format: int64, minimum: 0}
        LOW: {type: integer, format: int64, minimum: 0}
        UNKNOWN: {type: integer, format: int64, minimum: 0}
    AssetContextIssue:
      type: object
      additionalProperties: false
      required: [rowNumber, level, code, message]
      properties:
        rowNumber:
          type: integer
          format: int64
          minimum: 1
        level:
          enum: [WARNING, ERROR]
        code:
          type: string
        message:
          type: string
"""
    text = replace_once(
        text,
        "    CaseAuditEvent:\n",
        asset_schemas + "    CaseAuditEvent:\n",
        "Asset Context schemas",
    )
    OPENAPI.write_text(text, encoding="utf-8")


def align_readme() -> None:
    text = README.read_text(encoding="utf-8")
    text = text.replace("# RBVM CSV Platform — Increment 15", "# RBVM CSV Platform — Increment 16", 1)
    text = text.replace("0.15.0", "0.16.0")
    text = text.replace("v0.15.0", "v0.16.0")

    epss_bullet = "- FIRST EPSS مستقلة عبر `EPSS_CSV_V1` كدليل exploitation probability على مستوى CVE، مع probability وpercentile وmodel version وscore date وsource SHA-256؛ غياب score evidence لا يتحول إلى `0`.\n"
    asset_bullet = "- Asset Context مستقلة عبر `ASSET_CONTEXT_CSV_V1` كدليل تنظيمي على مستوى الـAsset، مع Environment وBusiness Service وOwner وqualitative Business Criticality وsource SHA-256؛ ولا تتحول هذه القيم تلقائياً إلى risk أوpriority.\n"
    if asset_bullet not in text:
        text = replace_once(text, epss_bullet, epss_bullet + asset_bullet, "README Asset Context bullet")

    text = replace_once(
        text,
        "- PostgreSQL V9 يحفظ Applicability history، V10 يحفظ CVSS history، V11 يحفظ CISA KEV snapshot-bound history، وV12 يحفظ EPSS score snapshots وCVE score history.\n",
        "- PostgreSQL V9 يحفظ Applicability history، V10 يحفظ CVSS history، V11 يحفظ CISA KEV snapshot-bound history، V12 يحفظ EPSS score snapshots وCVE score history، وV13 يحفظ immutable Asset Context snapshots/evidence.\n",
        "README persistence versions",
    )
    text = replace_once(
        text,
        "- API مخصصة لاستيراد Applicability وCVSS وKEV وEPSS وقراءة current evidence، مع صفحات تشغيل مستقلة على `/cvss` و`/kev` و`/epss`.\n",
        "- API مخصصة لاستيراد Applicability وCVSS وKEV وEPSS وAsset Context وقراءة current evidence، مع صفحات تشغيل مستقلة على `/cvss` و`/kev` و`/epss` و`/asset-context`.\n",
        "README API surfaces",
    )
    text = replace_once(
        text,
        "- current CVSS/KEV/EPSS evidence تبقى per-source من دون اختيار winner مخفي أوthreshold-to-priority mapping.\n",
        "- current CVSS/KEV/EPSS وAsset Context evidence تبقى per-source من دون اختيار winner مخفي أوthreshold-to-priority mapping؛ Business Criticality تبقى qualitative evidence فقط.\n",
        "README current-source semantics",
    )
    text = text.replace("تسلسل V1–V12", "تسلسل V1–V13")
    text = text.replace(
        "Applicability/CVSS/KEV/EPSS history",
        "Applicability/CVSS/KEV/EPSS/Asset Context history",
    )
    text = text.replace(
        "بقدرات Applicability وCVSS v3.1 وCISA KEV وEPSS",
        "بقدرات Applicability وCVSS v3.1 وCISA KEV وEPSS وAsset Context",
    )
    text = replace_once(
        text,
        "- OpenAPI 0.16.0 موحّد مع runtime Applicability/CVSS/CISA KEV/EPSS الحالي، إضافة إلى migrations واختبارات contract/domain/HTTP.\n",
        "- OpenAPI 0.16.0 موحّد مع runtime Applicability/CVSS/CISA KEV/EPSS/Asset Context الحالي، إضافة إلى migrations واختبارات contract/domain/HTTP.\n",
        "README OpenAPI alignment",
    )

    epss_ui = """واجهة FIRST EPSS المستقلة:

```text
http://127.0.0.1:8080/epss
```
"""
    asset_ui = """
واجهة Asset Context المستقلة:

```text
http://127.0.0.1:8080/asset-context
```
"""
    if asset_ui.strip() not in text:
        text = replace_once(text, epss_ui, epss_ui + asset_ui, "README Asset Context UI")

    migration_anchor = "- [`db/migration/V12__epss_persistence.sql`](db/migration/V12__epss_persistence.sql)\n"
    migration_new = "- [`db/migration/V13__asset_context_persistence.sql`](db/migration/V13__asset_context_persistence.sql)\n"
    if migration_new not in text:
        text = replace_once(text, migration_anchor, migration_anchor + migration_new, "README V13 migration")

    docs_anchor = "- [`docs/EPSS_PERSISTENCE.md`](docs/EPSS_PERSISTENCE.md)\n"
    if docs_anchor in text and "docs/ASSET_CONTEXT_CONTRACT.md" not in text:
        text = replace_once(
            text,
            docs_anchor,
            docs_anchor
            + "- [`docs/ASSET_CONTEXT_CONTRACT.md`](docs/ASSET_CONTEXT_CONTRACT.md)\n"
            + "- [`docs/ASSET_CONTEXT_PERSISTENCE.md`](docs/ASSET_CONTEXT_PERSISTENCE.md)\n",
            "README Asset Context docs",
        )

    scheduled_marker = "## تحديث استخبارات الثغرات المجدول\n"
    epss_section = """## تحديث FIRST EPSS المجدول

المسار الكانوني المستقل لـEPSS مكتمل أيضاً: `scheduled-epss-refresh.sh` يجلب أويعيد تشغيل
لقطة FIRST bulk متحققاً منها، يبني `EPSS_CSV_V1`، ثم يسلّم نفس البايتات إلى
`POST /api/v1/epss-imports` بمفتاح API مخصص. لا يتقدم `latest` إلا بعد نجاح الـAPI import،
وأي فشل fetch/build/handoff يبقي آخر لقطة منشورة سليمة كما هي. وحدتا
`rbvm-epss-refresh.service` و`rbvm-epss-refresh.timer` توفران جدولة يومية مع قفل يمنع
التشغيل المتداخل وretention للقطات المكتملة.

"""
    if "## تحديث FIRST EPSS المجدول" not in text:
        text = replace_once(text, scheduled_marker, epss_section + scheduled_marker, "README EPSS scheduling")

    api_marker = "## API\n"
    asset_api = """### Asset Context evidence

استيراد evidence تنظيمي مستقل:

```bash
curl -H "Authorization: Bearer $RBVM_API_KEY" \\
  -H 'Content-Type: text/csv' \\
  --data-binary @asset-context.csv \\
  http://127.0.0.1:8080/api/v1/asset-context-imports
```

قراءة current evidence per-source مع filters تشغيلية فقط:

```bash
curl -H "Authorization: Bearer $RBVM_API_KEY" \\
  'http://127.0.0.1:8080/api/v1/asset-context-evidence?asset=web-&sourceProfile=wazuh-primary&contextSource=CMDB%20inventory%20export&limit=100'
```

الـimporter لا ينشئ Assets من ملف السياق؛ الصف يجب أن يحل إلى Asset كانونـي موجود. ولا
تقوم القراءة بترجيح Business Criticality أواختيار context-source winner أوحساب Risk/SLA.

"""
    if api_marker in text and "### Asset Context evidence" not in text:
        text = replace_once(text, api_marker, api_marker + "\n" + asset_api, "README Asset Context API")

    boundary = """
## حد Asset Context الحالي

Asset Context أصبحت evidence كاملة من العقد حتى V13 وAPI/UI، لكن **ليست RBVM score**.
لا يوجد في 0.16.0 source arbitration بين أنظمة السياق، ولا internet exposure/reachability،
ولا numeric criticality multiplier، ولا CVSS+KEV+EPSS+asset formula، ولا remediation SLA مشتق.
المرحلة التالية هي Exposure/Reachability evidence مستقلة مع provenance، ثم Business/Mission
Impact، وبعدها فقط يمكن تثبيت methodology القرار بشكل صريح وقابل للتدقيق.
"""
    if "## حد Asset Context الحالي" not in text:
        text = text.rstrip() + "\n" + boundary + "\n"

    README.write_text(text, encoding="utf-8")


def main() -> None:
    align_openapi()
    align_readme()
    print("v0.16.0 source alignment applied")


if __name__ == "__main__":
    main()

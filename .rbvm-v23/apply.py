#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def path(name: str) -> Path:
    return ROOT / name


def replace_exact(file: str, old: str, new: str, count: int = 1) -> None:
    p = path(file)
    text = p.read_text(encoding="utf-8")
    actual = text.count(old)
    if actual != count:
        raise AssertionError(f"{file}: expected {count} occurrence(s), found {actual}: {old[:120]!r}")
    p.write_text(text.replace(old, new), encoding="utf-8")


def append_before(file: str, marker: str, insertion: str) -> None:
    replace_exact(file, marker, insertion + marker)


# Reuse the existing strict flat JSON parser inside the csv package without making it public.
replace_exact(
    "src/main/java/io/rbvm/csv/ManagedAssetApi.java",
    "    private static void requireJsonContentType(String contentType) {",
    "    static void requireJsonContentType(String contentType) {",
)
replace_exact(
    "src/main/java/io/rbvm/csv/ManagedAssetApi.java",
    "    private static Map<String, Object> readJsonObject(InputStream input) throws IOException {",
    "    static Map<String, Object> readJsonObject(InputStream input) throws IOException {",
)

server = "src/main/java/io/rbvm/csv/CsvPlatformServer.java"
replace_exact(
    server,
    "import io.rbvm.asset.ManagedAssetRegistry;\n",
    "import io.rbvm.asset.ManagedAssetRegistry;\nimport io.rbvm.asset.ScannerManagedAssetLinkRegistry;\n",
)
replace_exact(
    server,
    "    private final byte[] managedAssetsUi;\n",
    "    private final byte[] managedAssetsUi;\n    private final byte[] scannerManagedAssetLinksUi;\n",
)
replace_exact(
    server,
    "    private final Optional<ManagedAssetHttpRouter> managedAssetRouter;\n",
    "    private final Optional<ManagedAssetHttpRouter> managedAssetRouter;\n"
    "    private Optional<ScannerManagedAssetLinkHttpRouter> scannerManagedAssetLinkRouter;\n",
)
# Two terminal constructors initialize the capability as unavailable and load the static UI.
replace_exact(
    server,
    "        this.managedAssetRouter = Optional.empty();\n        this.webUi = loadResource(\"/web/index.html\");",
    "        this.managedAssetRouter = Optional.empty();\n"
    "        this.scannerManagedAssetLinkRouter = Optional.empty();\n"
    "        this.webUi = loadResource(\"/web/index.html\");",
    count=1,
)
replace_exact(
    server,
    "        this.managedAssetsUi = loadResource(\"/web/assets.html\");\n        this.server = HttpServer.create",
    "        this.managedAssetsUi = loadResource(\"/web/assets.html\");\n"
    "        this.scannerManagedAssetLinksUi = loadResource(\"/web/asset-links.html\");\n"
    "        this.server = HttpServer.create",
    count=2,
)
replace_exact(
    server,
    "        this.managedAssetRouter = Objects.requireNonNull(\n"
    "                managedAssetRegistry,\n"
    "                \"managedAssetRegistry\"\n"
    "        ).map(ManagedAssetApi::new).map(ManagedAssetHttpRouter::new);\n"
    "        this.webUi = loadResource(\"/web/index.html\");",
    "        this.managedAssetRouter = Objects.requireNonNull(\n"
    "                managedAssetRegistry,\n"
    "                \"managedAssetRegistry\"\n"
    "        ).map(ManagedAssetApi::new).map(ManagedAssetHttpRouter::new);\n"
    "        this.scannerManagedAssetLinkRouter = Optional.empty();\n"
    "        this.webUi = loadResource(\"/web/index.html\");",
)

# Add the V23 overload while preserving every older constructor signature.
constructor_marker = """    public void start() {
        server.start();
    }
"""
v23_constructor = """    /** Runtime constructor through the V23 scanner-managed-asset link API capability. */
    public CsvPlatformServer(
            String host,
            int port,
            Path dataDirectory,
            long maximumUploadBytes,
            CanonicalProjection canonicalProjection,
            DomainCatalog readCatalog,
            Optional<ApplicabilityImporter> applicabilityImporter,
            Optional<ApplicabilityFindingExporter> applicabilityFindingExporter,
            Optional<CvssV31Importer> cvssV31Importer,
            Optional<CvssV31EvidenceReader> cvssV31EvidenceReader,
            Optional<CisaKevImporter> cisaKevImporter,
            Optional<CisaKevEvidenceReader> cisaKevEvidenceReader,
            Optional<EpssImporter> epssImporter,
            Optional<EpssEvidenceReader> epssEvidenceReader,
            Optional<AssetContextImporter> assetContextImporter,
            Optional<AssetContextEvidenceReader> assetContextEvidenceReader,
            Optional<NetworkReachabilityImporter> networkReachabilityImporter,
            Optional<NetworkReachabilityEvidenceReader> networkReachabilityEvidenceReader,
            Optional<BusinessImpactImporter> businessImpactImporter,
            Optional<BusinessImpactEvidenceReader> businessImpactEvidenceReader,
            Optional<ManagedAssetRegistry> managedAssetRegistry,
            Optional<ScannerManagedAssetLinkRegistry> scannerManagedAssetLinkRegistry,
            ApiKeyAuthenticator authenticator,
            RequestRateLimiter rateLimiter
    ) throws IOException {
        this(
                host,
                port,
                dataDirectory,
                maximumUploadBytes,
                canonicalProjection,
                readCatalog,
                applicabilityImporter,
                applicabilityFindingExporter,
                cvssV31Importer,
                cvssV31EvidenceReader,
                cisaKevImporter,
                cisaKevEvidenceReader,
                epssImporter,
                epssEvidenceReader,
                assetContextImporter,
                assetContextEvidenceReader,
                networkReachabilityImporter,
                networkReachabilityEvidenceReader,
                businessImpactImporter,
                businessImpactEvidenceReader,
                managedAssetRegistry,
                authenticator,
                rateLimiter
        );
        this.scannerManagedAssetLinkRouter = Objects.requireNonNull(
                scannerManagedAssetLinkRegistry,
                "scannerManagedAssetLinkRegistry"
        ).map(ScannerManagedAssetLinkApi::new).map(ScannerManagedAssetLinkHttpRouter::new);
    }

"""
append_before(server, constructor_marker, v23_constructor)

replace_exact(
    server,
    "            if (\"/assets\".equals(path) || \"/assets/\".equals(path)) {\n"
    "                requireMethod(exchange, method, \"GET\");\n"
    "                sendBytes(exchange, 200, \"text/html; charset=utf-8\", managedAssetsUi);\n"
    "                return;\n"
    "            }\n",
    "            if (\"/assets\".equals(path) || \"/assets/\".equals(path)) {\n"
    "                requireMethod(exchange, method, \"GET\");\n"
    "                sendBytes(exchange, 200, \"text/html; charset=utf-8\", managedAssetsUi);\n"
    "                return;\n"
    "            }\n"
    "            if (\"/asset-links\".equals(path) || \"/asset-links/\".equals(path)) {\n"
    "                requireMethod(exchange, method, \"GET\");\n"
    "                sendBytes(exchange, 200, \"text/html; charset=utf-8\", scannerManagedAssetLinksUi);\n"
    "                return;\n"
    "            }\n",
)

managed_namespace = """            if (ManagedAssetHttpRouter.inNamespace(path)) {
                if (!ManagedAssetHttpRouter.handles(path)) {
                    throw new HttpProblem(
                            404,
                            "NOT_FOUND",
                            "The requested managed asset route does not exist"
                    );
                }
                ApiRole requiredRole = ManagedAssetHttpRouter.requiredRole(exchange, method);
                AuthPrincipal principal = authorize(exchange, requiredRole);
                ManagedAssetHttpRouter managedAssets = managedAssetRouter.orElseThrow(() ->
                        new HttpProblem(
                                503,
                                "MANAGED_ASSET_PERSISTENCE_UNAVAILABLE",
                                "Managed asset API requires PostgreSQL schema version 18 or newer"
                        ));
                managedAssets.routeAuthorized(exchange, method, principal);
                return;
            }
"""
scanner_namespace = """            if (ScannerManagedAssetLinkHttpRouter.inNamespace(path)) {
                if (!ScannerManagedAssetLinkHttpRouter.handles(path)) {
                    throw new HttpProblem(
                            404,
                            "NOT_FOUND",
                            "The requested scanner-managed-asset link route does not exist"
                    );
                }
                ApiRole requiredRole = ScannerManagedAssetLinkHttpRouter.requiredRole(exchange, method);
                AuthPrincipal principal = authorize(exchange, requiredRole);
                ScannerManagedAssetLinkHttpRouter links = scannerManagedAssetLinkRouter.orElseThrow(() ->
                        new HttpProblem(
                                503,
                                "SCANNER_MANAGED_ASSET_LINK_PERSISTENCE_UNAVAILABLE",
                                "Scanner-managed-asset link API requires PostgreSQL schema version 19 or newer"
                        ));
                links.routeAuthorized(exchange, method, principal);
                return;
            }
"""
replace_exact(server, managed_namespace, managed_namespace + scanner_namespace)

replace_exact(
    server,
    "        health.put(\"managedAssets\", Map.of(\n"
    "                \"readEnabled\", managedAssetRouter.isPresent(),\n"
    "                \"writeEnabled\", managedAssetRouter.isPresent(),\n"
    "                \"historyReadEnabled\", managedAssetRouter.isPresent()\n"
    "        ));\n"
    "        return health;",
    "        health.put(\"managedAssets\", Map.of(\n"
    "                \"readEnabled\", managedAssetRouter.isPresent(),\n"
    "                \"writeEnabled\", managedAssetRouter.isPresent(),\n"
    "                \"historyReadEnabled\", managedAssetRouter.isPresent()\n"
    "        ));\n"
    "        health.put(\"scannerManagedAssetLinks\", Map.of(\n"
    "                \"readEnabled\", scannerManagedAssetLinkRouter.isPresent(),\n"
    "                \"writeEnabled\", scannerManagedAssetLinkRouter.isPresent(),\n"
    "                \"historyReadEnabled\", scannerManagedAssetLinkRouter.isPresent()\n"
    "        ));\n"
    "        return health;",
)
replace_exact(
    server,
    "                + \"# TYPE rbvm_managed_asset_api_enabled gauge\\n\"\n"
    "                + \"rbvm_managed_asset_api_enabled \" + (managedAssetRouter.isPresent() ? 1 : 0) + \"\\n\"\n"
    "                + \"# TYPE rbvm_process_uptime_seconds gauge\\n\"",
    "                + \"# TYPE rbvm_managed_asset_api_enabled gauge\\n\"\n"
    "                + \"rbvm_managed_asset_api_enabled \" + (managedAssetRouter.isPresent() ? 1 : 0) + \"\\n\"\n"
    "                + \"# TYPE rbvm_scanner_managed_asset_link_api_enabled gauge\\n\"\n"
    "                + \"rbvm_scanner_managed_asset_link_api_enabled \"\n"
    "                + (scannerManagedAssetLinkRouter.isPresent() ? 1 : 0) + \"\\n\"\n"
    "                + \"# TYPE rbvm_process_uptime_seconds gauge\\n\"",
)
replace_exact(
    server,
    "                runtime.managedAssetRegistry(),\n                authenticator,",
    "                runtime.managedAssetRegistry(),\n"
    "                runtime.scannerManagedAssetLinkRegistry(),\n"
    "                authenticator,",
)
replace_exact(
    server,
    "        System.out.println(\"Business Impact operator UI: \" + application.baseUri().resolve(\"/business-impact\"));\n"
    "        System.out.println(\"Data directory: \"",
    "        System.out.println(\"Business Impact operator UI: \" + application.baseUri().resolve(\"/business-impact\"));\n"
    "        System.out.println(\"Managed Assets operator UI: \" + application.baseUri().resolve(\"/assets\"));\n"
    "        System.out.println(\"Scanner↔Managed Asset Link operator UI: \" + application.baseUri().resolve(\"/asset-links\"));\n"
    "        System.out.println(\"Data directory: \"",
)
replace_exact(
    server,
    "        System.out.println(\"Managed Asset API: \"\n"
    "                + (runtime.managedAssetRegistry().isPresent() ? \"ENABLED\" : \"DISABLED\"));\n"
    "        System.out.println(\"API authentication: \"",
    "        System.out.println(\"Managed Asset API: \"\n"
    "                + (runtime.managedAssetRegistry().isPresent() ? \"ENABLED\" : \"DISABLED\"));\n"
    "        System.out.println(\"Scanner↔Managed Asset Link API: \"\n"
    "                + (runtime.scannerManagedAssetLinkRegistry().isPresent() ? \"ENABLED\" : \"DISABLED\"));\n"
    "        System.out.println(\"API authentication: \"",
)

# Regression suite and structural verification.
replace_exact(
    "src/test/java/io/rbvm/csv/PlatformSelfTest.java",
    "        ManagedAssetApiSelfTest.main(args);\n",
    "        ManagedAssetApiSelfTest.main(args);\n        ScannerManagedAssetLinkApiSelfTest.main(args);\n",
)
replace_exact(
    "src/test/java/io/rbvm/csv/PlatformSelfTest.java",
    "        CsvManagedAssetHttpSelfTest.main(args);\n",
    "        CsvManagedAssetHttpSelfTest.main(args);\n        CsvScannerManagedAssetLinkHttpSelfTest.main(args);\n",
)
replace_exact(
    "scripts/verify.sh",
    "python3 \"$ROOT_DIR/scripts/verify-scanner-managed-asset-link.py\"\n"
    "python3 \"$ROOT_DIR/scripts/verify-managed-asset-api.py\"",
    "python3 \"$ROOT_DIR/scripts/verify-scanner-managed-asset-link.py\"\n"
    "python3 \"$ROOT_DIR/scripts/verify-scanner-managed-asset-link-api.py\"\n"
    "python3 \"$ROOT_DIR/scripts/verify-managed-asset-api.py\"",
)
replace_exact(
    "scripts/verify.sh",
    "python3 \"$ROOT_DIR/scripts/verify-managed-assets-ui.py\" \"$ROOT_DIR/src/main/resources/web/assets.html\"\n",
    "python3 \"$ROOT_DIR/scripts/verify-managed-assets-ui.py\" \"$ROOT_DIR/src/main/resources/web/assets.html\"\n"
    "python3 \"$ROOT_DIR/scripts/verify-asset-links-ui.py\"\n",
)

# Navigation only; no implicit linking is added to the managed-asset UI.
replace_exact(
    "src/main/resources/web/index.html",
    '<p><a href="/assets">Managed Assets</a> · <a href="/asset-context">Asset Context</a> · <a href="/reachability">Network Reachability</a> · <a href="/business-impact">Business Impact</a></p>',
    '<p><a href="/assets">Managed Assets</a> · <a href="/asset-links">Scanner↔Managed Asset Links</a> · <a href="/asset-context">Asset Context</a> · <a href="/reachability">Network Reachability</a> · <a href="/business-impact">Business Impact</a></p>',
)
replace_exact(
    "src/main/resources/web/assets.html",
    '<p><a href="/">المنصة الرئيسية</a> · <a href="/asset-context?guide=1">Asset Classification Guide</a> · <a href="/asset-context">Asset Context Evidence</a></p>',
    '<p><a href="/">المنصة الرئيسية</a> · <a href="/asset-links">Scanner↔Managed Asset Links</a> · <a href="/asset-context?guide=1">Asset Classification Guide</a> · <a href="/asset-context">Asset Context Evidence</a></p>',
)

# OpenAPI V23 paths and schemas.
openapi = "api/openapi.yaml"
replace_exact(openapi, "  version: 0.22.0\n", "  version: 0.23.0\n")
replace_exact(
    openapi,
    "    evidence, explicit case decisions, an append-only workflow audit trail, and optional\n"
    "    PostgreSQL canonical persistence.\n",
    "    evidence, customer-managed asset inventory, explicit customer-confirmed scanner-to-managed-asset\n"
    "    link decisions, explicit case decisions, an append-only workflow audit trail, and optional\n"
    "    PostgreSQL canonical persistence.\n",
)
scanner_paths = """  /scanner-assets:
    get:
      operationId: listScannerAssetsForManagedAssetLinks
      summary: List scanner assets with current explicit managed-asset link state
      description: >-
        Lists tenant-scoped canonical scanner identities and the latest explicit link decision, if any.
        Missing currentLink means never assessed and is distinct from an explicit UNLINKED decision.
      parameters:
        - name: limit
          in: query
          schema: { type: integer, minimum: 1, maximum: 500, default: 100 }
        - name: afterId
          in: query
          schema: { type: string, format: uuid }
      responses:
        '200':
          description: Scanner-asset page
          content:
            application/json:
              schema: { $ref: '#/components/schemas/ScannerAssetPage' }
        '400': { $ref: '#/components/responses/Problem' }
        '401': { $ref: '#/components/responses/AuthenticationRequired' }
        '429': { $ref: '#/components/responses/RateLimited' }
        '503': { $ref: '#/components/responses/Problem' }

  /scanner-assets/{scannerAssetId}/managed-asset-link:
    parameters:
      - $ref: '#/components/parameters/ScannerAssetId'
    get:
      operationId: getScannerManagedAssetLink
      summary: Read the current explicit scanner-to-managed-asset link decision
      description: >-
        Returns currentLink null with a deterministic strong revision-0 ETag when the scanner asset
        exists but has never had a link decision. An explicit UNLINKED revision is returned as evidence.
      responses:
        '200':
          description: Current explicit link state
          headers:
            ETag:
              description: Strong validator for current link state, including never-assessed revision 0
              schema: { type: string }
          content:
            application/json:
              schema: { $ref: '#/components/schemas/ScannerManagedAssetLinkCurrent' }
        '400': { $ref: '#/components/responses/Problem' }
        '401': { $ref: '#/components/responses/AuthenticationRequired' }
        '404': { $ref: '#/components/responses/Problem' }
        '429': { $ref: '#/components/responses/RateLimited' }
        '503': { $ref: '#/components/responses/Problem' }

  /scanner-assets/{scannerAssetId}/managed-asset-link/revisions:
    parameters:
      - $ref: '#/components/parameters/ScannerAssetId'
    get:
      operationId: listScannerManagedAssetLinkRevisions
      summary: Read immutable explicit link-decision history
      parameters:
        - name: limit
          in: query
          schema: { type: integer, minimum: 1, maximum: 500, default: 100 }
        - name: beforeRevision
          in: query
          schema: { type: integer, minimum: 1 }
      responses:
        '200':
          description: Link-decision history page, newest first
          content:
            application/json:
              schema: { $ref: '#/components/schemas/ScannerManagedAssetLinkHistoryPage' }
        '400': { $ref: '#/components/responses/Problem' }
        '401': { $ref: '#/components/responses/AuthenticationRequired' }
        '404': { $ref: '#/components/responses/Problem' }
        '429': { $ref: '#/components/responses/RateLimited' }
        '503': { $ref: '#/components/responses/Problem' }
    post:
      operationId: appendScannerManagedAssetLinkRevision
      summary: Append one explicit customer-confirmed link decision
      description: >-
        Requires exactly one strong If-Match validator from the current-state endpoint. The body is
        complete link state. There is no inferred matching, partial PATCH, DELETE, or automatic merge.
      parameters:
        - name: If-Match
          in: header
          required: true
          schema: { type: string }
      requestBody:
        required: true
        content:
          application/json:
            schema: { $ref: '#/components/schemas/ScannerManagedAssetLinkRevisionRequest' }
      responses:
        '200':
          description: Link decision appended or exact request replayed
          headers:
            ETag:
              schema: { type: string }
          content:
            application/json:
              schema: { $ref: '#/components/schemas/ScannerManagedAssetLinkCurrent' }
        '400': { $ref: '#/components/responses/Problem' }
        '401': { $ref: '#/components/responses/AuthenticationRequired' }
        '403': { $ref: '#/components/responses/InsufficientRole' }
        '404': { $ref: '#/components/responses/Problem' }
        '412': { $ref: '#/components/responses/Problem' }
        '413': { $ref: '#/components/responses/Problem' }
        '415': { $ref: '#/components/responses/Problem' }
        '422': { $ref: '#/components/responses/Problem' }
        '428': { $ref: '#/components/responses/Problem' }
        '429': { $ref: '#/components/responses/RateLimited' }
        '503': { $ref: '#/components/responses/Problem' }

"""
append_before(openapi, "components:\n", scanner_paths)
replace_exact(
    openapi,
    "  parameters:\n    ManagedAssetId:\n",
    "  parameters:\n"
    "    ScannerAssetId:\n"
    "      name: scannerAssetId\n"
    "      in: path\n"
    "      required: true\n"
    "      schema:\n"
    "        type: string\n"
    "        format: uuid\n"
    "    ManagedAssetId:\n",
)
replace_exact(
    openapi,
    "        - managedAssets\n        - storedImports\n",
    "        - managedAssets\n        - scannerManagedAssetLinks\n        - storedImports\n",
)
replace_exact(
    openapi,
    "        managedAssets:\n          $ref: '#/components/schemas/ManagedAssetCapability'\n        storedImports:\n",
    "        managedAssets:\n          $ref: '#/components/schemas/ManagedAssetCapability'\n"
    "        scannerManagedAssetLinks:\n"
    "          $ref: '#/components/schemas/ScannerManagedAssetLinkCapability'\n"
    "        storedImports:\n",
)
scanner_schemas = """    ScannerManagedAssetLinkCapability:
      type: object
      additionalProperties: false
      required: [readEnabled, writeEnabled, historyReadEnabled]
      properties:
        readEnabled: { type: boolean }
        writeEnabled: { type: boolean }
        historyReadEnabled: { type: boolean }

    ScannerManagedAssetLinkStatus:
      type: string
      enum: [LINKED, UNLINKED]

    ScannerManagedAssetLinkEvent:
      type: object
      additionalProperties: false
      required: [eventId, scannerAssetId, revision, linkStatus, managedAssetId, linkMethod, evidenceSha256, changedBy, changeNote, recordedAt]
      properties:
        eventId: { type: string, format: uuid }
        scannerAssetId: { type: string, format: uuid }
        revision: { type: integer, minimum: 1 }
        linkStatus: { $ref: '#/components/schemas/ScannerManagedAssetLinkStatus' }
        managedAssetId: { type: [string, 'null'], format: uuid }
        linkMethod: { const: CUSTOMER_CONFIRMED }
        evidenceSha256: { type: string, pattern: '^[a-f0-9]{64}$' }
        changedBy: { type: string, minLength: 1 }
        changeNote: { type: string }
        recordedAt: { type: string, format: date-time }

    ScannerAssetSummary:
      type: object
      additionalProperties: false
      required: [id, observedName, osNameRaw, sourceProfileKey, identityBasis, identityConfidence, firstObservedAt, lastObservedAt, currentLink]
      properties:
        id: { type: string, format: uuid }
        observedName: { type: string, minLength: 1 }
        osNameRaw: { type: string }
        sourceProfileKey: { type: string, minLength: 1 }
        identityBasis: { const: SOURCE_NAME_ONLY }
        identityConfidence: { const: LOW }
        firstObservedAt: { type: string, format: date-time }
        lastObservedAt: { type: string, format: date-time }
        currentLink:
          oneOf:
            - $ref: '#/components/schemas/ScannerManagedAssetLinkEvent'
            - type: 'null'

    ScannerAssetPage:
      type: object
      additionalProperties: false
      required: [assets, nextAfterId]
      properties:
        assets:
          type: array
          items: { $ref: '#/components/schemas/ScannerAssetSummary' }
        nextAfterId: { type: [string, 'null'], format: uuid }

    ScannerManagedAssetLinkCurrent:
      type: object
      additionalProperties: false
      required: [scannerAssetId, currentLink]
      properties:
        scannerAssetId: { type: string, format: uuid }
        currentLink:
          oneOf:
            - $ref: '#/components/schemas/ScannerManagedAssetLinkEvent'
            - type: 'null'

    ScannerManagedAssetLinkHistoryPage:
      type: object
      additionalProperties: false
      required: [scannerAssetId, events, nextBeforeRevision]
      properties:
        scannerAssetId: { type: string, format: uuid }
        events:
          type: array
          items: { $ref: '#/components/schemas/ScannerManagedAssetLinkEvent' }
        nextBeforeRevision: { type: [integer, 'null'], minimum: 1 }

    ScannerManagedAssetLinkRevisionRequest:
      type: object
      additionalProperties: false
      required: [linkStatus]
      allOf:
        - if:
            properties: { linkStatus: { const: LINKED } }
            required: [linkStatus]
          then:
            required: [managedAssetId]
            properties:
              managedAssetId: { type: string, format: uuid }
        - if:
            properties: { linkStatus: { const: UNLINKED } }
            required: [linkStatus]
          then:
            properties:
              managedAssetId: { type: 'null' }
      properties:
        linkStatus: { $ref: '#/components/schemas/ScannerManagedAssetLinkStatus' }
        managedAssetId: { type: [string, 'null'], format: uuid }
        changeNote: { type: [string, 'null'] }

"""
replace_exact(
    openapi,
    "    ManagedAssetEnvironment:\n",
    scanner_schemas + "    ManagedAssetEnvironment:\n",
)

# Verification knows the new route surface and health capability.
replace_exact(
    "scripts/verify-api.py",
    '    if document.get("info", {}).get("version") != "0.22.0":\n'
    '        raise AssertionError("OpenAPI info.version must match Increment 22")',
    '    if document.get("info", {}).get("version") != "0.23.0":\n'
    '        raise AssertionError("OpenAPI info.version must match Increment 23")',
)
replace_exact(
    "scripts/verify-api.py",
    '        "/managed-assets/{managedAssetId}/revisions",\n',
    '        "/managed-assets/{managedAssetId}/revisions",\n'
    '        "/scanner-assets",\n'
    '        "/scanner-assets/{scannerAssetId}/managed-asset-link",\n'
    '        "/scanner-assets/{scannerAssetId}/managed-asset-link/revisions",\n',
)
replace_exact(
    "scripts/verify-api.py",
    '    create_managed_asset = schemas.get("CreateManagedAssetRequest", {})\n',
    '    if "scannerManagedAssetLinks" not in health_required:\n'
    '        raise AssertionError("Health schema must expose scanner-managed-asset link capability")\n'
    '    link_capability = schemas.get("ScannerManagedAssetLinkCapability", {})\n'
    '    if set(link_capability.get("required", [])) != {\n'
    '        "readEnabled", "writeEnabled", "historyReadEnabled"\n'
    '    }:\n'
    '        raise AssertionError("Scanner-managed-asset link capability schema is incomplete")\n\n'
    '    link_revision = schemas.get("ScannerManagedAssetLinkRevisionRequest", {})\n'
    '    if link_revision.get("additionalProperties") is not False:\n'
    '        raise AssertionError("Scanner-managed-asset link revisions must reject unknown JSON fields")\n\n'
    '    create_managed_asset = schemas.get("CreateManagedAssetRequest", {})\n',
)

# Product release alignment. Workflow files are intentionally updated later via the GitHub connector.
replace_exact("build.gradle.kts", 'version = "0.22.0-SNAPSHOT"', 'version = "0.23.0-SNAPSHOT"')
replace_exact("scripts/build-distribution.sh", "VERSION=0.22.0", "VERSION=0.23.0")
replace_exact("scripts/verify-reproducible-build.sh", "VERSION=0.22.0", "VERSION=0.23.0")
replace_exact(
    "scripts/verify-reproducible-build.sh",
    "grep -q '^Implementation-Version: 0.22.0'",
    "grep -q '^Implementation-Version: 0.23.0'",
)

# README cleanup: current version, migration ceiling, and operational link surface.
replace_exact("README.md", "# RBVM CSV Platform — Increment 21", "# RBVM CSV Platform — Increment 23")
replace_exact(
    "README.md",
    "- Managed Assets UI على `/assets` تستهلك API V1 فقط: list/create/detail/history وcomplete-state immutable revisions مع conflict review صريح عند `412`؛ Increment 21 يضيف link persistence داخلياً لكنه لا يضيف link controls للـUI بعد.\n",
    "- Managed Assets UI على `/assets` تستهلك API V1 فقط: list/create/detail/history وcomplete-state immutable revisions مع conflict review صريح عند `412`.\n"
    "- Increment 23 يضيف `/asset-links` و`SCANNER_MANAGED_ASSET_LINK_API_V1` لعرض scanner assets وإدارة LINK/UNLINK/RELINK كسجل customer-confirmed append-only مع strong ETag/If-Match؛ لا توجد مطابقة تلقائية.\n",
)
replace_exact(
    "README.md",
    "- Migration runner بتدقيق SHA-256 وقفل PostgreSQL advisory وتسلسل V1–V19.",
    "- Migration runner بتدقيق SHA-256 وقفل PostgreSQL advisory وتسلسل V1–V20؛ V20 يضيف typed Decision Input V2 native references وربط managed-asset context بالـlink event التاريخي الدقيق.",
)
replace_exact("README.md", "- OpenAPI 0.21.0 موحّد", "- OpenAPI 0.23.0 موحّد")
replace_exact(
    "README.md",
    "واجهة Managed Assets:\n\n```text\nhttp://127.0.0.1:8080/assets\n```\n",
    "واجهة Managed Assets:\n\n```text\nhttp://127.0.0.1:8080/assets\n```\n\n"
    "واجهة الربط الصريح Scanner↔Managed Asset:\n\n```text\nhttp://127.0.0.1:8080/asset-links\n```\n",
)
replace_exact("README.md", "rbvm-csv-platform-0.21.0.jar", "rbvm-csv-platform-0.23.0.jar", count=3)
replace_exact("README.md", "v0.21.0", "v0.23.0", count=1)

print("V23 exact-context patch: PASS")

#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def replace_once(path: Path, old: str, new: str, label: str) -> None:
    text = path.read_text(encoding="utf-8")
    count = text.count(old)
    if count != 1:
        raise RuntimeError(f"{label}: expected one anchor, found {count}")
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


def factory() -> None:
    path = ROOT / "src/main/java/io/rbvm/postgres/CanonicalProjectionFactory.java"
    text = path.read_text(encoding="utf-8")

    # Disabled runtime: append the V15 capability pair.
    old = "                    Optional.empty(),\n                    Optional.empty()\n            );\n        }\n        JdbcConnectionFactory"
    new = "                    Optional.empty(),\n                    Optional.empty(),\n                    Optional.empty(),\n                    Optional.empty()\n            );\n        }\n        JdbcConnectionFactory"
    if text.count(old) != 1:
        raise RuntimeError("factory disabled runtime anchor mismatch")
    text = text.replace(old, new, 1)

    old = "        Optional<NetworkReachabilityEvidenceReader> networkReachabilityEvidenceReader = Optional.empty();\n"
    new = old + "        Optional<BusinessImpactImporter> businessImpactImporter = Optional.empty();\n" \
        + "        Optional<BusinessImpactEvidenceReader> businessImpactEvidenceReader = Optional.empty();\n"
    if text.count(old) != 1:
        raise RuntimeError("factory Business Impact declarations anchor mismatch")
    text = text.replace(old, new, 1)

    old = """        if (installedVersion >= 14) {
            PostgresNetworkReachabilityImporter importer =
                    new PostgresNetworkReachabilityImporter(connections, false);
            networkReachabilityImporter = Optional.of(importer::importFile);
            networkReachabilityEvidenceReader = Optional.of(
                    new PostgresNetworkReachabilityEvidenceReader(connections)
            );
        }
"""
    new = old + """        if (installedVersion >= 15) {
            PostgresBusinessImpactImporter importer = new PostgresBusinessImpactImporter(
                    connections,
                    false
            );
            businessImpactImporter = Optional.of(importer::importFile);
            businessImpactEvidenceReader = Optional.of(
                    new PostgresBusinessImpactEvidenceReader(connections)
            );
        }
"""
    if text.count(old) != 1:
        raise RuntimeError("factory V15 gate anchor mismatch")
    text = text.replace(old, new, 1)

    old = """                assetContextEvidenceReader,
                networkReachabilityImporter,
                networkReachabilityEvidenceReader
        );
"""
    new = """                assetContextEvidenceReader,
                networkReachabilityImporter,
                networkReachabilityEvidenceReader,
                businessImpactImporter,
                businessImpactEvidenceReader
        );
"""
    if text.count(old) != 1:
        raise RuntimeError("factory return capability anchor mismatch")
    text = text.replace(old, new, 1)

    old = """            Optional<AssetContextEvidenceReader> assetContextEvidenceReader,
            Optional<NetworkReachabilityImporter> networkReachabilityImporter,
            Optional<NetworkReachabilityEvidenceReader> networkReachabilityEvidenceReader
    ) {
"""
    new = """            Optional<AssetContextEvidenceReader> assetContextEvidenceReader,
            Optional<NetworkReachabilityImporter> networkReachabilityImporter,
            Optional<NetworkReachabilityEvidenceReader> networkReachabilityEvidenceReader,
            Optional<BusinessImpactImporter> businessImpactImporter,
            Optional<BusinessImpactEvidenceReader> businessImpactEvidenceReader
    ) {
"""
    if text.count(old) != 1:
        raise RuntimeError("factory RuntimeComponents record anchor mismatch")
    text = text.replace(old, new, 1)

    old = """            networkReachabilityEvidenceReader = Objects.requireNonNull(networkReachabilityEvidenceReader, "networkReachabilityEvidenceReader");
        }
"""
    new = """            networkReachabilityEvidenceReader = Objects.requireNonNull(networkReachabilityEvidenceReader, "networkReachabilityEvidenceReader");
            businessImpactImporter = Objects.requireNonNull(businessImpactImporter, "businessImpactImporter");
            businessImpactEvidenceReader = Objects.requireNonNull(businessImpactEvidenceReader, "businessImpactEvidenceReader");
        }
"""
    if text.count(old) != 1:
        raise RuntimeError("factory RuntimeComponents null guards anchor mismatch")
    text = text.replace(old, new, 1)

    # Existing convenience constructors delegate to the expanded canonical constructor.
    text = text.replace(
        "Optional.empty(), Optional.empty());",
        "Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty());"
    )

    # Preserve the former V14 canonical signature explicitly.
    marker = "    }\n}\n"
    if not text.endswith(marker):
        raise RuntimeError("factory record closing anchor mismatch")
    v14 = """

        /** Backward-compatible constructor through the Network Reachability V14 runtime capability layer. */
        public RuntimeComponents(
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
                Optional<NetworkReachabilityEvidenceReader> networkReachabilityEvidenceReader
        ) {
            this(canonicalProjection, readCatalog, applicabilityImporter, applicabilityFindingExporter,
                    cvssV31Importer, cvssV31EvidenceReader, cisaKevImporter, cisaKevEvidenceReader,
                    epssImporter, epssEvidenceReader, assetContextImporter, assetContextEvidenceReader,
                    networkReachabilityImporter, networkReachabilityEvidenceReader,
                    Optional.empty(), Optional.empty());
        }
"""
    text = text[:-len(marker)] + v14 + marker
    path.write_text(text, encoding="utf-8")


def server() -> None:
    path = ROOT / "src/main/java/io/rbvm/csv/CsvPlatformServer.java"
    text = path.read_text(encoding="utf-8")

    old = """import io.rbvm.postgres.AssetContextImporter;
import io.rbvm.postgres.CanonicalProjectionFactory;
"""
    new = """import io.rbvm.postgres.AssetContextImporter;
import io.rbvm.postgres.BusinessImpactEvidenceReader;
import io.rbvm.postgres.BusinessImpactImportResult;
import io.rbvm.postgres.BusinessImpactImporter;
import io.rbvm.postgres.CanonicalProjectionFactory;
"""
    if text.count(old) != 1:
        raise RuntimeError("server Business Impact imports anchor mismatch")
    text = text.replace(old, new, 1)

    old = """    private final byte[] networkReachabilityUi;
    private final ApiKeyAuthenticator authenticator;
"""
    new = """    private final byte[] networkReachabilityUi;
    private final byte[] businessImpactUi;
    private final ApiKeyAuthenticator authenticator;
"""
    if text.count(old) != 1:
        raise RuntimeError("server Business Impact UI field anchor mismatch")
    text = text.replace(old, new, 1)

    old = """    private final Optional<NetworkReachabilityImporter> networkReachabilityImporter;
    private final Optional<NetworkReachabilityEvidenceReader> networkReachabilityEvidenceReader;
    private final Instant startedAt = Instant.now();
"""
    new = """    private final Optional<NetworkReachabilityImporter> networkReachabilityImporter;
    private final Optional<NetworkReachabilityEvidenceReader> networkReachabilityEvidenceReader;
    private final Optional<BusinessImpactImporter> businessImpactImporter;
    private final Optional<BusinessImpactEvidenceReader> businessImpactEvidenceReader;
    private final Instant startedAt = Instant.now();
"""
    if text.count(old) != 1:
        raise RuntimeError("server Business Impact capability field anchor mismatch")
    text = text.replace(old, new, 1)

    old = """        this.networkReachabilityImporter = Optional.empty();
        this.networkReachabilityEvidenceReader = Optional.empty();
        this.webUi = loadResource("/web/index.html");
"""
    new = """        this.networkReachabilityImporter = Optional.empty();
        this.networkReachabilityEvidenceReader = Optional.empty();
        this.businessImpactImporter = Optional.empty();
        this.businessImpactEvidenceReader = Optional.empty();
        this.webUi = loadResource("/web/index.html");
"""
    if text.count(old) != 1:
        raise RuntimeError("server simple capability initialization anchor mismatch")
    text = text.replace(old, new, 1)

    old = """        this.networkReachabilityUi = loadResource("/web/network-reachability.html");
        this.server = HttpServer.create(new InetSocketAddress(host, port), 32);
"""
    new = """        this.networkReachabilityUi = loadResource("/web/network-reachability.html");
        this.businessImpactUi = loadResource("/web/business-impact.html");
        this.server = HttpServer.create(new InetSocketAddress(host, port), 32);
"""
    if text.count(old) != 2:
        raise RuntimeError(f"server UI resource anchors mismatch: {text.count(old)}")
    text = text.replace(old, new)

    # Expand the V14 implementation to V15.
    old = """            Optional<NetworkReachabilityImporter> networkReachabilityImporter,
            Optional<NetworkReachabilityEvidenceReader> networkReachabilityEvidenceReader,
            ApiKeyAuthenticator authenticator,
            RequestRateLimiter rateLimiter
    ) throws IOException {
        if (port < 0 || port > 65_535) {
"""
    new = """            Optional<NetworkReachabilityImporter> networkReachabilityImporter,
            Optional<NetworkReachabilityEvidenceReader> networkReachabilityEvidenceReader,
            Optional<BusinessImpactImporter> businessImpactImporter,
            Optional<BusinessImpactEvidenceReader> businessImpactEvidenceReader,
            ApiKeyAuthenticator authenticator,
            RequestRateLimiter rateLimiter
    ) throws IOException {
        if (port < 0 || port > 65_535) {
"""
    if text.count(old) != 1:
        raise RuntimeError("server V15 full constructor signature anchor mismatch")
    text = text.replace(old, new, 1)

    full_start = text.index("    public CsvPlatformServer(\n", text.index("Optional<BusinessImpactImporter> businessImpactImporter" ) - 1200)
    v14 = """    /** Backward-compatible runtime constructor through the Network Reachability V14 capability layer. */
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
            ApiKeyAuthenticator authenticator,
            RequestRateLimiter rateLimiter
    ) throws IOException {
        this(
                host, port, dataDirectory, maximumUploadBytes, canonicalProjection, readCatalog,
                applicabilityImporter, applicabilityFindingExporter,
                cvssV31Importer, cvssV31EvidenceReader,
                cisaKevImporter, cisaKevEvidenceReader,
                epssImporter, epssEvidenceReader,
                assetContextImporter, assetContextEvidenceReader,
                networkReachabilityImporter, networkReachabilityEvidenceReader,
                Optional.empty(), Optional.empty(), authenticator, rateLimiter
        );
    }

"""
    text = text[:full_start] + v14 + text[full_start:]

    old = """        this.networkReachabilityEvidenceReader = Objects.requireNonNull(
                networkReachabilityEvidenceReader,
                "networkReachabilityEvidenceReader"
        );
        this.webUi = loadResource("/web/index.html");
"""
    new = """        this.networkReachabilityEvidenceReader = Objects.requireNonNull(
                networkReachabilityEvidenceReader,
                "networkReachabilityEvidenceReader"
        );
        this.businessImpactImporter = Objects.requireNonNull(
                businessImpactImporter,
                "businessImpactImporter"
        );
        this.businessImpactEvidenceReader = Objects.requireNonNull(
                businessImpactEvidenceReader,
                "businessImpactEvidenceReader"
        );
        this.webUi = loadResource("/web/index.html");
"""
    if text.count(old) != 1:
        raise RuntimeError("server Business Impact full constructor assignments anchor mismatch")
    text = text.replace(old, new, 1)

    old = """            if ("/reachability".equals(path) || "/reachability/".equals(path)) {
                requireMethod(exchange, method, "GET");
                sendBytes(exchange, 200, "text/html; charset=utf-8", networkReachabilityUi);
                return;
            }
"""
    new = old + """            if ("/business-impact".equals(path) || "/business-impact/".equals(path)) {
                requireMethod(exchange, method, "GET");
                sendBytes(exchange, 200, "text/html; charset=utf-8", businessImpactUi);
                return;
            }
"""
    if text.count(old) != 1:
        raise RuntimeError("server Business Impact UI route anchor mismatch")
    text = text.replace(old, new, 1)

    old = """            if ("/api/v1/network-reachability-imports".equals(path)) {
                requireMethod(exchange, method, "POST");
                authorize(exchange, ApiRole.OPERATOR);
                createNetworkReachabilityImport(exchange);
                return;
            }
"""
    new = old + """            if ("/api/v1/business-impact-evidence".equals(path)) {
                requireMethod(exchange, method, "GET");
                authorize(exchange, ApiRole.VIEWER);
                readBusinessImpactEvidence(exchange);
                return;
            }
            if ("/api/v1/business-impact-imports".equals(path)) {
                requireMethod(exchange, method, "POST");
                authorize(exchange, ApiRole.OPERATOR);
                createBusinessImpactImport(exchange);
                return;
            }
"""
    if text.count(old) != 1:
        raise RuntimeError("server Business Impact API route anchor mismatch")
    text = text.replace(old, new, 1)

    old = """        health.put("networkReachability", Map.of(
                "importEnabled", networkReachabilityImporter.isPresent(),
                "evidenceReadEnabled", networkReachabilityEvidenceReader.isPresent()
        ));
        return health;
"""
    new = """        health.put("networkReachability", Map.of(
                "importEnabled", networkReachabilityImporter.isPresent(),
                "evidenceReadEnabled", networkReachabilityEvidenceReader.isPresent()
        ));
        health.put("businessImpact", Map.of(
                "importEnabled", businessImpactImporter.isPresent(),
                "evidenceReadEnabled", businessImpactEvidenceReader.isPresent()
        ));
        return health;
"""
    if text.count(old) != 1:
        raise RuntimeError("server Business Impact health anchor mismatch")
    text = text.replace(old, new, 1)

    methods = """    private void readBusinessImpactEvidence(HttpExchange exchange) throws IOException {
        BusinessImpactEvidenceReader reader = businessImpactEvidenceReader.orElseThrow(() ->
                new HttpProblem(
                        503,
                        "BUSINESS_IMPACT_PERSISTENCE_UNAVAILABLE",
                        "Business Impact evidence reads require PostgreSQL schema version 15 or newer"
                ));
        BusinessImpactEvidenceQuery query = parseBusinessImpactEvidenceQuery(exchange.getRequestURI());
        sendJson(exchange, 200, reader.currentEvidence(
                query.limit(),
                query.assetPrefix(),
                query.sourceProfileKey(),
                query.businessService(),
                query.impactSource(),
                query.impactDimension(),
                query.impactLevel()
        ));
    }

    private void createBusinessImpactImport(HttpExchange exchange) throws IOException {
        BusinessImpactImporter importer = businessImpactImporter.orElseThrow(() ->
                new HttpProblem(
                        503,
                        "BUSINESS_IMPACT_PERSISTENCE_UNAVAILABLE",
                        "Business Impact import requires PostgreSQL schema version 15 or newer"
                ));
        String contentType = exchange.getRequestHeaders().getFirst("Content-Type");
        if (!isCsvContentType(contentType)) {
            throw new HttpProblem(
                    415,
                    "UNSUPPORTED_MEDIA_TYPE",
                    "Content-Type must be text/csv, application/csv, or application/octet-stream"
            );
        }
        long contentLength = parseContentLength(exchange.getRequestHeaders().getFirst("Content-Length"));
        if (contentLength > maximumUploadBytes) {
            throw new HttpProblem(
                    413,
                    "UPLOAD_TOO_LARGE",
                    "Business Impact CSV exceeds the configured upload limit"
            );
        }
        Path staged = Files.createTempFile("rbvm-business-impact-upload-", ".csv");
        try {
            try (InputStream body = exchange.getRequestBody();
                 OutputStream output = Files.newOutputStream(staged)) {
                copyBounded(body, output, maximumUploadBytes, "Business Impact CSV");
            }
            BusinessImpactImportResult result = importer.importFile(staged);
            sendJson(exchange, 200, result.toMap());
        } finally {
            Files.deleteIfExists(staged);
        }
    }

"""
    marker = "    private static void copyBounded(\n"
    if text.count(marker) != 1:
        raise RuntimeError("server Business Impact method insertion anchor mismatch")
    text = text.replace(marker, methods + marker, 1)

    parser = """    private static BusinessImpactEvidenceQuery parseBusinessImpactEvidenceQuery(URI uri) {
        Map<String, String> query = parseParameters(uri.getRawQuery());
        rejectUnknownFields(query, Set.of(
                "limit", "asset", "sourceProfile", "businessService", "impactSource",
                "impactDimension", "impactLevel"));
        return new BusinessImpactEvidenceQuery(
                queryLimit(query),
                queryOptional(query, "asset", 160),
                querySourceProfile(query),
                queryOptional(query, "businessService", 256),
                queryOptional(query, "impactSource", 256),
                queryEnum(query, "impactDimension", Set.of(
                        "AVAILABILITY", "INTEGRITY", "CONFIDENTIALITY", "SAFETY", "FINANCIAL",
                        "REGULATORY", "OPERATIONAL", "REPUTATIONAL", "MISSION", "OTHER", "UNKNOWN")),
                queryEnum(query, "impactLevel", Set.of(
                        "SEVERE", "HIGH", "MODERATE", "LOW", "NEGLIGIBLE", "UNKNOWN"))
        );
    }

"""
    marker = "    private static Map<String, String> parseEvidenceQuery(URI uri) {\n"
    if text.count(marker) != 1:
        raise RuntimeError("server Business Impact query parser insertion anchor mismatch")
    text = text.replace(marker, parser + marker, 1)

    old = """                + "# TYPE rbvm_network_reachability_evidence_read_enabled gauge\\n"
                + "rbvm_network_reachability_evidence_read_enabled " + (networkReachabilityEvidenceReader.isPresent() ? 1 : 0) + "\\n"
                + "# TYPE rbvm_process_uptime_seconds gauge\\n"
"""
    new = """                + "# TYPE rbvm_network_reachability_evidence_read_enabled gauge\\n"
                + "rbvm_network_reachability_evidence_read_enabled " + (networkReachabilityEvidenceReader.isPresent() ? 1 : 0) + "\\n"
                + "# TYPE rbvm_business_impact_import_enabled gauge\\n"
                + "rbvm_business_impact_import_enabled " + (businessImpactImporter.isPresent() ? 1 : 0) + "\\n"
                + "# TYPE rbvm_business_impact_evidence_read_enabled gauge\\n"
                + "rbvm_business_impact_evidence_read_enabled " + (businessImpactEvidenceReader.isPresent() ? 1 : 0) + "\\n"
                + "# TYPE rbvm_process_uptime_seconds gauge\\n"
"""
    if text.count(old) != 1:
        raise RuntimeError("server Business Impact metrics anchor mismatch")
    text = text.replace(old, new, 1)

    old = """                runtime.networkReachabilityImporter(),
                runtime.networkReachabilityEvidenceReader(),
                authenticator,
"""
    new = """                runtime.networkReachabilityImporter(),
                runtime.networkReachabilityEvidenceReader(),
                runtime.businessImpactImporter(),
                runtime.businessImpactEvidenceReader(),
                authenticator,
"""
    if text.count(old) != 1:
        raise RuntimeError("server main Business Impact runtime components anchor mismatch")
    text = text.replace(old, new, 1)

    old = """        System.out.println("Network Reachability operator UI: " + application.baseUri().resolve("/reachability"));
        System.out.println("Data directory: " + configuration.dataDirectory().toAbsolutePath().normalize());
"""
    new = """        System.out.println("Network Reachability operator UI: " + application.baseUri().resolve("/reachability"));
        System.out.println("Business Impact operator UI: " + application.baseUri().resolve("/business-impact"));
        System.out.println("Data directory: " + configuration.dataDirectory().toAbsolutePath().normalize());
"""
    if text.count(old) != 1:
        raise RuntimeError("server Business Impact UI startup log anchor mismatch")
    text = text.replace(old, new, 1)

    old = """        System.out.println("Network Reachability persistence: "
                + (runtime.networkReachabilityImporter().isPresent() ? "ENABLED" : "DISABLED"));
        System.out.println("API authentication: "
"""
    new = """        System.out.println("Network Reachability persistence: "
                + (runtime.networkReachabilityImporter().isPresent() ? "ENABLED" : "DISABLED"));
        System.out.println("Business Impact persistence: "
                + (runtime.businessImpactImporter().isPresent() ? "ENABLED" : "DISABLED"));
        System.out.println("API authentication: "
"""
    if text.count(old) != 1:
        raise RuntimeError("server Business Impact persistence startup log anchor mismatch")
    text = text.replace(old, new, 1)

    old = """    private record NetworkReachabilityEvidenceQuery(
            int limit,
            String assetPrefix,
            String sourceProfileKey,
            String evidenceSource,
            String originScope,
            String reachabilityStatus
    ) {
    }

"""
    new = old + """    private record BusinessImpactEvidenceQuery(
            int limit,
            String assetPrefix,
            String sourceProfileKey,
            String businessService,
            String impactSource,
            String impactDimension,
            String impactLevel
    ) {
    }

"""
    if text.count(old) != 1:
        raise RuntimeError("server Business Impact query record anchor mismatch")
    text = text.replace(old, new, 1)

    path.write_text(text, encoding="utf-8")


def tests_and_web() -> None:
    path = ROOT / "src/test/java/io/rbvm/csv/PlatformSelfTest.java"
    replace_once(
        path,
        "        CsvNetworkReachabilityHttpSelfTest.main(args);\n",
        "        CsvNetworkReachabilityHttpSelfTest.main(args);\n"
        "        CsvBusinessImpactHttpSelfTest.main(args);\n",
        "PlatformSelfTest Business Impact HTTP wiring",
    )

    path = ROOT / "src/test/java/io/rbvm/postgres/PostgresFoundationSelfTest.java"
    replace_once(
        path,
        "        PostgresNetworkReachabilityEvidenceReaderSelfTest.main(args);\n",
        "        PostgresNetworkReachabilityEvidenceReaderSelfTest.main(args);\n"
        "        PostgresBusinessImpactEvidenceReaderSelfTest.main(args);\n",
        "PostgresFoundation Business Impact reader wiring",
    )

    path = ROOT / "scripts/verify-web.py"
    replace_once(
        path,
        '        (root / "src/main/resources/web/network-reachability.html", True),\n',
        '        (root / "src/main/resources/web/network-reachability.html", True),\n'
        '        (root / "src/main/resources/web/business-impact.html", True),\n',
        "web verifier Business Impact page",
    )


def main() -> None:
    factory()
    server()
    tests_and_web()
    print("Business Impact V15 runtime wiring applied")


if __name__ == "__main__":
    main()

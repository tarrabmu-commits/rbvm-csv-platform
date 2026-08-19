#!/usr/bin/env python3
"""One-shot deterministic wiring for the V14 Network Reachability runtime surface."""

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

    disabled = '''                    Optional.empty(),
                    Optional.empty(),
                    Optional.empty(),
                    Optional.empty()
            );
'''
    if text.count(disabled) < 1:
        raise RuntimeError("factory disabled component anchor missing")
    text = text.replace(
        disabled,
        '''                    Optional.empty(),
                    Optional.empty(),
                    Optional.empty(),
                    Optional.empty(),
                    Optional.empty(),
                    Optional.empty()
            );
''',
        1,
    )

    variables = '''        Optional<AssetContextImporter> assetContextImporter = Optional.empty();
        Optional<AssetContextEvidenceReader> assetContextEvidenceReader = Optional.empty();
'''
    if text.count(variables) != 1:
        raise RuntimeError("factory reachability variable anchor mismatch")
    text = text.replace(
        variables,
        variables
        + '''        Optional<NetworkReachabilityImporter> networkReachabilityImporter = Optional.empty();
        Optional<NetworkReachabilityEvidenceReader> networkReachabilityEvidenceReader = Optional.empty();
''',
        1,
    )

    gate = '''        if (installedVersion >= 13) {
            PostgresAssetContextImporter importer = new PostgresAssetContextImporter(connections, false);
            assetContextImporter = Optional.of(importer::importFile);
            assetContextEvidenceReader = Optional.of(
                    new PostgresAssetContextEvidenceReader(connections)
            );
        }
'''
    if text.count(gate) != 1:
        raise RuntimeError("factory V14 gate anchor mismatch")
    text = text.replace(
        gate,
        gate + '''        if (installedVersion >= 14) {
            PostgresNetworkReachabilityImporter importer =
                    new PostgresNetworkReachabilityImporter(connections, false);
            networkReachabilityImporter = Optional.of(importer::importFile);
            networkReachabilityEvidenceReader = Optional.of(
                    new PostgresNetworkReachabilityEvidenceReader(connections)
            );
        }
''',
        1,
    )

    result_tail = '''                epssEvidenceReader,
                assetContextImporter,
                assetContextEvidenceReader
        );
'''
    if text.count(result_tail) != 1:
        raise RuntimeError("factory runtime result anchor mismatch")
    text = text.replace(
        result_tail,
        '''                epssEvidenceReader,
                assetContextImporter,
                assetContextEvidenceReader,
                networkReachabilityImporter,
                networkReachabilityEvidenceReader
        );
''',
        1,
    )

    record_tail = '''            Optional<EpssEvidenceReader> epssEvidenceReader,
            Optional<AssetContextImporter> assetContextImporter,
            Optional<AssetContextEvidenceReader> assetContextEvidenceReader
    ) {
'''
    if text.count(record_tail) != 1:
        raise RuntimeError("factory runtime record anchor mismatch")
    text = text.replace(
        record_tail,
        '''            Optional<EpssEvidenceReader> epssEvidenceReader,
            Optional<AssetContextImporter> assetContextImporter,
            Optional<AssetContextEvidenceReader> assetContextEvidenceReader,
            Optional<NetworkReachabilityImporter> networkReachabilityImporter,
            Optional<NetworkReachabilityEvidenceReader> networkReachabilityEvidenceReader
    ) {
''',
        1,
    )

    validation = '''            assetContextEvidenceReader = Objects.requireNonNull(
                    assetContextEvidenceReader,
                    "assetContextEvidenceReader"
            );
'''
    if text.count(validation) != 1:
        raise RuntimeError("factory validation anchor mismatch")
    text = text.replace(
        validation,
        validation + '''            networkReachabilityImporter = Objects.requireNonNull(
                    networkReachabilityImporter,
                    "networkReachabilityImporter"
            );
            networkReachabilityEvidenceReader = Objects.requireNonNull(
                    networkReachabilityEvidenceReader,
                    "networkReachabilityEvidenceReader"
            );
''',
        1,
    )

    # Every backward-compatible constructor delegation must now supply two additional empty optionals.
    # The V13 constructor is preserved explicitly below; older constructors delegate through it.
    marker = '''        /** Backward-compatible constructor through the EPSS V12 runtime capability layer. */
'''
    if text.count(marker) != 1:
        raise RuntimeError("factory V13 compatibility insertion anchor mismatch")

    # Existing V13 constructor currently delegates to the record canonical constructor. Extend only its
    # delegation, while older overloads already target earlier overloads and remain source-compatible.
    v13_ctor_tail = '''                    epssEvidenceReader,
                    assetContextImporter,
                    assetContextEvidenceReader
            );
        }
'''
    if text.count(v13_ctor_tail) != 1:
        raise RuntimeError("factory V13 constructor delegation anchor mismatch")
    text = text.replace(
        v13_ctor_tail,
        '''                    epssEvidenceReader,
                    assetContextImporter,
                    assetContextEvidenceReader,
                    Optional.empty(),
                    Optional.empty()
            );
        }
''',
        1,
    )

    # All shorter constructors that directly hit the canonical record constructor need enough empties.
    # Adding two fields to the canonical record means append two empties to every delegation ending in
    # four empties or more; do this structurally by fixing constructor invocations that still have the
    # previous arity. javac is the final guard.
    patterns = [
        ('''                    Optional.empty(),
                    Optional.empty(),
                    Optional.empty(),
                    Optional.empty()
            );
        }
''', '''                    Optional.empty(),
                    Optional.empty(),
                    Optional.empty(),
                    Optional.empty(),
                    Optional.empty(),
                    Optional.empty()
            );
        }
'''),
    ]
    # Apply to remaining backward constructor calls, not the disabled runtime branch already updated.
    for old, new in patterns:
        while old in text:
            text = text.replace(old, new, 1)

    path.write_text(text, encoding="utf-8")


def server() -> None:
    path = ROOT / "src/main/java/io/rbvm/csv/CsvPlatformServer.java"
    text = path.read_text(encoding="utf-8")

    text = text.replace(
        "import io.rbvm.postgres.EpssImporter;\n",
        "import io.rbvm.postgres.EpssImporter;\n"
        "import io.rbvm.postgres.NetworkReachabilityEvidenceReader;\n"
        "import io.rbvm.postgres.NetworkReachabilityImportResult;\n"
        "import io.rbvm.postgres.NetworkReachabilityImporter;\n",
        1,
    )
    text = text.replace(
        "    private final byte[] assetContextUi;\n",
        "    private final byte[] assetContextUi;\n"
        "    private final byte[] networkReachabilityUi;\n",
        1,
    )
    text = text.replace(
        "    private final Optional<AssetContextEvidenceReader> assetContextEvidenceReader;\n",
        "    private final Optional<AssetContextEvidenceReader> assetContextEvidenceReader;\n"
        "    private final Optional<NetworkReachabilityImporter> networkReachabilityImporter;\n"
        "    private final Optional<NetworkReachabilityEvidenceReader> networkReachabilityEvidenceReader;\n",
        1,
    )

    simple_fields = '''        this.assetContextImporter = Optional.empty();
        this.assetContextEvidenceReader = Optional.empty();
'''
    if text.count(simple_fields) != 1:
        raise RuntimeError("server simple reachability fields anchor mismatch")
    text = text.replace(
        simple_fields,
        simple_fields
        + '''        this.networkReachabilityImporter = Optional.empty();
        this.networkReachabilityEvidenceReader = Optional.empty();
''',
        1,
    )
    text = text.replace(
        '        this.assetContextUi = loadResource("/web/asset-context.html");\n',
        '        this.assetContextUi = loadResource("/web/asset-context.html");\n'
        '        this.networkReachabilityUi = loadResource("/web/network-reachability.html");\n',
        1,
    )

    # Preserve the V13 constructor as a backward-compatible wrapper, then extend the canonical one.
    final_signature = '''    public CsvPlatformServer(
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
            ApiKeyAuthenticator authenticator,
            RequestRateLimiter rateLimiter
    ) throws IOException {
'''
    if text.count(final_signature) != 1:
        raise RuntimeError("server V13 final constructor signature anchor mismatch")
    wrapper = '''    /** Backward-compatible runtime constructor through the Asset Context V13 capability layer. */
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
                Optional.empty(),
                Optional.empty(),
                authenticator,
                rateLimiter
        );
    }

'''
    extended = final_signature.replace(
        "            Optional<AssetContextEvidenceReader> assetContextEvidenceReader,\n            ApiKeyAuthenticator authenticator,\n",
        "            Optional<AssetContextEvidenceReader> assetContextEvidenceReader,\n"
        "            Optional<NetworkReachabilityImporter> networkReachabilityImporter,\n"
        "            Optional<NetworkReachabilityEvidenceReader> networkReachabilityEvidenceReader,\n"
        "            ApiKeyAuthenticator authenticator,\n"
    )
    text = text.replace(final_signature, wrapper + extended, 1)

    assign = '''        this.assetContextEvidenceReader = Objects.requireNonNull(
                assetContextEvidenceReader,
                "assetContextEvidenceReader"
        );
'''
    if text.count(assign) != 1:
        raise RuntimeError("server reachability assignment anchor mismatch")
    text = text.replace(
        assign,
        assign + '''        this.networkReachabilityImporter = Objects.requireNonNull(
                networkReachabilityImporter,
                "networkReachabilityImporter"
        );
        this.networkReachabilityEvidenceReader = Objects.requireNonNull(
                networkReachabilityEvidenceReader,
                "networkReachabilityEvidenceReader"
        );
''',
        1,
    )
    # Final constructor has its own resource-load block; the first simple constructor was already updated.
    target = '        this.assetContextUi = loadResource("/web/asset-context.html");\n'
    if text.count(target) != 2:
        raise RuntimeError(f"server resource count unexpected after simple update: {text.count(target)}")
    # Replace the remaining occurrence only.
    first = text.find(target)
    second = text.find(target, first + len(target))
    text = text[:second] + target + '        this.networkReachabilityUi = loadResource("/web/network-reachability.html");\n' + text[second + len(target):]

    page_anchor = '''            if ("/asset-context".equals(path) || "/asset-context/".equals(path)) {
                requireMethod(exchange, method, "GET");
                sendBytes(exchange, 200, "text/html; charset=utf-8", assetContextUi);
                return;
            }
'''
    if text.count(page_anchor) != 1:
        raise RuntimeError("server reachability page anchor mismatch")
    text = text.replace(
        page_anchor,
        page_anchor + '''            if ("/reachability".equals(path) || "/reachability/".equals(path)) {
                requireMethod(exchange, method, "GET");
                sendBytes(exchange, 200, "text/html; charset=utf-8", networkReachabilityUi);
                return;
            }
''',
        1,
    )

    api_anchor = '''            if ("/api/v1/asset-context-imports".equals(path)) {
                requireMethod(exchange, method, "POST");
                authorize(exchange, ApiRole.OPERATOR);
                createAssetContextImport(exchange);
                return;
            }
'''
    if text.count(api_anchor) != 1:
        raise RuntimeError("server reachability API anchor mismatch")
    text = text.replace(
        api_anchor,
        api_anchor + '''            if ("/api/v1/network-reachability-evidence".equals(path)) {
                requireMethod(exchange, method, "GET");
                authorize(exchange, ApiRole.VIEWER);
                readNetworkReachabilityEvidence(exchange);
                return;
            }
            if ("/api/v1/network-reachability-imports".equals(path)) {
                requireMethod(exchange, method, "POST");
                authorize(exchange, ApiRole.OPERATOR);
                createNetworkReachabilityImport(exchange);
                return;
            }
''',
        1,
    )

    health_anchor = '''        health.put("assetContext", Map.of(
                "importEnabled", assetContextImporter.isPresent(),
                "evidenceReadEnabled", assetContextEvidenceReader.isPresent()
        ));
'''
    if text.count(health_anchor) != 1:
        raise RuntimeError("server reachability health anchor mismatch")
    text = text.replace(
        health_anchor,
        health_anchor + '''        health.put("networkReachability", Map.of(
                "importEnabled", networkReachabilityImporter.isPresent(),
                "evidenceReadEnabled", networkReachabilityEvidenceReader.isPresent()
        ));
''',
        1,
    )

    method_marker = "    private static void copyBounded(\n"
    if text.count(method_marker) != 1:
        raise RuntimeError("server reachability method marker mismatch")
    methods = '''    private void readNetworkReachabilityEvidence(HttpExchange exchange) throws IOException {
        NetworkReachabilityEvidenceReader reader = networkReachabilityEvidenceReader.orElseThrow(() ->
                new HttpProblem(
                        503,
                        "NETWORK_REACHABILITY_PERSISTENCE_UNAVAILABLE",
                        "Network reachability evidence reads require PostgreSQL schema version 14 or newer"
                ));
        NetworkReachabilityEvidenceQuery query = parseNetworkReachabilityEvidenceQuery(
                exchange.getRequestURI());
        sendJson(exchange, 200, reader.currentEvidence(
                query.limit(),
                query.assetPrefix(),
                query.sourceProfileKey(),
                query.evidenceSource(),
                query.originScope(),
                query.reachabilityStatus()
        ));
    }

    private void createNetworkReachabilityImport(HttpExchange exchange) throws IOException {
        NetworkReachabilityImporter importer = networkReachabilityImporter.orElseThrow(() ->
                new HttpProblem(
                        503,
                        "NETWORK_REACHABILITY_PERSISTENCE_UNAVAILABLE",
                        "Network reachability import requires PostgreSQL schema version 14 or newer"
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
                    "Network reachability CSV exceeds the configured upload limit"
            );
        }
        Path staged = Files.createTempFile("rbvm-network-reachability-upload-", ".csv");
        try {
            try (InputStream body = exchange.getRequestBody();
                 OutputStream output = Files.newOutputStream(staged)) {
                copyBounded(body, output, maximumUploadBytes, "Network reachability CSV");
            }
            NetworkReachabilityImportResult result = importer.importFile(staged);
            sendJson(exchange, 200, result.toMap());
        } finally {
            Files.deleteIfExists(staged);
        }
    }

'''
    text = text.replace(method_marker, methods + method_marker, 1)

    query_anchor = '''    private static AssetContextEvidenceQuery parseAssetContextEvidenceQuery(URI uri) {
        Map<String, String> query = parseParameters(uri.getRawQuery());
        rejectUnknownFields(query, Set.of("limit", "asset", "sourceProfile", "contextSource"));
        return new AssetContextEvidenceQuery(
                queryLimit(query),
                queryOptional(query, "asset", 160),
                querySourceProfile(query),
                queryOptional(query, "contextSource", 256)
        );
    }
'''
    if text.count(query_anchor) != 1:
        raise RuntimeError("server reachability query anchor mismatch")
    text = text.replace(
        query_anchor,
        query_anchor + '''
    private static NetworkReachabilityEvidenceQuery parseNetworkReachabilityEvidenceQuery(URI uri) {
        Map<String, String> query = parseParameters(uri.getRawQuery());
        rejectUnknownFields(query, Set.of(
                "limit", "asset", "sourceProfile", "evidenceSource",
                "originScope", "reachabilityStatus"));
        return new NetworkReachabilityEvidenceQuery(
                queryLimit(query),
                queryOptional(query, "asset", 160),
                querySourceProfile(query),
                queryOptional(query, "evidenceSource", 256),
                queryEnum(query, "originScope", Set.of(
                        "INTERNET", "EXTERNAL_PARTNER", "INTERNAL_ENTERPRISE",
                        "LOCAL_SEGMENT", "OTHER", "UNKNOWN")),
                queryEnum(query, "reachabilityStatus", Set.of(
                        "REACHABLE", "NOT_REACHABLE", "UNKNOWN"))
        );
    }
''',
        1,
    )

    helper_marker = "    private static String querySourceProfile(Map<String, String> query) {\n"
    if text.count(helper_marker) != 1:
        raise RuntimeError("server reachability enum helper marker mismatch")
    helper = '''    private static String queryEnum(
            Map<String, String> query,
            String field,
            Set<String> allowed
    ) {
        String value = queryOptional(query, field, 64);
        if (value == null) {
            return null;
        }
        value = value.toUpperCase(Locale.ROOT);
        if (!allowed.contains(value)) {
            throw new InvalidCaseActionException(field + " contains an unsupported value");
        }
        return value;
    }

'''
    text = text.replace(helper_marker, helper + helper_marker, 1)

    metrics_anchor = '''                + "# TYPE rbvm_asset_context_evidence_read_enabled gauge\\n"
                + "rbvm_asset_context_evidence_read_enabled " + (assetContextEvidenceReader.isPresent() ? 1 : 0) + "\\n"
'''
    if text.count(metrics_anchor) != 1:
        raise RuntimeError("server reachability metrics anchor mismatch")
    text = text.replace(
        metrics_anchor,
        metrics_anchor + '''                + "# TYPE rbvm_network_reachability_import_enabled gauge\\n"
                + "rbvm_network_reachability_import_enabled " + (networkReachabilityImporter.isPresent() ? 1 : 0) + "\\n"
                + "# TYPE rbvm_network_reachability_evidence_read_enabled gauge\\n"
                + "rbvm_network_reachability_evidence_read_enabled " + (networkReachabilityEvidenceReader.isPresent() ? 1 : 0) + "\\n"
''',
        1,
    )

    main_args = '''                runtime.assetContextImporter(),
                runtime.assetContextEvidenceReader(),
                authenticator,
'''
    if text.count(main_args) != 1:
        raise RuntimeError("server reachability main args anchor mismatch")
    text = text.replace(
        main_args,
        '''                runtime.assetContextImporter(),
                runtime.assetContextEvidenceReader(),
                runtime.networkReachabilityImporter(),
                runtime.networkReachabilityEvidenceReader(),
                authenticator,
''',
        1,
    )
    text = text.replace(
        '        System.out.println("Asset Context operator UI: " + application.baseUri().resolve("/asset-context"));\n',
        '        System.out.println("Asset Context operator UI: " + application.baseUri().resolve("/asset-context"));\n'
        '        System.out.println("Network Reachability operator UI: " + application.baseUri().resolve("/reachability"));\n',
        1,
    )
    text = text.replace(
        '''        System.out.println("Asset Context persistence: "
                + (runtime.assetContextImporter().isPresent() ? "ENABLED" : "DISABLED"));
''',
        '''        System.out.println("Asset Context persistence: "
                + (runtime.assetContextImporter().isPresent() ? "ENABLED" : "DISABLED"));
        System.out.println("Network Reachability persistence: "
                + (runtime.networkReachabilityImporter().isPresent() ? "ENABLED" : "DISABLED"));
''',
        1,
    )

    record_anchor = '''    private record AssetContextEvidenceQuery(
            int limit,
            String assetPrefix,
            String sourceProfileKey,
            String contextSource
    ) {
    }
'''
    if text.count(record_anchor) != 1:
        raise RuntimeError("server reachability query record anchor mismatch")
    text = text.replace(
        record_anchor,
        record_anchor + '''
    private record NetworkReachabilityEvidenceQuery(
            int limit,
            String assetPrefix,
            String sourceProfileKey,
            String evidenceSource,
            String originScope,
            String reachabilityStatus
    ) {
    }
''',
        1,
    )

    path.write_text(text, encoding="utf-8")


def tests_and_web() -> None:
    path = ROOT / "src/test/java/io/rbvm/postgres/PostgresFoundationSelfTest.java"
    text = path.read_text(encoding="utf-8")
    anchor = "        PostgresNetworkReachabilityImporterSelfTest.main(args);\n"
    if text.count(anchor) != 1:
        raise RuntimeError("foundation reachability reader self-test anchor mismatch")
    text = text.replace(
        anchor,
        anchor + "        PostgresNetworkReachabilityEvidenceReaderSelfTest.main(args);\n",
        1,
    )
    path.write_text(text, encoding="utf-8")

    path = ROOT / "src/test/java/io/rbvm/csv/PlatformSelfTest.java"
    text = path.read_text(encoding="utf-8")
    anchor = "        CsvAssetContextHttpSelfTest.main(args);\n"
    if text.count(anchor) != 1:
        raise RuntimeError("platform reachability HTTP test anchor mismatch")
    text = text.replace(anchor, anchor + "        CsvNetworkReachabilityHttpSelfTest.main(args);\n", 1)
    path.write_text(text, encoding="utf-8")

    path = ROOT / "scripts/verify-web.py"
    text = path.read_text(encoding="utf-8")
    anchor = '        (root / "src/main/resources/web/asset-context.html", True),\n'
    if text.count(anchor) != 1:
        raise RuntimeError("web reachability page anchor mismatch")
    text = text.replace(
        anchor,
        anchor + '        (root / "src/main/resources/web/network-reachability.html", True),\n',
        1,
    )
    path.write_text(text, encoding="utf-8")


def main() -> None:
    factory()
    server()
    tests_and_web()
    print("Network Reachability runtime wiring applied")


if __name__ == "__main__":
    main()

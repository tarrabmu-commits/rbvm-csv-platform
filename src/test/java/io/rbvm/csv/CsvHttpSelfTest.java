package io.rbvm.csv;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.security.MessageDigest;
import java.time.Duration;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import io.rbvm.domain.InMemoryDomainCatalog;
import io.rbvm.security.ApiKeyAuthenticator;
import io.rbvm.security.RequestRateLimiter;

public final class CsvHttpSelfTest {
    private static final Pattern IMPORT_ID = Pattern.compile(
            "\\\"importId\\\"\\s*:\\s*\\\"([0-9a-f-]{36})\\\"");
    private static final Pattern CASE_ID = Pattern.compile(
            "\\\"caseId\\\"\\s*:\\s*\\\"([0-9a-f]{64})\\\"");
    private static final Pattern NEXT_CURSOR = Pattern.compile(
            "\\\"nextCursor\\\"\\s*:\\s*\\\"([^\\\"]+)\\\"");

    private CsvHttpSelfTest() {
    }

    public static void main(String[] args) throws Exception {
        uploadPreviewConfirmAndRecover();
        rejectsInvalidRequests();
        acceptsOptInV2ContractHeader();
        enforcesAuthenticationRolesAndAuditIdentity();
        System.out.println("CsvHttpSelfTest: PASS");
    }

    private static void uploadPreviewConfirmAndRecover() throws Exception {
        Path data = Files.createTempDirectory("rbvm-http-self-test-");
        HttpClient client = client();
        String csv = headers()
                + "agent-a,CVE-2025-1234,High,description,pkg-a,https://example.test/1,Ubuntu,2026-07-01T10:15:30Z\r\n";
        String importId;
        String caseId;
        try {
            try (CsvPlatformServer server = server(data, 1024 * 1024)) {
                server.start();
                URI base = server.baseUri();

                HttpResponse<String> page = get(client, base.resolve("/"));
                assert page.statusCode() == 200;
                assert page.body().contains("RBVM CSV");

                HttpResponse<String> health = get(client, base.resolve("/api/v1/health"));
                assert health.statusCode() == 200;
                assert health.body().contains("\"catalogBackend\": \"LOCAL_MEMORY_REBUILD\"");
                assert health.body().contains("\"backend\": \"DISABLED\"");
                assert health.body().contains("\"status\": \"NOT_CONFIGURED\"");

                HttpResponse<String> created = upload(client, base, csv, "create-key-0001");
                assert created.statusCode() == 201 : created.body();
                assert created.headers().firstValue("Location").orElse("").contains("/csv-imports/");
                assert created.body().contains("\"status\": \"PREVIEW_READY\"");
                assert created.body().contains("\"acceptedRows\": 1");
                assert created.body().contains("\"stored\": true");
                assert created.body().contains("\"materialization\": null");
                importId = extractImportId(created.body());

                HttpResponse<String> fetched = get(
                        client,
                        base.resolve("/api/v1/csv-imports/" + importId)
                );
                assert fetched.statusCode() == 200;
                assert fetched.body().contains(importId);

                HttpResponse<String> replay = upload(client, base, csv, "create-key-0001");
                assert replay.statusCode() == 200;
                assert "true".equals(replay.headers().firstValue("Idempotency-Replayed").orElse(null));

                HttpResponse<String> fileReplay = upload(client, base, csv, "create-key-0002");
                assert fileReplay.statusCode() == 200;
                assert fileReplay.body().contains(importId);
                assert "FILE_SHA256".equals(
                        fileReplay.headers().firstValue("RBVM-Replay-Reason").orElse(null));

                HttpResponse<String> confirmed = confirm(client, base, importId, "confirm-key-0001");
                assert confirmed.statusCode() == 200 : confirmed.body();
                assert confirmed.body().contains("\"status\": \"COMPLETED\"");
                assert confirmed.body().contains(
                        "\"commitScope\": \"CANONICAL_DOMAIN_AND_RAW_EVIDENCE\"");
                assert confirmed.body().contains("\"insertedObservations\": 1");
                assert confirmed.body().contains("\"newAssets\": 1");
                assert confirmed.body().contains("\"newCases\": 1");

                HttpResponse<String> catalog = get(client, base.resolve("/api/v1/catalog/summary"));
                assert catalog.statusCode() == 200;
                assert catalog.body().contains("\"observations\": 1");
                assert catalog.body().contains("\"assets\": 1");
                assert catalog.body().contains("\"cases\": 1");
                assert catalog.body().contains("\"autoClosedCases\": 0");

                HttpResponse<String> cases = get(client, base.resolve("/api/v1/cases?limit=10"));
                assert cases.statusCode() == 200;
                assert cases.body().contains("\"cveId\": \"CVE-2025-1234\"");
                assert cases.body().contains("\"status\": \"OPEN\"");

                String expandedCsv = csv
                        + "agent-b,CVE-2025-5678,Medium,description,pkg-b,https://example.test/2,Ubuntu,2026-07-02T10:15:30Z\r\n";
                HttpResponse<String> expanded = upload(
                        client,
                        base,
                        expandedCsv,
                        "create-key-expanded-0001"
                );
                assert expanded.statusCode() == 201 : expanded.body();
                String expandedImportId = extractImportId(expanded.body());
                HttpResponse<String> expandedConfirmed = confirm(
                        client,
                        base,
                        expandedImportId,
                        "confirm-key-expanded-0001"
                );
                assert expandedConfirmed.statusCode() == 200;
                assert expandedConfirmed.body().contains("\"acceptedObservations\": 2");
                assert expandedConfirmed.body().contains("\"insertedObservations\": 1");
                assert expandedConfirmed.body().contains("\"duplicateObservations\": 1");

                HttpResponse<String> expandedCatalog = get(
                        client,
                        base.resolve("/api/v1/catalog/summary")
                );
                assert expandedCatalog.body().contains("\"materializedImports\": 2");
                assert expandedCatalog.body().contains("\"observations\": 2");
                assert expandedCatalog.body().contains("\"importObservationLinks\": 3");
                assert expandedCatalog.body().contains("\"assets\": 2");
                assert expandedCatalog.body().contains("\"cases\": 2");

                HttpResponse<String> firstPage = get(client, base.resolve("/api/v1/cases?limit=1"));
                assert firstPage.statusCode() == 200;
                caseId = extract(CASE_ID, firstPage.body(), "caseId");
                String staleCursor = extract(NEXT_CURSOR, firstPage.body(), "nextCursor");

                HttpResponse<String> detail = get(
                        client,
                        base.resolve("/api/v1/cases/" + caseId)
                );
                assert detail.statusCode() == 200;
                assert detail.body().contains("\"exposures\": [");
                assert detail.body().contains("\"auditEvents\": []");

                HttpResponse<String> acceptedRisk = caseAction(
                        client,
                        base,
                        caseId,
                        "case-action-key-0001",
                        "action=ACCEPT_RISK&reason=Temporary+exception&expiresAt=2099-08-20T12%3A00%3A00Z"
                );
                assert acceptedRisk.statusCode() == 200 : acceptedRisk.body();
                assert acceptedRisk.body().contains("\"status\": \"ACCEPTED_RISK\"");
                assert acceptedRisk.body().contains("\"actorAssurance\": \"UNAUTHENTICATED_LOCAL\"");
                assert acceptedRisk.body().contains("\"workflowVersion\": 1");

                HttpResponse<String> actionReplay = caseAction(
                        client,
                        base,
                        caseId,
                        "case-action-key-0001",
                        "action=ACCEPT_RISK&reason=Temporary+exception&expiresAt=2099-08-20T12%3A00%3A00Z"
                );
                assert actionReplay.statusCode() == 200;
                assert "true".equals(
                        actionReplay.headers().firstValue("Idempotency-Replayed").orElse(null));

                HttpResponse<String> actionConflict = caseAction(
                        client,
                        base,
                        caseId,
                        "case-action-key-0001",
                        "action=ACCEPT_RISK&reason=Different+request&expiresAt=2099-09-20T12%3A00%3A00Z"
                );
                assert actionConflict.statusCode() == 409 : actionConflict.body();

                HttpResponse<String> stalePage = get(
                        client,
                        base.resolve("/api/v1/cases?limit=1&cursor=" + staleCursor)
                );
                assert stalePage.statusCode() == 409 : stalePage.body();

                HttpResponse<String> acceptedFilter = get(
                        client,
                        base.resolve("/api/v1/cases?status=ACCEPTED_RISK&limit=10")
                );
                assert acceptedFilter.statusCode() == 200;
                assert acceptedFilter.body().contains(caseId);
                assert acceptedFilter.body().contains("\"caseStatusDistribution\"");

                HttpResponse<String> confirmReplay = confirm(client, base, importId, "confirm-key-0002");
                assert confirmReplay.statusCode() == 200;
                assert "true".equals(
                        confirmReplay.headers().firstValue("Idempotency-Replayed").orElse(null));
            }

            try (CsvPlatformServer recovered = server(data, 1024 * 1024)) {
                recovered.start();
                HttpResponse<String> fetched = get(
                        client,
                        recovered.baseUri().resolve("/api/v1/csv-imports/" + importId)
                );
                assert fetched.statusCode() == 200 : fetched.body();
                assert fetched.body().contains("\"status\": \"COMPLETED\"");
                assert fetched.body().contains("\"acceptedRows\": 1");
                assert fetched.body().contains("\"insertedObservations\": 1");

                HttpResponse<String> catalog = get(
                        client,
                        recovered.baseUri().resolve("/api/v1/catalog/summary")
                );
                assert catalog.body().contains("\"materializedImports\": 2");
                assert catalog.body().contains("\"observations\": 2");
                assert catalog.body().contains("\"importObservationLinks\": 3");
                assert catalog.body().contains("\"cases\": 2");
                assert catalog.body().contains("\"openCases\": 1");
                assert catalog.body().contains("\"ACCEPTED_RISK\": 1");

                HttpResponse<String> recoveredCase = get(
                        client,
                        recovered.baseUri().resolve("/api/v1/cases/" + caseId)
                );
                assert recoveredCase.statusCode() == 200;
                assert recoveredCase.body().contains("\"status\": \"ACCEPTED_RISK\"");
                assert recoveredCase.body().contains("\"workflowVersion\": 1");
                assert recoveredCase.body().contains("\"action\": \"ACCEPT_RISK\"");
            }
        } finally {
            deleteTree(data);
        }
    }

    private static void rejectsInvalidRequests() throws Exception {
        Path data = Files.createTempDirectory("rbvm-http-rejections-");
        HttpClient client = client();
        try (CsvPlatformServer server = server(data, 240)) {
            server.start();
            URI base = server.baseUri();

            HttpRequest missingHeaders = HttpRequest.newBuilder(base.resolve("/api/v1/csv-imports"))
                    .timeout(Duration.ofSeconds(10))
                    .header("Content-Type", "text/csv")
                    .POST(HttpRequest.BodyPublishers.ofString(headers()))
                    .build();
            HttpResponse<String> missingResponse = client.send(
                    missingHeaders,
                    HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8)
            );
            assert missingResponse.statusCode() == 400 : missingResponse.body();

            String invalid = headers()
                    + "agent-a,CVE-bad,High,description,pkg-a,https://example.test/1,Ubuntu,2026-07-01T10:15:30Z\r\n";
            HttpResponse<String> invalidResponse = upload(client, base, invalid, "invalid-key-0001");
            assert invalidResponse.statusCode() == 201 : invalidResponse.body();
            assert invalidResponse.body().contains("\"quarantinedRows\": 1");

            String tooLarge = headers() + "x".repeat(400);
            HttpResponse<String> largeResponse = upload(client, base, tooLarge, "large-key-000001");
            assert largeResponse.statusCode() == 413 : largeResponse.body();

            HttpRequest wrongType = HttpRequest.newBuilder(base.resolve("/api/v1/csv-imports"))
                    .timeout(Duration.ofSeconds(10))
                    .header("Content-Type", "application/json")
                    .header("X-Source-Profile-Id", "test-profile")
                    .header("Idempotency-Key", "wrong-type-0001")
                    .POST(HttpRequest.BodyPublishers.ofString("{}"))
                    .build();
            HttpResponse<String> wrongTypeResponse = client.send(
                    wrongType,
                    HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8)
            );
            assert wrongTypeResponse.statusCode() == 415 : wrongTypeResponse.body();

            HttpResponse<String> invalidLimit = get(client, base.resolve("/api/v1/cases?limit=101"));
            assert invalidLimit.statusCode() == 400 : invalidLimit.body();
        } finally {
            deleteTree(data);
        }
    }

    private static void acceptsOptInV2ContractHeader() throws Exception {
        Path data = Files.createTempDirectory("rbvm-http-v2-");
        HttpClient client = client();
        String csv = "Agent,Agent_ID,CVE_ID,Severity,CVE_Description,Affected_Product,"
                + "Package_Version,Package_Architecture,References,OS_name,Finding_Status,"
                + "Detected_At,Resolved_At\r\n"
                + "agent,agent-1,CVE-2026-9999,High,description,pkg,1.2.3,amd64,"
                + "https://example.test/v2,Ubuntu,RESOLVED,2026-08-01T10:00:00Z,"
                + "2026-08-02T10:00:00Z\r\n";
        try (CsvPlatformServer server = server(data, 1024 * 1024)) {
            server.start();
            HttpRequest request = HttpRequest.newBuilder(
                            server.baseUri().resolve("/api/v1/csv-imports"))
                    .timeout(Duration.ofSeconds(10))
                    .header("Content-Type", "text/csv")
                    .header("X-Source-Profile-Id", "v2-http-profile")
                    .header("X-CSV-Contract", "WAZUH_CSV_V2")
                    .header("Idempotency-Key", "v2-http-create-0001")
                    .POST(HttpRequest.BodyPublishers.ofString(csv, StandardCharsets.UTF_8))
                    .build();
            HttpResponse<String> created = client.send(
                    request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            assert created.statusCode() == 201 : created.body();
            assert created.body().contains("\"contractId\": \"WAZUH_CSV_V2\"");
            assert created.body().contains("\"resolvedRows\": 1");
            String importId = extractImportId(created.body());
            HttpResponse<String> confirmed = confirm(
                    client, server.baseUri(), importId, "v2-http-confirm-0001");
            assert confirmed.statusCode() == 200 : confirmed.body();
            HttpResponse<String> cases = get(
                    client, server.baseUri().resolve("/api/v1/cases?status=SOURCE_RESOLVED"));
            assert cases.statusCode() == 200;
            assert cases.body().contains("\"status\": \"SOURCE_RESOLVED\"");
            assert cases.body().contains("\"vulnerabilityIntelligence\"");
            assert cases.body().contains("\"unenrichedVulnerabilities\": 1");
            assert cases.body().contains("\"freshnessWindowHours\": 168");
        } finally {
            deleteTree(data);
        }
    }

    private static void enforcesAuthenticationRolesAndAuditIdentity() throws Exception {
        Path data = Files.createTempDirectory("rbvm-http-auth-");
        String viewerToken = "viewer-token-abcdefghijklmnopqrstuvwxyz-123456";
        String operatorToken = "operator-token-abcdefghijklmnopqrstuvwxyz-123";
        Path registry = data.resolve("api-keys.conf");
        Files.writeString(registry,
                digest(viewerToken) + "=security-viewer|VIEWER\n"
                        + digest(operatorToken) + "=soc-operator@example.test|OPERATOR\n",
                StandardCharsets.UTF_8);
        try {
            Files.setPosixFilePermissions(registry, Set.of(
                    PosixFilePermission.OWNER_READ,
                    PosixFilePermission.OWNER_WRITE
            ));
        } catch (UnsupportedOperationException ignored) {
            // The authenticator defers to platform ACLs on non-POSIX filesystems.
        }
        HttpClient client = client();
        try (CsvPlatformServer server = new CsvPlatformServer(
                "127.0.0.1", 0, data.resolve("evidence"), 1024 * 1024,
                new NoopCanonicalProjection(), new InMemoryDomainCatalog(),
                ApiKeyAuthenticator.fromFile(registry),
                RequestRateLimiter.configured(100, 2, Clock.fixed(
                        Instant.parse("2026-08-14T10:00:30Z"), ZoneOffset.UTC)))) {
            server.start();
            URI base = server.baseUri();

            HttpResponse<String> missing = get(client, base.resolve("/api/v1/cases"));
            assert missing.statusCode() == 401 : missing.body();
            assert missing.headers().firstValue("WWW-Authenticate").orElse("")
                    .startsWith("Bearer");

            HttpResponse<String> invalid = authorizedGet(
                    client, base.resolve("/api/v1/cases"), "invalid-secret-that-must-not-leak-123456");
            assert invalid.statusCode() == 401 : invalid.body();
            assert !invalid.body().contains("invalid-secret");

            HttpResponse<String> throttled = get(client, base.resolve("/api/v1/cases"));
            assert throttled.statusCode() == 429 : throttled.body();
            assert throttled.headers().firstValue("Retry-After").orElse("").equals("30");

            HttpResponse<String> publicReadiness = get(client, base.resolve("/api/v1/ready"));
            assert publicReadiness.statusCode() == 200 : publicReadiness.body();
            assert publicReadiness.body().contains("\"status\": \"UP\"");
            assert !publicReadiness.body().contains("observations");

            HttpResponse<String> protectedHealthMissing = get(
                    client, base.resolve("/api/v1/health"));
            assert protectedHealthMissing.statusCode() == 429 : protectedHealthMissing.body();
            HttpResponse<String> protectedHealth = authorizedGet(
                    client, base.resolve("/api/v1/health"), viewerToken);
            assert protectedHealth.statusCode() == 200 : protectedHealth.body();

            HttpResponse<String> allowedRead = authorizedGet(
                    client, base.resolve("/api/v1/cases"), viewerToken);
            assert allowedRead.statusCode() == 200 : allowedRead.body();

            HttpResponse<String> deniedWrite = authorizedUpload(
                    client, base, headers(), "viewer-denied-0001", viewerToken);
            assert deniedWrite.statusCode() == 403 : deniedWrite.body();

            String csv = headers()
                    + "agent-auth,CVE-2026-9001,High,description,pkg-auth,"
                    + "https://example.test/auth,Ubuntu,2026-08-01T10:15:30Z\r\n";
            HttpResponse<String> created = authorizedUpload(
                    client, base, csv, "operator-create-0001", operatorToken);
            assert created.statusCode() == 201 : created.body();
            String importId = extractImportId(created.body());
            HttpResponse<String> confirmed = authorizedPost(
                    client,
                    base.resolve("/api/v1/csv-imports/" + importId + "/confirm"),
                    "operator-confirm-0001", null, operatorToken);
            assert confirmed.statusCode() == 200 : confirmed.body();

            HttpResponse<String> cases = authorizedGet(
                    client, base.resolve("/api/v1/cases?limit=1"), operatorToken);
            String caseId = extract(CASE_ID, cases.body(), "caseId");
            HttpResponse<String> action = authorizedPost(
                    client,
                    base.resolve("/api/v1/cases/" + caseId + "/actions"),
                    "operator-action-0001",
                    "action=COMMENT&reason=Authenticated+decision",
                    operatorToken);
            assert action.statusCode() == 200 : action.body();
            assert action.body().contains("\"actorId\": \"soc-operator@example.test\"");
            assert action.body().contains("\"actorAssurance\": \"API_KEY_SHA256\"");
        } finally {
            deleteTree(data);
        }
    }

    private static CsvPlatformServer server(Path data, long maxBytes) throws IOException {
        return new CsvPlatformServer("127.0.0.1", 0, data, maxBytes);
    }

    private static HttpClient client() {
        return HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(10))
                .build();
    }

    private static HttpResponse<String> upload(
            HttpClient client,
            URI base,
            String csv,
            String idempotencyKey
    ) throws IOException, InterruptedException {
        HttpRequest request = HttpRequest.newBuilder(base.resolve("/api/v1/csv-imports"))
                .timeout(Duration.ofSeconds(10))
                .header("Content-Type", "text/csv; charset=utf-8")
                .header("X-Source-Profile-Id", "test-profile")
                .header("Idempotency-Key", idempotencyKey)
                .POST(HttpRequest.BodyPublishers.ofString(csv, StandardCharsets.UTF_8))
                .build();
        return client.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
    }

    private static HttpResponse<String> confirm(
            HttpClient client,
            URI base,
            String importId,
            String idempotencyKey
    ) throws IOException, InterruptedException {
        HttpRequest request = HttpRequest.newBuilder(
                        base.resolve("/api/v1/csv-imports/" + importId + "/confirm"))
                .timeout(Duration.ofSeconds(10))
                .header("Idempotency-Key", idempotencyKey)
                .POST(HttpRequest.BodyPublishers.noBody())
                .build();
        return client.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
    }

    private static HttpResponse<String> caseAction(
            HttpClient client,
            URI base,
            String caseId,
            String idempotencyKey,
            String form
    ) throws IOException, InterruptedException {
        HttpRequest request = HttpRequest.newBuilder(
                        base.resolve("/api/v1/cases/" + caseId + "/actions"))
                .timeout(Duration.ofSeconds(10))
                .header("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
                .header("Idempotency-Key", idempotencyKey)
                .POST(HttpRequest.BodyPublishers.ofString(form, StandardCharsets.UTF_8))
                .build();
        return client.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
    }

    private static HttpResponse<String> get(HttpClient client, URI uri)
            throws IOException, InterruptedException {
        HttpRequest request = HttpRequest.newBuilder(uri)
                .timeout(Duration.ofSeconds(10))
                .GET()
                .build();
        return client.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
    }

    private static HttpResponse<String> authorizedGet(HttpClient client, URI uri, String token)
            throws IOException, InterruptedException {
        HttpRequest request = HttpRequest.newBuilder(uri)
                .timeout(Duration.ofSeconds(10))
                .header("Authorization", "Bearer " + token)
                .GET()
                .build();
        return client.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
    }

    private static HttpResponse<String> authorizedUpload(
            HttpClient client, URI base, String csv, String idempotencyKey, String token)
            throws IOException, InterruptedException {
        HttpRequest request = HttpRequest.newBuilder(base.resolve("/api/v1/csv-imports"))
                .timeout(Duration.ofSeconds(10))
                .header("Authorization", "Bearer " + token)
                .header("Content-Type", "text/csv; charset=utf-8")
                .header("X-Source-Profile-Id", "test-profile")
                .header("Idempotency-Key", idempotencyKey)
                .POST(HttpRequest.BodyPublishers.ofString(csv, StandardCharsets.UTF_8))
                .build();
        return client.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
    }

    private static HttpResponse<String> authorizedPost(
            HttpClient client, URI uri, String idempotencyKey, String form, String token)
            throws IOException, InterruptedException {
        HttpRequest.Builder request = HttpRequest.newBuilder(uri)
                .timeout(Duration.ofSeconds(10))
                .header("Authorization", "Bearer " + token)
                .header("Idempotency-Key", idempotencyKey);
        if (form == null) {
            request.POST(HttpRequest.BodyPublishers.noBody());
        } else {
            request.header("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
                    .POST(HttpRequest.BodyPublishers.ofString(form, StandardCharsets.UTF_8));
        }
        return client.send(request.build(),
                HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
    }

    private static String digest(String token) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                .digest(token.getBytes(StandardCharsets.UTF_8)));
    }

    private static String extractImportId(String body) {
        return extract(IMPORT_ID, body, "importId");
    }

    private static String extract(Pattern pattern, String body, String field) {
        Matcher matcher = pattern.matcher(body);
        if (!matcher.find()) {
            throw new AssertionError("Response has no " + field + ": " + body);
        }
        return matcher.group(1);
    }

    private static String headers() {
        return "Agent,CVE_ID,Severity,CVE_Description,Affected_Product,References,OS_name,Detected_At\r\n";
    }

    private static void deleteTree(Path root) throws IOException {
        if (!Files.exists(root)) {
            return;
        }
        try (Stream<Path> paths = Files.walk(root)) {
            for (Path path : paths.sorted(Comparator.reverseOrder()).toList()) {
                Files.deleteIfExists(path);
            }
        }
    }
}

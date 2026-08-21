package io.rbvm.csv;

import io.rbvm.domain.InMemoryDomainCatalog;
import io.rbvm.postgres.AssetContextEvidenceReader;
import io.rbvm.postgres.AssetContextImportResult;
import io.rbvm.postgres.AssetContextImporter;
import io.rbvm.security.ApiKeyAuthenticator;
import io.rbvm.security.RequestRateLimiter;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Optional;

public final class CsvAssetContextHttpSelfTest {
    private CsvAssetContextHttpSelfTest() {
    }

    public static void main(String[] args) throws Exception {
        exposesAssetContextImportCurrentEvidenceAndUi();
        reportsAssetContextCapabilityAsUnavailableWithoutPostgresV13();
        System.out.println("CsvAssetContextHttpSelfTest: PASS");
    }

    private static void exposesAssetContextImportCurrentEvidenceAndUi() throws Exception {
        Path data = Files.createTempDirectory("rbvm-asset-context-http-");
        HttpClient client = client();
        AssetContextImporter importer = path -> {
            String body = Files.readString(path, StandardCharsets.UTF_8);
            assert body.contains("web-01");
            AssetContextCsvAnalysisReport analysis = new AssetContextCsvAnalysisReport(
                    AssetContextCsvContract.ID,
                    AssetContextCsvContract.SEMANTICS,
                    AssetContextCsvContract.HEADERS,
                    List.of(),
                    1,
                    1,
                    0,
                    0,
                    Map.of("PRODUCTION", 1L),
                    Map.of("MISSION_CRITICAL", 1L),
                    List.of(),
                    List.of()
            );
            return new AssetContextImportResult(analysis, 1, 0, 0, 1, 0, 0, List.of());
        };
        AssetContextEvidenceReader reader = (limit, assetPrefix, sourceProfileKey, contextSource) -> {
            assert limit == 50;
            assert "web-".equals(assetPrefix);
            assert "wazuh-primary".equals(sourceProfileKey);
            assert "CMDB inventory export".equals(contextSource);
            return Map.of(
                    "semantics", "CURRENT_PER_SOURCE_ASSET_ORGANIZATIONAL_CONTEXT_EVIDENCE",
                    "limit", limit,
                    "assetPrefix", assetPrefix,
                    "sourceProfileKey", sourceProfileKey,
                    "contextSource", contextSource,
                    "count", 1,
                    "items", List.of(Map.ofEntries(
                            Map.entry("sourceProfileKey", "wazuh-primary"),
                            Map.entry("assetIdentityBasis", "SOURCE_NAME_ONLY"),
                            Map.entry("assetName", "web-01"),
                            Map.entry("assetSourceId", ""),
                            Map.entry("environment", "PRODUCTION"),
                            Map.entry("businessService", "Checkout"),
                            Map.entry("businessOwner", "Payments Team"),
                            Map.entry("businessCriticality", "MISSION_CRITICAL"),
                            Map.entry("contextSource", "CMDB inventory export"),
                            Map.entry("contextSourceSha256", "a".repeat(64)),
                            Map.entry("contextObservedAt", "2026-08-19T09:00:00Z"),
                            Map.entry("evidenceIngestedAt", "2026-08-19T09:01:00Z"),
                            Map.entry("snapshotIngestedAt", "2026-08-19T09:01:00Z")
                    ))
            );
        };

        try (CsvPlatformServer server = new CsvPlatformServer(
                "127.0.0.1",
                0,
                data,
                1024 * 1024,
                new NoopCanonicalProjection(),
                new InMemoryDomainCatalog(),
                Optional.empty(),
                Optional.empty(),
                Optional.empty(),
                Optional.empty(),
                Optional.empty(),
                Optional.empty(),
                Optional.empty(),
                Optional.empty(),
                Optional.of(importer),
                Optional.of(reader),
                ApiKeyAuthenticator.disabled(),
                RequestRateLimiter.disabled()
        )) {
            server.start();
            URI base = server.baseUri();

            HttpResponse<String> ui = get(client, base.resolve("/asset-context"));
            assert ui.statusCode() == 200 : ui.body();
            assert ui.body().contains("<html lang=\"en\" dir=\"ltr\">");
            assert ui.body().contains("id=\"rbvm-app\"");
            assert ui.body().contains("/ui/rbvm-ui.js");

            HttpResponse<String> health = get(client, base.resolve("/api/v1/health"));
            assert health.statusCode() == 200 : health.body();
            assert health.body().contains("\"assetContext\"");
            assert health.body().contains("\"evidenceReadEnabled\": true");

            HttpResponse<String> evidence = get(
                    client,
                    base.resolve("/api/v1/asset-context-evidence?limit=50&asset=web-&sourceProfile=wazuh-primary&contextSource=CMDB%20inventory%20export")
            );
            assert evidence.statusCode() == 200 : evidence.body();
            assert evidence.body().contains("CURRENT_PER_SOURCE_ASSET_ORGANIZATIONAL_CONTEXT_EVIDENCE");
            assert evidence.body().contains("\"assetName\": \"web-01\"");
            assert evidence.body().contains("\"environment\": \"PRODUCTION\"");
            assert evidence.body().contains("\"businessService\": \"Checkout\"");
            assert evidence.body().contains("\"businessCriticality\": \"MISSION_CRITICAL\"");
            assert evidence.body().contains("\"contextSource\": \"CMDB inventory export\"");

            HttpResponse<String> invalidProfile = get(
                    client,
                    base.resolve("/api/v1/asset-context-evidence?sourceProfile=bad%20profile!")
            );
            assert invalidProfile.statusCode() == 400 : invalidProfile.body();
            HttpResponse<String> invalidLimit = get(
                    client,
                    base.resolve("/api/v1/asset-context-evidence?limit=501")
            );
            assert invalidLimit.statusCode() == 400 : invalidLimit.body();

            String csv = "Source_Profile_Key,Asset_Identity_Basis,Asset_Name,Asset_Source_ID,Environment,Business_Service,Business_Owner,Business_Criticality,Context_Source,Context_Observed_At,Context_Source_SHA256\r\n"
                    + "wazuh-primary,SOURCE_NAME_ONLY,web-01,,PRODUCTION,Checkout,Payments Team,MISSION_CRITICAL,CMDB inventory export,2026-08-19T09:00:00Z,"
                    + "a".repeat(64) + "\r\n";
            HttpRequest request = HttpRequest.newBuilder(base.resolve("/api/v1/asset-context-imports"))
                    .timeout(Duration.ofSeconds(10))
                    .header("Content-Type", "text/csv; charset=utf-8")
                    .POST(HttpRequest.BodyPublishers.ofString(csv, StandardCharsets.UTF_8))
                    .build();
            HttpResponse<String> imported = client.send(
                    request,
                    HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8)
            );
            assert imported.statusCode() == 200 : imported.body();
            assert imported.body().contains("\"contractId\": \"ASSET_CONTEXT_CSV_V1\"");
            assert imported.body().contains("\"insertedEvidence\": 1");
            assert imported.body().contains("\"insertedSnapshots\": 1");
            assert imported.body().contains("\"totalQuarantinedRows\": 0");

            HttpRequest wrongType = HttpRequest.newBuilder(base.resolve("/api/v1/asset-context-imports"))
                    .timeout(Duration.ofSeconds(10))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString("{}"))
                    .build();
            HttpResponse<String> rejected = client.send(
                    wrongType,
                    HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8)
            );
            assert rejected.statusCode() == 415 : rejected.body();
        } finally {
            deleteTree(data);
        }
    }

    private static void reportsAssetContextCapabilityAsUnavailableWithoutPostgresV13()
            throws Exception {
        Path data = Files.createTempDirectory("rbvm-asset-context-disabled-");
        HttpClient client = client();
        try (CsvPlatformServer server = new CsvPlatformServer(
                "127.0.0.1", 0, data, 1024 * 1024)) {
            server.start();
            URI base = server.baseUri();
            HttpResponse<String> health = get(client, base.resolve("/api/v1/health"));
            assert health.body().contains("\"assetContext\"");
            assert health.body().contains("\"evidenceReadEnabled\": false");

            HttpResponse<String> readUnavailable = get(
                    client,
                    base.resolve("/api/v1/asset-context-evidence")
            );
            assert readUnavailable.statusCode() == 503 : readUnavailable.body();

            HttpRequest request = HttpRequest.newBuilder(base.resolve("/api/v1/asset-context-imports"))
                    .timeout(Duration.ofSeconds(10))
                    .header("Content-Type", "text/csv")
                    .POST(HttpRequest.BodyPublishers.ofString(
                            "Source_Profile_Key,Asset_Identity_Basis,Asset_Name,Asset_Source_ID,Environment,Business_Service,Business_Owner,Business_Criticality,Context_Source,Context_Observed_At,Context_Source_SHA256\r\n"))
                    .build();
            HttpResponse<String> unavailable = client.send(
                    request,
                    HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8)
            );
            assert unavailable.statusCode() == 503 : unavailable.body();
            assert unavailable.body().contains("ASSET CONTEXT PERSISTENCE UNAVAILABLE");
        } finally {
            deleteTree(data);
        }
    }

    private static HttpClient client() {
        return HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build();
    }

    private static HttpResponse<String> get(HttpClient client, URI uri) throws Exception {
        return client.send(
                HttpRequest.newBuilder(uri).timeout(Duration.ofSeconds(10)).GET().build(),
                HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8)
        );
    }

    private static void deleteTree(Path root) throws Exception {
        if (!Files.exists(root)) return;
        try (var paths = Files.walk(root)) {
            paths.sorted(java.util.Comparator.reverseOrder()).forEach(path -> {
                try {
                    Files.deleteIfExists(path);
                } catch (java.io.IOException exception) {
                    throw new RuntimeException(exception);
                }
            });
        }
    }
}

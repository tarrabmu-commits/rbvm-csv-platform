package io.rbvm.csv;

import io.rbvm.domain.InMemoryDomainCatalog;
import io.rbvm.postgres.BusinessImpactEvidenceReader;
import io.rbvm.postgres.BusinessImpactImportResult;
import io.rbvm.postgres.BusinessImpactImporter;
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

public final class CsvBusinessImpactHttpSelfTest {
    private CsvBusinessImpactHttpSelfTest() {
    }

    public static void main(String[] args) throws Exception {
        exposesBusinessImpactImportCurrentEvidenceAndUi();
        reportsBusinessImpactCapabilityAsUnavailableWithoutPostgresV15();
        System.out.println("CsvBusinessImpactHttpSelfTest: PASS");
    }

    private static void exposesBusinessImpactImportCurrentEvidenceAndUi() throws Exception {
        Path data = Files.createTempDirectory("rbvm-business-impact-http-");
        HttpClient client = client();
        BusinessImpactImporter importer = path -> {
            String body = Files.readString(path, StandardCharsets.UTF_8);
            assert body.contains("Checkout");
            BusinessImpactCsvAnalysisReport analysis = new BusinessImpactCsvAnalysisReport(
                    BusinessImpactCsvContract.ID,
                    BusinessImpactCsvContract.SEMANTICS,
                    BusinessImpactCsvContract.HEADERS,
                    List.of(),
                    1,
                    1,
                    0,
                    0,
                    Map.of("MISSION", 1L),
                    Map.of("SEVERE", 1L),
                    Map.of("BUSINESS_IMPACT_ANALYSIS", 1L),
                    List.of(),
                    List.of()
            );
            return new BusinessImpactImportResult(
                    analysis, 1, 0, 0, 1, 0, 0, List.of());
        };
        BusinessImpactEvidenceReader reader = (
                limit, assetPrefix, sourceProfileKey, service, impactSource, dimension, level) -> {
            assert limit == 50;
            assert "web-".equals(assetPrefix);
            assert "wazuh-primary".equals(sourceProfileKey);
            assert "checkout".equals(service);
            assert "bia-2026".equals(impactSource);
            assert "MISSION".equals(dimension);
            assert "SEVERE".equals(level);
            return Map.of(
                    "semantics", "CURRENT_PER_SOURCE_ASSET_SERVICE_BUSINESS_MISSION_IMPACT_EVIDENCE",
                    "limit", limit,
                    "assetPrefix", assetPrefix,
                    "sourceProfileKey", sourceProfileKey,
                    "businessService", service,
                    "impactSource", impactSource,
                    "impactDimension", dimension,
                    "impactLevel", level,
                    "count", 1,
                    "items", List.of(Map.ofEntries(
                            Map.entry("sourceProfileKey", "wazuh-primary"),
                            Map.entry("assetIdentityBasis", "SOURCE_NAME_ONLY"),
                            Map.entry("assetName", "web-01"),
                            Map.entry("assetSourceId", ""),
                            Map.entry("businessService", "Checkout"),
                            Map.entry("impactDimension", "MISSION"),
                            Map.entry("impactLevel", "SEVERE"),
                            Map.entry("impactMethod", "BUSINESS_IMPACT_ANALYSIS"),
                            Map.entry("impactStatement", "Checkout outage stops order intake"),
                            Map.entry("impactSource", "bia-2026"),
                            Map.entry("impactSourceSha256", "a".repeat(64)),
                            Map.entry("impactObservedAt", "2026-08-19T09:00:00Z"),
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
                Optional.empty(), Optional.empty(),
                Optional.empty(), Optional.empty(),
                Optional.empty(), Optional.empty(),
                Optional.empty(), Optional.empty(),
                Optional.empty(), Optional.empty(),
                Optional.empty(), Optional.empty(),
                Optional.of(importer), Optional.of(reader),
                ApiKeyAuthenticator.disabled(),
                RequestRateLimiter.disabled()
        )) {
            server.start();
            URI base = server.baseUri();

            HttpResponse<String> ui = get(client, base.resolve("/business-impact"));
            assert ui.statusCode() == 200 : ui.body();
            assert ui.body().contains("BUSINESS_IMPACT_CSV_V1");
            assert ui.body().contains("SEVERE/HIGH/...");
            assert ui.body().contains("ما في mapping تلقائي بين MISSION_CRITICAL وSEVERE");
            assert !ui.body().contains("riskScore");
            assert !ui.body().contains("priorityTier");
            assert !ui.body().contains("impactWeight");

            HttpResponse<String> health = get(client, base.resolve("/api/v1/health"));
            assert health.statusCode() == 200 : health.body();
            assert health.body().contains("\"businessImpact\"");
            assert health.body().contains("\"evidenceReadEnabled\": true");

            HttpResponse<String> evidence = get(
                    client,
                    base.resolve("/api/v1/business-impact-evidence?limit=50&asset=web-&sourceProfile=wazuh-primary&businessService=checkout&impactSource=bia-2026&impactDimension=MISSION&impactLevel=SEVERE")
            );
            assert evidence.statusCode() == 200 : evidence.body();
            assert evidence.body().contains("CURRENT_PER_SOURCE_ASSET_SERVICE_BUSINESS_MISSION_IMPACT_EVIDENCE");
            assert evidence.body().contains("\"assetName\": \"web-01\"");
            assert evidence.body().contains("\"businessService\": \"Checkout\"");
            assert evidence.body().contains("\"impactDimension\": \"MISSION\"");
            assert evidence.body().contains("\"impactLevel\": \"SEVERE\"");
            assert evidence.body().contains("\"impactSource\": \"bia-2026\"");

            HttpResponse<String> invalidDimension = get(
                    client,
                    base.resolve("/api/v1/business-impact-evidence?impactDimension=IMPACT")
            );
            assert invalidDimension.statusCode() == 400 : invalidDimension.body();
            HttpResponse<String> invalidLevel = get(
                    client,
                    base.resolve("/api/v1/business-impact-evidence?impactLevel=CRITICAL")
            );
            assert invalidLevel.statusCode() == 400 : invalidLevel.body();
            HttpResponse<String> invalidLimit = get(
                    client,
                    base.resolve("/api/v1/business-impact-evidence?limit=501")
            );
            assert invalidLimit.statusCode() == 400 : invalidLimit.body();

            String csv = "Source_Profile_Key,Asset_Identity_Basis,Asset_Name,Asset_Source_ID,Business_Service,Impact_Dimension,Impact_Level,Impact_Method,Impact_Statement,Impact_Source,Impact_Observed_At,Impact_Source_SHA256\r\n"
                    + "wazuh-primary,SOURCE_NAME_ONLY,web-01,,Checkout,MISSION,SEVERE,BUSINESS_IMPACT_ANALYSIS,Checkout outage stops order intake,bia-2026,2026-08-19T09:00:00Z,"
                    + "a".repeat(64) + "\r\n";
            HttpRequest request = HttpRequest.newBuilder(
                            base.resolve("/api/v1/business-impact-imports"))
                    .timeout(Duration.ofSeconds(10))
                    .header("Content-Type", "text/csv; charset=utf-8")
                    .POST(HttpRequest.BodyPublishers.ofString(csv, StandardCharsets.UTF_8))
                    .build();
            HttpResponse<String> imported = client.send(
                    request,
                    HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8)
            );
            assert imported.statusCode() == 200 : imported.body();
            assert imported.body().contains("\"contractId\": \"BUSINESS_IMPACT_CSV_V1\"");
            assert imported.body().contains("\"insertedEvidence\": 1");
            assert imported.body().contains("\"insertedSnapshots\": 1");
            assert imported.body().contains("\"totalQuarantinedRows\": 0");

            HttpRequest wrongType = HttpRequest.newBuilder(
                            base.resolve("/api/v1/business-impact-imports"))
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

    private static void reportsBusinessImpactCapabilityAsUnavailableWithoutPostgresV15()
            throws Exception {
        Path data = Files.createTempDirectory("rbvm-business-impact-disabled-");
        HttpClient client = client();
        try (CsvPlatformServer server = new CsvPlatformServer(
                "127.0.0.1", 0, data, 1024 * 1024)) {
            server.start();
            URI base = server.baseUri();
            HttpResponse<String> health = get(client, base.resolve("/api/v1/health"));
            assert health.body().contains("\"businessImpact\"");
            assert health.body().contains("\"evidenceReadEnabled\": false");

            HttpResponse<String> readUnavailable = get(
                    client,
                    base.resolve("/api/v1/business-impact-evidence")
            );
            assert readUnavailable.statusCode() == 503 : readUnavailable.body();

            HttpRequest request = HttpRequest.newBuilder(
                            base.resolve("/api/v1/business-impact-imports"))
                    .timeout(Duration.ofSeconds(10))
                    .header("Content-Type", "text/csv")
                    .POST(HttpRequest.BodyPublishers.ofString(
                            "Source_Profile_Key,Asset_Identity_Basis,Asset_Name,Asset_Source_ID,Business_Service,Impact_Dimension,Impact_Level,Impact_Method,Impact_Statement,Impact_Source,Impact_Observed_At,Impact_Source_SHA256\r\n"))
                    .build();
            HttpResponse<String> unavailable = client.send(
                    request,
                    HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8)
            );
            assert unavailable.statusCode() == 503 : unavailable.body();
            assert unavailable.body().contains("BUSINESS IMPACT PERSISTENCE UNAVAILABLE");
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

package io.rbvm.csv;

import io.rbvm.domain.InMemoryDomainCatalog;
import io.rbvm.postgres.NetworkReachabilityEvidenceReader;
import io.rbvm.postgres.NetworkReachabilityImportResult;
import io.rbvm.postgres.NetworkReachabilityImporter;
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

public final class CsvNetworkReachabilityHttpSelfTest {
    private CsvNetworkReachabilityHttpSelfTest() {
    }

    public static void main(String[] args) throws Exception {
        exposesReachabilityImportCurrentEvidenceAndUi();
        reportsReachabilityCapabilityAsUnavailableWithoutPostgresV14();
        System.out.println("CsvNetworkReachabilityHttpSelfTest: PASS");
    }

    private static void exposesReachabilityImportCurrentEvidenceAndUi() throws Exception {
        Path data = Files.createTempDirectory("rbvm-reachability-http-");
        HttpClient client = client();
        NetworkReachabilityImporter importer = path -> {
            String body = Files.readString(path, StandardCharsets.UTF_8);
            assert body.contains("web-01");
            NetworkReachabilityCsvAnalysisReport analysis = new NetworkReachabilityCsvAnalysisReport(
                    NetworkReachabilityCsvContract.ID,
                    NetworkReachabilityCsvContract.SEMANTICS,
                    NetworkReachabilityCsvContract.HEADERS,
                    List.of(),
                    1,
                    1,
                    0,
                    0,
                    Map.of("INTERNET", 1L),
                    Map.of("TCP", 1L),
                    Map.of("REACHABLE", 1L),
                    Map.of("ACTIVE_PROBE", 1L),
                    List.of(),
                    List.of()
            );
            return new NetworkReachabilityImportResult(
                    analysis, 1, 0, 0, 1, 0, 0, List.of());
        };
        NetworkReachabilityEvidenceReader reader = (
                limit, assetPrefix, sourceProfileKey, evidenceSource, originScope, status) -> {
            assert limit == 50;
            assert "web-".equals(assetPrefix);
            assert "wazuh-primary".equals(sourceProfileKey);
            assert "reachability-export".equals(evidenceSource);
            assert "INTERNET".equals(originScope);
            assert "REACHABLE".equals(status);
            return Map.of(
                    "semantics", "CURRENT_PER_SOURCE_SCOPED_NETWORK_REACHABILITY_EVIDENCE",
                    "limit", limit,
                    "assetPrefix", assetPrefix,
                    "sourceProfileKey", sourceProfileKey,
                    "evidenceSource", evidenceSource,
                    "originScope", originScope,
                    "reachabilityStatus", status,
                    "count", 1,
                    "items", List.of(Map.ofEntries(
                            Map.entry("sourceProfileKey", "wazuh-primary"),
                            Map.entry("assetIdentityBasis", "SOURCE_NAME_ONLY"),
                            Map.entry("assetName", "web-01"),
                            Map.entry("assetSourceId", ""),
                            Map.entry("originScope", "INTERNET"),
                            Map.entry("originLabel", "public-probes"),
                            Map.entry("transportProtocol", "TCP"),
                            Map.entry("targetPort", 443),
                            Map.entry("targetService", "https"),
                            Map.entry("reachabilityStatus", "REACHABLE"),
                            Map.entry("reachabilityMethod", "ACTIVE_PROBE"),
                            Map.entry("evidenceSource", "reachability-export"),
                            Map.entry("evidenceSourceSha256", "a".repeat(64)),
                            Map.entry("evidenceObservedAt", "2026-08-19T09:00:00Z"),
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
                Optional.empty(),
                Optional.empty(),
                Optional.of(importer),
                Optional.of(reader),
                ApiKeyAuthenticator.disabled(),
                RequestRateLimiter.disabled()
        )) {
            server.start();
            URI base = server.baseUri();

            HttpResponse<String> ui = get(client, base.resolve("/reachability"));
            assert ui.statusCode() == 200 : ui.body();
            assert ui.body().contains("<html lang=\"en\" dir=\"ltr\">");
            assert ui.body().contains("id=\"rbvm-app\"");
            assert ui.body().contains("/ui/rbvm-ui.js");

            HttpResponse<String> health = get(client, base.resolve("/api/v1/health"));
            assert health.statusCode() == 200 : health.body();
            assert health.body().contains("\"networkReachability\"");
            assert health.body().contains("\"evidenceReadEnabled\": true");

            HttpResponse<String> evidence = get(
                    client,
                    base.resolve("/api/v1/network-reachability-evidence?limit=50&asset=web-&sourceProfile=wazuh-primary&evidenceSource=reachability-export&originScope=INTERNET&reachabilityStatus=REACHABLE")
            );
            assert evidence.statusCode() == 200 : evidence.body();
            assert evidence.body().contains("CURRENT_PER_SOURCE_SCOPED_NETWORK_REACHABILITY_EVIDENCE");
            assert evidence.body().contains("\"assetName\": \"web-01\"");
            assert evidence.body().contains("\"originScope\": \"INTERNET\"");
            assert evidence.body().contains("\"targetPort\": 443");
            assert evidence.body().contains("\"reachabilityStatus\": \"REACHABLE\"");
            assert evidence.body().contains("\"evidenceSource\": \"reachability-export\"");

            HttpResponse<String> invalidOrigin = get(
                    client,
                    base.resolve("/api/v1/network-reachability-evidence?originScope=PUBLIC")
            );
            assert invalidOrigin.statusCode() == 400 : invalidOrigin.body();
            HttpResponse<String> invalidStatus = get(
                    client,
                    base.resolve("/api/v1/network-reachability-evidence?reachabilityStatus=OPEN")
            );
            assert invalidStatus.statusCode() == 400 : invalidStatus.body();
            HttpResponse<String> invalidLimit = get(
                    client,
                    base.resolve("/api/v1/network-reachability-evidence?limit=501")
            );
            assert invalidLimit.statusCode() == 400 : invalidLimit.body();

            String csv = "Source_Profile_Key,Asset_Identity_Basis,Asset_Name,Asset_Source_ID,Origin_Scope,Origin_Label,Transport_Protocol,Target_Port,Target_Service,Reachability_Status,Reachability_Method,Evidence_Source,Evidence_Observed_At,Evidence_Source_SHA256\r\n"
                    + "wazuh-primary,SOURCE_NAME_ONLY,web-01,,INTERNET,public-probes,TCP,443,https,REACHABLE,ACTIVE_PROBE,reachability-export,2026-08-19T09:00:00Z,"
                    + "a".repeat(64) + "\r\n";
            HttpRequest request = HttpRequest.newBuilder(
                            base.resolve("/api/v1/network-reachability-imports"))
                    .timeout(Duration.ofSeconds(10))
                    .header("Content-Type", "text/csv; charset=utf-8")
                    .POST(HttpRequest.BodyPublishers.ofString(csv, StandardCharsets.UTF_8))
                    .build();
            HttpResponse<String> imported = client.send(
                    request,
                    HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8)
            );
            assert imported.statusCode() == 200 : imported.body();
            assert imported.body().contains("\"contractId\": \"NETWORK_REACHABILITY_CSV_V1\"");
            assert imported.body().contains("\"insertedEvidence\": 1");
            assert imported.body().contains("\"insertedSnapshots\": 1");
            assert imported.body().contains("\"totalQuarantinedRows\": 0");

            HttpRequest wrongType = HttpRequest.newBuilder(
                            base.resolve("/api/v1/network-reachability-imports"))
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

    private static void reportsReachabilityCapabilityAsUnavailableWithoutPostgresV14()
            throws Exception {
        Path data = Files.createTempDirectory("rbvm-reachability-disabled-");
        HttpClient client = client();
        try (CsvPlatformServer server = new CsvPlatformServer(
                "127.0.0.1", 0, data, 1024 * 1024)) {
            server.start();
            URI base = server.baseUri();
            HttpResponse<String> health = get(client, base.resolve("/api/v1/health"));
            assert health.body().contains("\"networkReachability\"");
            assert health.body().contains("\"evidenceReadEnabled\": false");

            HttpResponse<String> readUnavailable = get(
                    client,
                    base.resolve("/api/v1/network-reachability-evidence")
            );
            assert readUnavailable.statusCode() == 503 : readUnavailable.body();

            HttpRequest request = HttpRequest.newBuilder(
                            base.resolve("/api/v1/network-reachability-imports"))
                    .timeout(Duration.ofSeconds(10))
                    .header("Content-Type", "text/csv")
                    .POST(HttpRequest.BodyPublishers.ofString(
                            "Source_Profile_Key,Asset_Identity_Basis,Asset_Name,Asset_Source_ID,Origin_Scope,Origin_Label,Transport_Protocol,Target_Port,Target_Service,Reachability_Status,Reachability_Method,Evidence_Source,Evidence_Observed_At,Evidence_Source_SHA256\r\n"))
                    .build();
            HttpResponse<String> unavailable = client.send(
                    request,
                    HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8)
            );
            assert unavailable.statusCode() == 503 : unavailable.body();
            assert unavailable.body().contains("NETWORK REACHABILITY PERSISTENCE UNAVAILABLE");
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

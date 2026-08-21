package io.rbvm.csv;

import io.rbvm.domain.InMemoryDomainCatalog;
import io.rbvm.postgres.CisaKevEvidenceReader;
import io.rbvm.postgres.CisaKevImportResult;
import io.rbvm.postgres.CisaKevImporter;
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

public final class CsvCisaKevHttpSelfTest {
    private CsvCisaKevHttpSelfTest() {
    }

    public static void main(String[] args) throws Exception {
        exposesCisaKevImportCurrentEvidenceAndUi();
        reportsCisaKevCapabilityAsUnavailableWithoutPostgresV11();
        System.out.println("CsvCisaKevHttpSelfTest: PASS");
    }

    private static void exposesCisaKevImportCurrentEvidenceAndUi() throws Exception {
        Path data = Files.createTempDirectory("rbvm-kev-http-");
        HttpClient client = client();
        CisaKevImporter importer = path -> {
            String body = Files.readString(path, StandardCharsets.UTF_8);
            assert body.contains("CVE-2026-25087");
            CisaKevCsvAnalysisReport analysis = new CisaKevCsvAnalysisReport(
                    CisaKevCsvContract.ID,
                    CisaKevCsvContract.SEMANTICS,
                    CisaKevCsvContract.HEADERS,
                    List.of(),
                    1,
                    1,
                    0,
                    0,
                    1,
                    0,
                    1,
                    1,
                    List.of(),
                    List.of()
            );
            return new CisaKevImportResult(analysis, 1, 0, 0, 1, 0, 0, List.of());
        };
        CisaKevEvidenceReader reader = (limit, cvePrefix) -> {
            assert limit == 50;
            assert "CVE-2026-".equals(cvePrefix);
            return Map.of(
                    "semantics", "CURRENT_PER_SOURCE_CISA_KEV_SNAPSHOT_MEMBERSHIP_EVIDENCE",
                    "limit", limit,
                    "cvePrefix", cvePrefix,
                    "count", 1,
                    "items", List.of(Map.ofEntries(
                            Map.entry("cveId", "CVE-2026-25087"),
                            Map.entry("kevStatus", "LISTED"),
                            Map.entry("kevDateAdded", "2026-08-18"),
                            Map.entry("kevDueDate", "2026-09-08"),
                            Map.entry("knownRansomwareCampaignUse", "UNKNOWN"),
                            Map.entry("kevCatalogVersion", "2026.08.18"),
                            Map.entry("kevCatalogSha256", "a".repeat(64)),
                            Map.entry("kevCatalogCount", 1500),
                            Map.entry("kevSource", "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"),
                            Map.entry("kevObservedAt", "2026-08-19T08:00:00Z"),
                            Map.entry("evidenceIngestedAt", "2026-08-19T08:01:00Z"),
                            Map.entry("snapshotIngestedAt", "2026-08-19T08:01:00Z")
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
                Optional.of(importer),
                Optional.of(reader),
                ApiKeyAuthenticator.disabled(),
                RequestRateLimiter.disabled()
        )) {
            server.start();
            URI base = server.baseUri();

            HttpResponse<String> ui = get(client, base.resolve("/kev"));
            assert ui.statusCode() == 200 : ui.body();
            assert ui.body().contains("<html lang=\"en\" dir=\"ltr\">");
            assert ui.body().contains("id=\"rbvm-app\"");
            assert ui.body().contains("/ui/rbvm-ui.js");

            HttpResponse<String> health = get(client, base.resolve("/api/v1/health"));
            assert health.statusCode() == 200 : health.body();
            assert health.body().contains("\"cisaKev\"");
            assert health.body().contains("\"evidenceReadEnabled\": true");

            HttpResponse<String> evidence = get(
                    client,
                    base.resolve("/api/v1/cisa-kev-evidence?limit=50&cve=CVE-2026-")
            );
            assert evidence.statusCode() == 200 : evidence.body();
            assert evidence.body().contains("CURRENT_PER_SOURCE_CISA_KEV_SNAPSHOT_MEMBERSHIP_EVIDENCE");
            assert evidence.body().contains("CVE-2026-25087");
            assert evidence.body().contains("\"kevStatus\": \"LISTED\"");

            HttpResponse<String> invalidFilter = get(
                    client,
                    base.resolve("/api/v1/cisa-kev-evidence?cve=not-a-cve")
            );
            assert invalidFilter.statusCode() == 400 : invalidFilter.body();

            String csv = "CVE_ID,KEV_Status,KEV_Catalog_Version,KEV_Catalog_SHA256,KEV_Catalog_Count,KEV_Source,KEV_Observed_At,KEV_Date_Added,KEV_Due_Date,Known_Ransomware_Campaign_Use\r\n"
                    + "CVE-2026-25087,LISTED,2026.08.18," + "a".repeat(64) + ",1500,"
                    + "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json,"
                    + "2026-08-19T08:00:00Z,2026-08-18,2026-09-08,UNKNOWN\r\n";
            HttpRequest request = HttpRequest.newBuilder(base.resolve("/api/v1/cisa-kev-imports"))
                    .timeout(Duration.ofSeconds(10))
                    .header("Content-Type", "text/csv; charset=utf-8")
                    .POST(HttpRequest.BodyPublishers.ofString(csv, StandardCharsets.UTF_8))
                    .build();
            HttpResponse<String> imported = client.send(
                    request,
                    HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8)
            );
            assert imported.statusCode() == 200 : imported.body();
            assert imported.body().contains("\"contractId\": \"CISA_KEV_CSV_V1\"");
            assert imported.body().contains("\"insertedEvidence\": 1");
            assert imported.body().contains("\"insertedSnapshots\": 1");
            assert imported.body().contains("\"totalQuarantinedRows\": 0");

            HttpRequest wrongType = HttpRequest.newBuilder(base.resolve("/api/v1/cisa-kev-imports"))
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

    private static void reportsCisaKevCapabilityAsUnavailableWithoutPostgresV11() throws Exception {
        Path data = Files.createTempDirectory("rbvm-kev-disabled-");
        HttpClient client = client();
        try (CsvPlatformServer server = new CsvPlatformServer(
                "127.0.0.1", 0, data, 1024 * 1024)) {
            server.start();
            URI base = server.baseUri();
            HttpResponse<String> health = get(client, base.resolve("/api/v1/health"));
            assert health.body().contains("\"cisaKev\"");
            assert health.body().contains("\"evidenceReadEnabled\": false");

            HttpResponse<String> readUnavailable = get(
                    client,
                    base.resolve("/api/v1/cisa-kev-evidence")
            );
            assert readUnavailable.statusCode() == 503 : readUnavailable.body();

            HttpRequest request = HttpRequest.newBuilder(base.resolve("/api/v1/cisa-kev-imports"))
                    .timeout(Duration.ofSeconds(10))
                    .header("Content-Type", "text/csv")
                    .POST(HttpRequest.BodyPublishers.ofString(
                            "CVE_ID,KEV_Status,KEV_Catalog_Version,KEV_Catalog_SHA256,KEV_Catalog_Count,KEV_Source,KEV_Observed_At,KEV_Date_Added,KEV_Due_Date,Known_Ransomware_Campaign_Use\r\n"))
                    .build();
            HttpResponse<String> unavailable = client.send(
                    request,
                    HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8)
            );
            assert unavailable.statusCode() == 503 : unavailable.body();
            assert unavailable.body().contains("CISA KEV PERSISTENCE UNAVAILABLE");
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

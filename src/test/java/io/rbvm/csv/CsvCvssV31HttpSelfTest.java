package io.rbvm.csv;

import io.rbvm.domain.InMemoryDomainCatalog;
import io.rbvm.postgres.CvssV31EvidenceReader;
import io.rbvm.postgres.CvssV31ImportResult;
import io.rbvm.postgres.CvssV31Importer;
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

public final class CsvCvssV31HttpSelfTest {
    private CsvCvssV31HttpSelfTest() {
    }

    public static void main(String[] args) throws Exception {
        exposesCvssImportCurrentEvidenceAndUi();
        reportsCvssCapabilityAsUnavailableWithoutPostgresV10();
        System.out.println("CsvCvssV31HttpSelfTest: PASS");
    }

    private static void exposesCvssImportCurrentEvidenceAndUi() throws Exception {
        Path data = Files.createTempDirectory("rbvm-cvss-http-");
        HttpClient client = client();
        CvssV31Importer importer = path -> {
            String body = Files.readString(path, StandardCharsets.UTF_8);
            assert body.contains("CVE-2026-25087");
            CvssV31CsvAnalysisReport analysis = new CvssV31CsvAnalysisReport(
                    CvssV31CsvContract.ID,
                    CvssV31CsvContract.SEMANTICS,
                    CvssV31CsvContract.HEADERS,
                    List.of(),
                    1,
                    1,
                    0,
                    0,
                    1,
                    1,
                    List.of(),
                    List.of()
            );
            return new CvssV31ImportResult(analysis, 1, 0, 0, List.of());
        };
        CvssV31EvidenceReader reader = (limit, cvePrefix) -> {
            assert limit == 50;
            assert "CVE-2026-".equals(cvePrefix);
            return Map.of(
                    "semantics", "CURRENT_PER_SOURCE_CVSS_V31_BASE_EVIDENCE",
                    "limit", limit,
                    "cvePrefix", cvePrefix,
                    "count", 1,
                    "items", List.of(Map.of(
                            "cveId", "CVE-2026-25087",
                            "cvssVersion", "3.1",
                            "cvssBaseScore", 8.1,
                            "cvssVector", "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
                            "cvssSource", "https://nvd.nist.gov/vuln/detail/CVE-2026-25087",
                            "cvssObservedAt", "2026-08-19T08:00:00Z",
                            "ingestedAt", "2026-08-19T08:01:00Z"
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
                Optional.of(importer),
                Optional.of(reader),
                ApiKeyAuthenticator.disabled(),
                RequestRateLimiter.disabled()
        )) {
            server.start();
            URI base = server.baseUri();

            HttpResponse<String> ui = get(client, base.resolve("/cvss"));
            assert ui.statusCode() == 200 : ui.body();
            assert ui.body().contains("<html lang=\"en\" dir=\"ltr\">");
            assert ui.body().contains("id=\"rbvm-app\"");
            assert ui.body().contains("/ui/rbvm-ui.js");

            HttpResponse<String> health = get(client, base.resolve("/api/v1/health"));
            assert health.statusCode() == 200 : health.body();
            assert health.body().contains("\"cvssV31\"");
            assert health.body().contains("\"evidenceReadEnabled\": true");

            HttpResponse<String> evidence = get(
                    client,
                    base.resolve("/api/v1/cvss-v31-evidence?limit=50&cve=CVE-2026-")
            );
            assert evidence.statusCode() == 200 : evidence.body();
            assert evidence.body().contains("CURRENT_PER_SOURCE_CVSS_V31_BASE_EVIDENCE");
            assert evidence.body().contains("CVE-2026-25087");
            assert evidence.body().contains("\"cvssBaseScore\": 8.1");

            HttpResponse<String> invalidFilter = get(
                    client,
                    base.resolve("/api/v1/cvss-v31-evidence?cve=not-a-cve")
            );
            assert invalidFilter.statusCode() == 400 : invalidFilter.body();

            String csv = "CVE_ID,CVSS_Version,CVSS_Base_Score,CVSS_Vector,CVSS_Source,CVSS_Observed_At\r\n"
                    + "CVE-2026-25087,3.1,8.1,CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H,"
                    + "https://nvd.nist.gov/vuln/detail/CVE-2026-25087,2026-08-19T08:00:00Z\r\n";
            HttpRequest request = HttpRequest.newBuilder(base.resolve("/api/v1/cvss-v31-imports"))
                    .timeout(Duration.ofSeconds(10))
                    .header("Content-Type", "text/csv; charset=utf-8")
                    .POST(HttpRequest.BodyPublishers.ofString(csv, StandardCharsets.UTF_8))
                    .build();
            HttpResponse<String> imported = client.send(
                    request,
                    HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8)
            );
            assert imported.statusCode() == 200 : imported.body();
            assert imported.body().contains("\"contractId\": \"CVSS_V31_CSV_V1\"");
            assert imported.body().contains("\"insertedEvidence\": 1");
            assert imported.body().contains("\"totalQuarantinedRows\": 0");

            HttpRequest wrongType = HttpRequest.newBuilder(base.resolve("/api/v1/cvss-v31-imports"))
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

    private static void reportsCvssCapabilityAsUnavailableWithoutPostgresV10() throws Exception {
        Path data = Files.createTempDirectory("rbvm-cvss-disabled-");
        HttpClient client = client();
        try (CsvPlatformServer server = new CsvPlatformServer(
                "127.0.0.1", 0, data, 1024 * 1024)) {
            server.start();
            URI base = server.baseUri();
            HttpResponse<String> health = get(client, base.resolve("/api/v1/health"));
            assert health.body().contains("\"evidenceReadEnabled\": false");

            HttpResponse<String> readUnavailable = get(
                    client,
                    base.resolve("/api/v1/cvss-v31-evidence")
            );
            assert readUnavailable.statusCode() == 503 : readUnavailable.body();

            HttpRequest request = HttpRequest.newBuilder(base.resolve("/api/v1/cvss-v31-imports"))
                    .timeout(Duration.ofSeconds(10))
                    .header("Content-Type", "text/csv")
                    .POST(HttpRequest.BodyPublishers.ofString(
                            "CVE_ID,CVSS_Version,CVSS_Base_Score,CVSS_Vector,CVSS_Source,CVSS_Observed_At\r\n"))
                    .build();
            HttpResponse<String> unavailable = client.send(
                    request,
                    HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8)
            );
            assert unavailable.statusCode() == 503 : unavailable.body();
            assert unavailable.body().contains("CVSS V31 PERSISTENCE UNAVAILABLE");
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

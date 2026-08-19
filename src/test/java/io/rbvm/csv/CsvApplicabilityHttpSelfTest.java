package io.rbvm.csv;

import io.rbvm.domain.InMemoryDomainCatalog;
import io.rbvm.postgres.ApplicabilityImportResult;
import io.rbvm.postgres.ApplicabilityImporter;
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

public final class CsvApplicabilityHttpSelfTest {
    private static final String FINDING = "11111111-1111-4111-8111-111111111111";

    private CsvApplicabilityHttpSelfTest() {
    }

    public static void main(String[] args) throws Exception {
        exposesReferenceExportAndTransactionalImport();
        reportsApplicabilityCapabilityAsUnavailableWithoutPostgres();
        System.out.println("CsvApplicabilityHttpSelfTest: PASS");
    }

    private static void exposesReferenceExportAndTransactionalImport() throws Exception {
        Path data = Files.createTempDirectory("rbvm-applicability-http-");
        HttpClient client = client();
        ApplicabilityImporter importer = path -> {
            String body = Files.readString(path, StandardCharsets.UTF_8);
            assert body.contains(FINDING);
            ApplicabilityCsvAnalysisReport analysis = new ApplicabilityCsvAnalysisReport(
                    ApplicabilityCsvContract.ID,
                    ApplicabilityCsvContract.SEMANTICS,
                    ApplicabilityCsvContract.HEADERS,
                    List.of(),
                    1,
                    1,
                    0,
                    0,
                    Map.of("APPLICABLE", 1L, "NOT_APPLICABLE", 0L, "UNKNOWN", 0L),
                    List.of(),
                    List.of()
            );
            return new ApplicabilityImportResult(analysis, 1, 0, 0, List.of());
        };
        byte[] referenceCsv = ("Finding_ID,Agent,CVE_ID,Affected_Product,Severity,"
                + "Current_Applicability_Status,Current_Applicability_Assessed,"
                + "Current_Applicability_Reason,Current_Evidence_Source,Current_Evaluated_At\r\n"
                + FINDING + ",agent-a,CVE-2026-25087,pyarrow,HIGH,UNKNOWN,false,,,\r\n")
                .getBytes(StandardCharsets.UTF_8);

        try (CsvPlatformServer server = new CsvPlatformServer(
                "127.0.0.1",
                0,
                data,
                1024 * 1024,
                new NoopCanonicalProjection(),
                new InMemoryDomainCatalog(),
                Optional.of(importer),
                Optional.of(() -> referenceCsv),
                ApiKeyAuthenticator.disabled(),
                RequestRateLimiter.disabled()
        )) {
            server.start();
            URI base = server.baseUri();

            HttpResponse<String> health = get(client, base.resolve("/api/v1/health"));
            assert health.statusCode() == 200 : health.body();
            assert health.body().contains("\"importEnabled\": true");
            assert health.body().contains("\"findingReferenceExportEnabled\": true");

            HttpResponse<String> reference = get(
                    client,
                    base.resolve("/api/v1/applicability-findings.csv")
            );
            assert reference.statusCode() == 200 : reference.body();
            assert reference.headers().firstValue("Content-Type").orElse("")
                    .startsWith("text/csv");
            assert reference.body().contains("Current_Applicability_Status");
            assert reference.body().contains(FINDING);

            String csv = "Finding_ID,Applicability_Status,Applicability_Reason,Evidence_Source,Evaluated_At\r\n"
                    + FINDING + ",APPLICABLE,Validated deployment,Vendor advisory,2026-08-19T07:00:00Z\r\n";
            HttpRequest request = HttpRequest.newBuilder(
                            base.resolve("/api/v1/applicability-imports"))
                    .timeout(Duration.ofSeconds(10))
                    .header("Content-Type", "text/csv; charset=utf-8")
                    .POST(HttpRequest.BodyPublishers.ofString(csv, StandardCharsets.UTF_8))
                    .build();
            HttpResponse<String> imported = client.send(
                    request,
                    HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8)
            );
            assert imported.statusCode() == 200 : imported.body();
            assert imported.body().contains("\"contractId\": \"APPLICABILITY_CSV_V1\"");
            assert imported.body().contains("\"insertedAssessments\": 1");
            assert imported.body().contains("\"totalQuarantinedRows\": 0");

            HttpRequest wrongType = HttpRequest.newBuilder(
                            base.resolve("/api/v1/applicability-imports"))
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

    private static void reportsApplicabilityCapabilityAsUnavailableWithoutPostgres()
            throws Exception {
        Path data = Files.createTempDirectory("rbvm-applicability-disabled-");
        HttpClient client = client();
        try (CsvPlatformServer server = new CsvPlatformServer(
                "127.0.0.1", 0, data, 1024 * 1024)) {
            server.start();
            URI base = server.baseUri();
            HttpResponse<String> health = get(client, base.resolve("/api/v1/health"));
            assert health.body().contains("\"importEnabled\": false");
            assert health.body().contains("\"findingReferenceExportEnabled\": false");

            HttpRequest request = HttpRequest.newBuilder(
                            base.resolve("/api/v1/applicability-imports"))
                    .timeout(Duration.ofSeconds(10))
                    .header("Content-Type", "text/csv")
                    .POST(HttpRequest.BodyPublishers.ofString(
                            "Finding_ID,Applicability_Status,Applicability_Reason,Evidence_Source,Evaluated_At\r\n"))
                    .build();
            HttpResponse<String> unavailable = client.send(
                    request,
                    HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8)
            );
            assert unavailable.statusCode() == 503 : unavailable.body();
            assert unavailable.body().contains("APPLICABILITY PERSISTENCE UNAVAILABLE");

            HttpResponse<String> exportUnavailable = get(
                    client,
                    base.resolve("/api/v1/applicability-findings.csv")
            );
            assert exportUnavailable.statusCode() == 503 : exportUnavailable.body();
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
        if (!Files.exists(root)) {
            return;
        }
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

package io.rbvm.csv;

import com.sun.net.httpserver.HttpServer;

import io.rbvm.postgres.PostgresPublicIntelligenceStore;
import io.rbvm.postgres.PublicIntelligenceStatusReader;
import io.rbvm.security.ApiKeyAuthenticator;

import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.Executors;

/** Dependency-free HTTP contract proof for GET /api/v1/intelligence/status. */
public final class PublicIntelligenceStatusHttpSelfTest {
    private PublicIntelligenceStatusHttpSelfTest() {
    }

    public static void main(String[] args) throws Exception {
        Instant t0 = Instant.parse("2026-08-24T06:30:00Z");
        UUID jobId = UUID.fromString("10000000-0000-4000-8000-000000000031");
        UUID runId = UUID.fromString("20000000-0000-4000-8000-000000000031");
        PublicIntelligenceStatusReader reader = () -> List.of(
                new PublicIntelligenceStatusReader.ProviderStatus(
                        PostgresPublicIntelligenceStore.Provider.CISA_KEV,
                        jobId,
                        "SCHEDULED",
                        "FAILED",
                        "FAILED",
                        t0,
                        t0.plusSeconds(10),
                        t0.plusSeconds(10),
                        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
                        "2026.08.24",
                        "a".repeat(64),
                        null,
                        "SOURCE_FETCH_FAILED",
                        "synthetic status failure",
                        runId,
                        "BOOTSTRAP",
                        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
                        "2026.08.23",
                        "b".repeat(64),
                        t0.minusSeconds(3600),
                        t0.minusSeconds(3500),
                        t0.minusSeconds(3400),
                        1400L
                )
        );

        HttpResponse<String> ok = request(Optional.of(reader), "GET", PublicIntelligenceStatusHttpHandler.ROOT);
        require(ok.statusCode() == 200, "status GET must return 200");
        require("no-store".equals(ok.headers().firstValue("Cache-Control").orElse(null)),
                "status response must be non-cacheable");
        require(PublicIntelligenceStatusHttpHandler.CONTRACT_ID.equals(
                        ok.headers().firstValue("X-RBVM-Contract").orElse(null)),
                "status response must expose its contract id");
        require(ok.body().contains("\"provider\": \"CISA_KEV\""),
                "status body must expose provider identity");
        require(ok.body().contains("\"latestJob\""),
                "status body must expose latest operational job");
        require(ok.body().contains("\"SOURCE_FETCH_FAILED\""),
                "status body must expose latest failure without hiding it");
        require(ok.body().contains("\"lastSuccess\""),
                "status body must independently expose last successful source state");
        require(ok.body().contains(runId.toString()),
                "status body must retain exact last-successful V30 run id");

        HttpResponse<String> method = request(Optional.of(reader), "POST", PublicIntelligenceStatusHttpHandler.ROOT);
        require(method.statusCode() == 405, "status endpoint must be read-only");
        require("GET".equals(method.headers().firstValue("Allow").orElse(null)),
                "status endpoint must advertise GET only");

        HttpResponse<String> unavailable = request(Optional.empty(), "GET", PublicIntelligenceStatusHttpHandler.ROOT);
        require(unavailable.statusCode() == 503, "missing PostgreSQL status capability must return 503");
        require(unavailable.body().contains("INTELLIGENCE_STATUS_UNAVAILABLE"),
                "unavailable response must be explicit");

        System.out.println("PublicIntelligenceStatusHttpSelfTest: PASS");
    }

    private static HttpResponse<String> request(
            Optional<? extends PublicIntelligenceStatusReader> reader,
            String method,
            String path
    ) throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 8);
        var executor = Executors.newFixedThreadPool(2);
        server.setExecutor(executor);
        server.createContext(
                PublicIntelligenceStatusHttpHandler.ROOT,
                new PublicIntelligenceStatusHttpHandler(reader, ApiKeyAuthenticator.disabled()));
        server.start();
        try {
            HttpRequest request = HttpRequest.newBuilder(
                            URI.create("http://127.0.0.1:" + server.getAddress().getPort() + path))
                    .method(method, HttpRequest.BodyPublishers.noBody())
                    .build();
            return HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString());
        } finally {
            server.stop(0);
            executor.shutdownNow();
        }
    }

    private static void require(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
}

package io.rbvm.csv;

import com.sun.net.httpserver.HttpServer;

import io.rbvm.postgres.PostgresPublicIntelligenceStore;
import io.rbvm.postgres.PostgresPublicIntelligenceSyncJobStore;
import io.rbvm.postgres.PublicIntelligenceSyncCoordinator;
import io.rbvm.postgres.PublicIntelligenceSyncTrigger;
import io.rbvm.security.ApiKeyAuthenticator;

import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicReference;

/** Dependency-free HTTP contract proof for POST /api/v1/intelligence/sync/{provider}. */
public final class PublicIntelligenceSyncHttpSelfTest {
    private PublicIntelligenceSyncHttpSelfTest() {
    }

    public static void main(String[] args) throws Exception {
        AtomicReference<String> received = new AtomicReference<>();
        PublicIntelligenceSyncTrigger trigger = (provider, feed, triggerSource) -> {
            received.set(provider.name() + ":" + feed + ":" + triggerSource.name());
            return new PublicIntelligenceSyncTrigger.Submission(
                    UUID.fromString("30000000-0000-4000-8000-000000000001"),
                    provider,
                    feed,
                    "RUNNING",
                    "ACQUIRING",
                    Instant.parse("2026-08-24T07:00:00Z"));
        };

        HttpResponse<String> cisa = request(
                Optional.of(trigger),
                "POST",
                PublicIntelligenceSyncHttpHandler.ROOT + "/CISA_KEV",
                HttpRequest.BodyPublishers.noBody());
        require(cisa.statusCode() == 202, "CISA sync POST must return 202");
        require("CISA_KEV:null:MANUAL".equals(received.get()),
                "non-NVD sync must submit one manual provider source without NVD feed");
        require(cisa.body().contains("\"provider\": \"CISA_KEV\""),
                "accepted sync response must expose provider");
        require(cisa.body().contains("\"stage\": \"ACQUIRING\""),
                "accepted sync response must expose initial job stage");
        require(PublicIntelligenceStatusHttpHandler.ROOT.equals(
                        cisa.headers().firstValue("Location").orElse(null)),
                "accepted sync response must point to status endpoint");

        HttpResponse<String> nvd = request(
                Optional.of(trigger),
                "POST",
                PublicIntelligenceSyncHttpHandler.ROOT + "/NVD?feed=2026",
                HttpRequest.BodyPublishers.noBody());
        require(nvd.statusCode() == 202, "NVD exact year sync POST must return 202");
        require("NVD:2026:MANUAL".equals(received.get()),
                "NVD sync must retain exact requested feed identity");

        HttpResponse<String> method = request(
                Optional.of(trigger),
                "GET",
                PublicIntelligenceSyncHttpHandler.ROOT + "/FIRST_EPSS",
                HttpRequest.BodyPublishers.noBody());
        require(method.statusCode() == 405, "sync endpoint must be POST-only");
        require("POST".equals(method.headers().firstValue("Allow").orElse(null)),
                "sync endpoint must advertise POST only");

        HttpResponse<String> invalidQuery = request(
                Optional.of(trigger),
                "POST",
                PublicIntelligenceSyncHttpHandler.ROOT + "/CISA_KEV?feed=modified",
                HttpRequest.BodyPublishers.noBody());
        require(invalidQuery.statusCode() == 400,
                "non-NVD provider must reject NVD feed query parameter");

        HttpResponse<String> body = request(
                Optional.of(trigger),
                "POST",
                PublicIntelligenceSyncHttpHandler.ROOT + "/CVE_PROGRAM",
                HttpRequest.BodyPublishers.ofString("{}"));
        require(body.statusCode() == 400, "sync endpoint must reject request bodies");

        HttpResponse<String> unavailable = request(
                Optional.empty(),
                "POST",
                PublicIntelligenceSyncHttpHandler.ROOT + "/FIRST_EPSS",
                HttpRequest.BodyPublishers.noBody());
        require(unavailable.statusCode() == 503,
                "missing synchronization runtime must return 503");

        PublicIntelligenceSyncTrigger conflicting = (provider, feed, triggerSource) -> {
            throw new PublicIntelligenceSyncCoordinator.AlreadyRunningException(provider);
        };
        HttpResponse<String> conflict = request(
                Optional.of(conflicting),
                "POST",
                PublicIntelligenceSyncHttpHandler.ROOT + "/CISA_KEV",
                HttpRequest.BodyPublishers.noBody());
        require(conflict.statusCode() == 409,
                "overlapping provider synchronization must return 409");
        require(conflict.body().contains("INTELLIGENCE_SYNC_ALREADY_RUNNING"),
                "overlap response must expose stable problem code");

        System.out.println("PublicIntelligenceSyncHttpSelfTest: PASS");
    }

    private static HttpResponse<String> request(
            Optional<? extends PublicIntelligenceSyncTrigger> trigger,
            String method,
            String path,
            HttpRequest.BodyPublisher body
    ) throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 8);
        var executor = Executors.newFixedThreadPool(2);
        server.setExecutor(executor);
        server.createContext(
                PublicIntelligenceSyncHttpHandler.ROOT,
                new PublicIntelligenceSyncHttpHandler(trigger, ApiKeyAuthenticator.disabled()));
        server.start();
        try {
            HttpRequest request = HttpRequest.newBuilder(
                            URI.create("http://127.0.0.1:" + server.getAddress().getPort() + path))
                    .method(method, body)
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

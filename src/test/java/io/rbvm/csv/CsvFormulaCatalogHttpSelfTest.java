package io.rbvm.csv;

import io.rbvm.decision.RbvmFormulaV1;
import io.rbvm.domain.InMemoryDomainCatalog;
import io.rbvm.postgres.DecisionInputSnapshotInstallResult;
import io.rbvm.postgres.DecisionInputSnapshotStore;
import io.rbvm.postgres.FormulaResultInstallResult;
import io.rbvm.postgres.FormulaResultReplayVerifier;
import io.rbvm.postgres.FormulaResultStore;
import io.rbvm.postgres.StoredFormulaResult;
import io.rbvm.security.ApiKeyAuthenticator;
import io.rbvm.security.RequestRateLimiter;

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
import java.util.HexFormat;
import java.util.Optional;
import java.util.Set;

public final class CsvFormulaCatalogHttpSelfTest {
    private CsvFormulaCatalogHttpSelfTest() {
    }

    public static void main(String[] args) throws Exception {
        exposesFormulaIdentityWithoutDefaultSelection();
        protectsDisabledCatalogBehindViewerAuthentication();
        System.out.println("CsvFormulaCatalogHttpSelfTest: PASS");
    }

    private static void exposesFormulaIdentityWithoutDefaultSelection() throws Exception {
        Path data = Files.createTempDirectory("rbvm-formula-catalog-http-");
        HttpClient client = client();
        try (CsvPlatformServer server = server(
                data,
                ApiKeyAuthenticator.disabled(),
                Optional.of(emptyFormulaApi())
        )) {
            server.start();
            URI catalog = server.baseUri().resolve("/api/v1/formulas");

            HttpResponse<String> response = get(client, catalog);
            assert response.statusCode() == 200 : response.body();
            assert response.body().contains("RBVM_FORMULA_CATALOG_API_V1");
            assert response.body().contains("EXPLICIT_ID_AND_SHA_ONLY_NO_DEFAULT");
            assert response.body().contains("\"formulaId\": \"RBVM_FORMULA_V1\"");
            assert response.body().contains("\"formulaSha256\": \""
                    + RbvmFormulaV1.FORMULA_SHA256 + "\"");
            assert response.body().contains("\"classification\": \"RBVM_POLICY\"");
            assert response.body().contains("\"numericMinimum\": \"0.00\"");
            assert response.body().contains("\"numericMaximum\": \"100.00\"");
            assert response.body().contains("NOT_PRIORITY_SLA_TREATMENT_OR_PROBABILITY");
            assert !response.body().contains("defaultFormula");
            assert !response.body().contains("preferredFormula");

            HttpResponse<String> queryRejected = get(
                    client,
                    URI.create(catalog.toString() + "?latest=true")
            );
            assert queryRejected.statusCode() == 400 : queryRejected.body();
            assert queryRejected.body().contains("INVALID FORMULA CATALOG QUERY");

            HttpResponse<String> writeRejected = client.send(
                    HttpRequest.newBuilder(catalog)
                            .timeout(Duration.ofSeconds(10))
                            .POST(HttpRequest.BodyPublishers.noBody())
                            .build(),
                    HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8)
            );
            assert writeRejected.statusCode() == 405 : writeRejected.body();
            assert writeRejected.headers().firstValue("Allow").orElseThrow().equals("GET");
        } finally {
            deleteTree(data);
        }
    }

    private static void protectsDisabledCatalogBehindViewerAuthentication() throws Exception {
        Path data = Files.createTempDirectory("rbvm-formula-catalog-auth-");
        String viewerToken = "formula-catalog-viewer-token-abcdefghijklmnopqrstuvwxyz-123";
        Path keyRegistry = data.resolve("api-keys.conf");
        Files.writeString(
                keyRegistry,
                digest(viewerToken) + "=formula-catalog-viewer|VIEWER\n",
                StandardCharsets.UTF_8
        );
        try {
            Files.setPosixFilePermissions(keyRegistry, Set.of(
                    PosixFilePermission.OWNER_READ,
                    PosixFilePermission.OWNER_WRITE
            ));
        } catch (UnsupportedOperationException ignored) {
            // Non-POSIX filesystems rely on platform ACLs.
        }

        HttpClient client = client();
        try (CsvPlatformServer server = server(
                data.resolve("evidence"),
                ApiKeyAuthenticator.fromFile(keyRegistry),
                Optional.empty()
        )) {
            server.start();
            URI catalog = server.baseUri().resolve("/api/v1/formulas");

            HttpResponse<String> unauthenticated = get(client, catalog);
            assert unauthenticated.statusCode() == 401 : unauthenticated.body();
            assert !unauthenticated.body().contains("PERSISTENCE UNAVAILABLE");

            HttpResponse<String> viewer = authorizedGet(client, catalog, viewerToken);
            assert viewer.statusCode() == 503 : viewer.body();
            assert viewer.body().contains("FORMULA RESULT PERSISTENCE UNAVAILABLE");
        } finally {
            deleteTree(data);
        }
    }

    private static CsvPlatformServer server(
            Path data,
            ApiKeyAuthenticator authenticator,
            Optional<FormulaResultApi> formulaApi
    ) throws Exception {
        CsvPlatformServer server = new CsvPlatformServer(
                "127.0.0.1",
                0,
                data,
                1024 * 1024,
                new NoopCanonicalProjection(),
                new InMemoryDomainCatalog(),
                authenticator,
                RequestRateLimiter.disabled()
        );
        formulaApi.ifPresent(server::enableFormulaResultApi);
        return server;
    }

    private static FormulaResultApi emptyFormulaApi() {
        FormulaResultStore results = new FormulaResultStore() {
            @Override
            public FormulaResultInstallResult install(
                    io.rbvm.decision.RbvmFormulaV1Explanation explanation
            ) {
                throw new UnsupportedOperationException("catalog-only test store");
            }

            @Override
            public Optional<StoredFormulaResult> findByExplanationSha256(String sha256) {
                return Optional.empty();
            }

            @Override
            public Optional<StoredFormulaResult> findBySnapshotAndFormula(
                    String inputSnapshotSha256,
                    String formulaSha256
            ) {
                return Optional.empty();
            }
        };
        DecisionInputSnapshotStore snapshots = new DecisionInputSnapshotStore() {
            @Override
            public DecisionInputSnapshotInstallResult install(
                    io.rbvm.decision.RbvmDecisionInputSnapshot snapshot
            ) {
                throw new UnsupportedOperationException("catalog-only test store");
            }

            @Override
            public Optional<io.rbvm.decision.RbvmDecisionInputSnapshot> findBySha256(String sha256) {
                return Optional.empty();
            }
        };
        FormulaResultReplayVerifier verifier = new FormulaResultReplayVerifier(
                results,
                snapshots,
                ignored -> {
                    throw new IOException("catalog test must not resolve Decision Input evidence");
                }
        );
        return new FormulaResultApi(results, verifier);
    }

    private static HttpClient client() {
        return HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();
    }

    private static HttpResponse<String> get(HttpClient client, URI uri) throws Exception {
        return client.send(
                HttpRequest.newBuilder(uri).timeout(Duration.ofSeconds(10)).GET().build(),
                HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8)
        );
    }

    private static HttpResponse<String> authorizedGet(
            HttpClient client,
            URI uri,
            String token
    ) throws Exception {
        return client.send(
                HttpRequest.newBuilder(uri)
                        .timeout(Duration.ofSeconds(10))
                        .header("Authorization", "Bearer " + token)
                        .GET()
                        .build(),
                HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8)
        );
    }

    private static String digest(String value) throws Exception {
        return HexFormat.of().formatHex(
                MessageDigest.getInstance("SHA-256")
                        .digest(value.getBytes(StandardCharsets.UTF_8))
        );
    }

    private static void deleteTree(Path root) throws IOException {
        if (root == null || !Files.exists(root)) return;
        try (var paths = Files.walk(root)) {
            paths.sorted((left, right) -> right.compareTo(left)).forEach(path -> {
                try {
                    Files.deleteIfExists(path);
                } catch (IOException exception) {
                    throw new RuntimeException(exception);
                }
            });
        } catch (RuntimeException exception) {
            if (exception.getCause() instanceof IOException io) throw io;
            throw exception;
        }
    }
}

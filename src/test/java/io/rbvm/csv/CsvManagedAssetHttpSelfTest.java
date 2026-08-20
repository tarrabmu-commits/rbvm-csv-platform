package io.rbvm.csv;

import io.rbvm.asset.ManagedAsset;
import io.rbvm.asset.ManagedAsset.LifecycleStatus;
import io.rbvm.asset.ManagedAsset.Revision;
import io.rbvm.asset.ManagedAsset.RevisionDraft;
import io.rbvm.asset.ManagedAssetRegistry;
import io.rbvm.asset.ManagedAssetRegistry.LifecycleFilter;
import io.rbvm.asset.ManagedAssetRegistry.ManagedAssetPage;
import io.rbvm.asset.ManagedAssetRegistry.MutationResult;
import io.rbvm.asset.ManagedAssetRegistry.MutationStatus;
import io.rbvm.asset.ManagedAssetRegistry.RevisionPage;
import io.rbvm.domain.InMemoryDomainCatalog;
import io.rbvm.security.ApiKeyAuthenticator;
import io.rbvm.security.RequestRateLimiter;

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
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

public final class CsvManagedAssetHttpSelfTest {
    private CsvManagedAssetHttpSelfTest() {
    }

    public static void main(String[] args) throws Exception {
        exposesManagedAssetLifecycleAndHistory();
        reportsManagedAssetCapabilityAsUnavailableWithoutV18();
        protectsUnavailableCapabilityBehindAuthentication();
        derivesAuditActorFromAuthenticatedPrincipal();
        System.out.println("CsvManagedAssetHttpSelfTest: PASS");
    }

    private static void exposesManagedAssetLifecycleAndHistory() throws Exception {
        Path data = Files.createTempDirectory("rbvm-managed-asset-http-");
        FakeRegistry registry = new FakeRegistry();
        HttpClient client = client();
        try (CsvPlatformServer server = server(data, registry)) {
            server.start();
            URI base = server.baseUri();

            HttpResponse<String> health = get(client, base.resolve("/api/v1/health"));
            assert health.statusCode() == 200 : health.body();
            assert health.body().contains("\"managedAssets\"");
            assert health.body().contains("\"historyReadEnabled\": true");

            String createJson = """
                    {
                      "customerAssetKey": "CMDB-42",
                      "displayName": "payments-prod-01",
                      "environment": "PRODUCTION",
                      "businessService": "Payments",
                      "businessOwner": "Payments Operations",
                      "businessCriticality": "HIGH",
                      "classificationMethod": "CUSTOMER_DIRECT",
                      "changeNote": "customer creation"
                    }
                    """;
            HttpResponse<String> created = postJson(
                    client,
                    base.resolve("/api/v1/managed-assets"),
                    createJson,
                    null
            );
            assert created.statusCode() == 201 : created.body();
            String location = created.headers().firstValue("Location").orElseThrow();
            String etag1 = created.headers().firstValue("ETag").orElseThrow();
            assert location.startsWith("/api/v1/managed-assets/");
            assert created.body().contains("\"customerAssetKey\": \"CMDB-42\"");
            assert created.body().contains("\"lifecycleStatus\": \"ACTIVE\"");
            assert created.body().contains("\"changedBy\": \"local-operator\"");
            assert created.body().contains("\"contextSource\": \"CUSTOMER_ASSET_REGISTRY\"");

            URI item = base.resolve(location);
            HttpResponse<String> current = get(client, item);
            assert current.statusCode() == 200 : current.body();
            assert current.headers().firstValue("ETag").orElseThrow().equals(etag1);

            HttpResponse<String> listed = get(
                    client,
                    base.resolve("/api/v1/managed-assets?limit=10&lifecycle=ALL")
            );
            assert listed.statusCode() == 200 : listed.body();
            assert listed.body().contains("CMDB-42");
            assert listed.body().contains("\"nextAfterId\": null");

            String retireJson = """
                    {
                      "lifecycleStatus": "RETIRED",
                      "displayName": "payments-prod-01",
                      "environment": "PRODUCTION",
                      "businessService": "Payments",
                      "businessOwner": "Payments Operations",
                      "businessCriticality": "HIGH",
                      "classificationMethod": "CUSTOMER_DIRECT",
                      "changeNote": "retired by customer"
                    }
                    """;
            HttpResponse<String> missingPrecondition = postJson(
                    client,
                    base.resolve(location + "/revisions"),
                    retireJson,
                    null
            );
            assert missingPrecondition.statusCode() == 428 : missingPrecondition.body();

            HttpResponse<String> retired = postJson(
                    client,
                    base.resolve(location + "/revisions"),
                    retireJson,
                    etag1
            );
            assert retired.statusCode() == 200 : retired.body();
            String etag2 = retired.headers().firstValue("ETag").orElseThrow();
            assert !etag1.equals(etag2);
            assert retired.body().contains("\"revision\": 2");
            assert retired.body().contains("\"lifecycleStatus\": \"RETIRED\"");
            assert retired.body().contains("\"changedBy\": \"local-operator\"");

            // The exact network retry remains replay-safe through V18's existing semantics.
            HttpResponse<String> replay = postJson(
                    client,
                    base.resolve(location + "/revisions"),
                    retireJson,
                    etag1
            );
            assert replay.statusCode() == 200 : replay.body();
            assert replay.headers().firstValue("ETag").orElseThrow().equals(etag2);
            assert registry.find(UUID.fromString(location.substring(location.lastIndexOf('/') + 1)))
                    .orElseThrow().currentRevision().revision() == 2;

            String staleConflictJson = retireJson
                    .replace("\"RETIRED\"", "\"ACTIVE\"")
                    .replace("retired by customer", "stale conflicting edit");
            HttpResponse<String> stale = postJson(
                    client,
                    base.resolve(location + "/revisions"),
                    staleConflictJson,
                    etag1
            );
            assert stale.statusCode() == 412 : stale.body();

            HttpResponse<String> history = get(
                    client,
                    base.resolve(location + "/revisions?limit=10")
            );
            assert history.statusCode() == 200 : history.body();
            assert history.body().contains("\"revision\": 2");
            assert history.body().contains("\"revision\": 1");
            assert history.body().contains("\"nextBeforeRevision\": null");

            HttpResponse<String> retiredOnly = get(
                    client,
                    base.resolve("/api/v1/managed-assets?lifecycle=RETIRED")
            );
            assert retiredOnly.statusCode() == 200 : retiredOnly.body();
            assert retiredOnly.body().contains("CMDB-42");
            HttpResponse<String> activeOnly = get(
                    client,
                    base.resolve("/api/v1/managed-assets?lifecycle=ACTIVE")
            );
            assert activeOnly.statusCode() == 200 : activeOnly.body();
            assert !activeOnly.body().contains("CMDB-42");

            String spoofedAudit = createJson.replace(
                    "\"changeNote\": \"customer creation\"",
                    "\"changedBy\": \"mallory\", \"changeNote\": \"customer creation\""
            );
            HttpResponse<String> spoofRejected = postJson(
                    client,
                    base.resolve("/api/v1/managed-assets"),
                    spoofedAudit,
                    null
            );
            assert spoofRejected.statusCode() == 400 : spoofRejected.body();

            HttpResponse<String> duplicateKey = postJson(
                    client,
                    base.resolve("/api/v1/managed-assets"),
                    createJson,
                    null
            );
            assert duplicateKey.statusCode() == 409 : duplicateKey.body();

            HttpRequest delete = HttpRequest.newBuilder(item)
                    .timeout(Duration.ofSeconds(10))
                    .DELETE()
                    .build();
            HttpResponse<String> deleteRejected = client.send(
                    delete,
                    HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8)
            );
            assert deleteRejected.statusCode() == 405 : deleteRejected.body();
            assert "GET".equals(deleteRejected.headers().firstValue("Allow").orElse(null));
        } finally {
            deleteTree(data);
        }
    }

    private static void reportsManagedAssetCapabilityAsUnavailableWithoutV18() throws Exception {
        Path data = Files.createTempDirectory("rbvm-managed-asset-disabled-");
        HttpClient client = client();
        try (CsvPlatformServer server = new CsvPlatformServer(
                "127.0.0.1", 0, data, 1024 * 1024)) {
            server.start();
            URI base = server.baseUri();
            HttpResponse<String> health = get(client, base.resolve("/api/v1/health"));
            assert health.body().contains("\"managedAssets\"");
            assert health.body().contains("\"historyReadEnabled\": false");

            HttpResponse<String> unavailable = get(
                    client,
                    base.resolve("/api/v1/managed-assets")
            );
            assert unavailable.statusCode() == 503 : unavailable.body();
            assert unavailable.body().contains("MANAGED ASSET PERSISTENCE UNAVAILABLE");

            HttpResponse<String> unknownSubroute = get(
                    client,
                    base.resolve("/api/v1/managed-assets/not-a-route")
            );
            assert unknownSubroute.statusCode() == 404 : unknownSubroute.body();
        } finally {
            deleteTree(data);
        }
    }

    private static void protectsUnavailableCapabilityBehindAuthentication() throws Exception {
        Path data = Files.createTempDirectory("rbvm-managed-asset-auth-");
        String viewerToken = "managed-viewer-token-abcdefghijklmnopqrstuvwxyz-123";
        String operatorToken = "managed-operator-token-abcdefghijklmnopqrstuvwxyz";
        Path keyRegistry = data.resolve("api-keys.conf");
        Files.writeString(
                keyRegistry,
                digest(viewerToken) + "=managed-viewer|VIEWER\n"
                        + digest(operatorToken) + "=managed-operator|OPERATOR\n",
                StandardCharsets.UTF_8
        );
        try {
            Files.setPosixFilePermissions(keyRegistry, Set.of(
                    PosixFilePermission.OWNER_READ,
                    PosixFilePermission.OWNER_WRITE
            ));
        } catch (UnsupportedOperationException ignored) {
            // The authenticator defers to platform ACLs on non-POSIX filesystems.
        }

        HttpClient client = client();
        try (CsvPlatformServer server = server(
                data.resolve("evidence"),
                Optional.empty(),
                ApiKeyAuthenticator.fromFile(keyRegistry)
        )) {
            server.start();
            URI base = server.baseUri();

            HttpResponse<String> missing = get(
                    client,
                    base.resolve("/api/v1/managed-assets")
            );
            assert missing.statusCode() == 401 : missing.body();

            HttpResponse<String> authorizedUnavailable = authorizedGet(
                    client,
                    base.resolve("/api/v1/managed-assets"),
                    viewerToken
            );
            assert authorizedUnavailable.statusCode() == 503 : authorizedUnavailable.body();

            String createJson = """
                    {
                      "displayName": "auth-test",
                      "environment": "UNKNOWN",
                      "businessService": "UNKNOWN",
                      "businessOwner": "UNKNOWN",
                      "businessCriticality": "UNKNOWN",
                      "classificationMethod": "CUSTOMER_DIRECT"
                    }
                    """;
            HttpResponse<String> viewerDenied = authorizedPostJson(
                    client,
                    base.resolve("/api/v1/managed-assets"),
                    createJson,
                    viewerToken
            );
            assert viewerDenied.statusCode() == 403 : viewerDenied.body();

            HttpResponse<String> operatorUnavailable = authorizedPostJson(
                    client,
                    base.resolve("/api/v1/managed-assets"),
                    createJson,
                    operatorToken
            );
            assert operatorUnavailable.statusCode() == 503 : operatorUnavailable.body();
        } finally {
            deleteTree(data);
        }
    }

    private static void derivesAuditActorFromAuthenticatedPrincipal() throws Exception {
        Path data = Files.createTempDirectory("rbvm-managed-asset-auth-actor-");
        String operatorToken = "managed-actor-token-abcdefghijklmnopqrstuvwxyz-123";
        Path keyRegistry = data.resolve("api-keys.conf");
        Files.writeString(
                keyRegistry,
                digest(operatorToken) + "=asset-owner@example.test|OPERATOR\n",
                StandardCharsets.UTF_8
        );
        try {
            Files.setPosixFilePermissions(keyRegistry, Set.of(
                    PosixFilePermission.OWNER_READ,
                    PosixFilePermission.OWNER_WRITE
            ));
        } catch (UnsupportedOperationException ignored) {
            // The authenticator defers to platform ACLs on non-POSIX filesystems.
        }

        FakeRegistry registry = new FakeRegistry();
        HttpClient client = client();
        try (CsvPlatformServer server = server(
                data.resolve("evidence"),
                Optional.of(registry),
                ApiKeyAuthenticator.fromFile(keyRegistry)
        )) {
            server.start();
            String createJson = """
                    {
                      "customerAssetKey": "CMDB-AUTH-1",
                      "displayName": "authenticated-asset",
                      "environment": "PRODUCTION",
                      "businessService": "Payments",
                      "businessOwner": "Payments Operations",
                      "businessCriticality": "HIGH",
                      "classificationMethod": "CUSTOMER_DIRECT",
                      "changeNote": "authenticated creation"
                    }
                    """;
            HttpResponse<String> created = authorizedPostJson(
                    client,
                    server.baseUri().resolve("/api/v1/managed-assets"),
                    createJson,
                    operatorToken
            );
            assert created.statusCode() == 201 : created.body();
            assert created.body().contains("\"changedBy\": \"asset-owner@example.test\"");
            ManagedAsset persisted = registry.assets.values().stream().findFirst().orElseThrow();
            assert persisted.currentRevision().changedBy().equals("asset-owner@example.test");
        } finally {
            deleteTree(data);
        }
    }

    private static CsvPlatformServer server(Path data, ManagedAssetRegistry registry)
            throws Exception {
        return server(data, Optional.of(registry), ApiKeyAuthenticator.disabled());
    }

    private static CsvPlatformServer server(
            Path data,
            Optional<ManagedAssetRegistry> registry,
            ApiKeyAuthenticator authenticator
    ) throws Exception {
        return new CsvPlatformServer(
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
                Optional.empty(),
                Optional.empty(),
                Optional.empty(),
                Optional.empty(),
                registry,
                authenticator,
                RequestRateLimiter.disabled()
        );
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

    private static HttpResponse<String> postJson(
            HttpClient client,
            URI uri,
            String json,
            String ifMatch
    ) throws Exception {
        HttpRequest.Builder request = HttpRequest.newBuilder(uri)
                .timeout(Duration.ofSeconds(10))
                .header("Content-Type", "application/json");
        if (ifMatch != null) {
            request.header("If-Match", ifMatch);
        }
        return client.send(
                request.POST(HttpRequest.BodyPublishers.ofString(json, StandardCharsets.UTF_8)).build(),
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

    private static HttpResponse<String> authorizedPostJson(
            HttpClient client,
            URI uri,
            String json,
            String token
    ) throws Exception {
        return client.send(
                HttpRequest.newBuilder(uri)
                        .timeout(Duration.ofSeconds(10))
                        .header("Authorization", "Bearer " + token)
                        .header("Content-Type", "application/json")
                        .POST(HttpRequest.BodyPublishers.ofString(json, StandardCharsets.UTF_8))
                        .build(),
                HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8)
        );
    }

    private static String digest(String token) throws Exception {
        return HexFormat.of().formatHex(
                MessageDigest.getInstance("SHA-256")
                        .digest(token.getBytes(StandardCharsets.UTF_8))
        );
    }

    private static void deleteTree(Path root) throws Exception {
        if (!Files.exists(root)) return;
        try (var paths = Files.walk(root)) {
            paths.sorted(Comparator.reverseOrder()).forEach(path -> {
                try {
                    Files.deleteIfExists(path);
                } catch (java.io.IOException exception) {
                    throw new RuntimeException(exception);
                }
            });
        }
    }

    private static final class FakeRegistry implements ManagedAssetRegistry {
        private final Map<UUID, ManagedAsset> assets = new LinkedHashMap<>();
        private final Map<UUID, List<Revision>> histories = new LinkedHashMap<>();
        private long tick;

        @Override
        public MutationResult create(UUID id, String key, RevisionDraft draft) {
            for (ManagedAsset asset : assets.values()) {
                if (key != null && key.equals(asset.customerAssetKey())) {
                    return new MutationResult(MutationStatus.CUSTOMER_KEY_CONFLICT, asset);
                }
            }
            Instant now = Instant.parse("2026-08-20T10:00:00Z").plusSeconds(tick++);
            Revision revision = revision(id, 1, draft, now);
            ManagedAsset asset = new ManagedAsset(id, key, now, revision);
            assets.put(id, asset);
            histories.put(id, new ArrayList<>(List.of(revision)));
            return new MutationResult(MutationStatus.CREATED, asset);
        }

        @Override
        public MutationResult revise(UUID id, int expected, RevisionDraft draft) {
            ManagedAsset current = assets.get(id);
            if (current == null) return new MutationResult(MutationStatus.NOT_FOUND, null);
            int revision = current.currentRevision().revision();
            if (revision == expected + 1 && draft.sameCustomerState(current.currentRevision())) {
                return new MutationResult(MutationStatus.REPLAYED, current);
            }
            if (revision != expected) {
                return new MutationResult(MutationStatus.REVISION_CONFLICT, current);
            }
            if (draft.sameCustomerState(current.currentRevision())) {
                return new MutationResult(MutationStatus.REPLAYED, current);
            }
            Instant now = Instant.parse("2026-08-20T10:00:00Z").plusSeconds(tick++);
            Revision next = revision(id, revision + 1, draft, now);
            ManagedAsset updated = new ManagedAsset(
                    id,
                    current.customerAssetKey(),
                    current.createdAt(),
                    next
            );
            assets.put(id, updated);
            histories.get(id).add(next);
            return new MutationResult(MutationStatus.UPDATED, updated);
        }

        @Override
        public Optional<ManagedAsset> find(UUID id) {
            return Optional.ofNullable(assets.get(id));
        }

        @Override
        public ManagedAssetPage list(int limit, UUID afterId, LifecycleFilter filter) {
            List<ManagedAsset> all = assets.values().stream()
                    .filter(asset -> afterId == null || asset.id().compareTo(afterId) > 0)
                    .filter(asset -> filter == LifecycleFilter.ALL
                            || asset.currentRevision().lifecycleStatus().name().equals(filter.name()))
                    .sorted(Comparator.comparing(ManagedAsset::id))
                    .toList();
            boolean more = all.size() > limit;
            List<ManagedAsset> page = all.subList(0, Math.min(limit, all.size()));
            UUID next = more ? page.get(page.size() - 1).id() : null;
            return new ManagedAssetPage(page, next);
        }

        @Override
        public Optional<RevisionPage> history(UUID id, int limit, Integer beforeRevision) {
            List<Revision> history = histories.get(id);
            if (history == null) return Optional.empty();
            List<Revision> all = history.stream()
                    .filter(revision -> beforeRevision == null
                            || revision.revision() < beforeRevision)
                    .sorted(Comparator.comparingInt(Revision::revision).reversed())
                    .toList();
            boolean more = all.size() > limit;
            List<Revision> page = all.subList(0, Math.min(limit, all.size()));
            Integer next = more ? page.get(page.size() - 1).revision() : null;
            return Optional.of(new RevisionPage(id, page, next));
        }

        private static Revision revision(UUID id, int number, RevisionDraft draft, Instant now) {
            String sha = sha256(id + "|" + number + "|" + draft + "|" + now);
            return new Revision(
                    UUID.nameUUIDFromBytes((id + ":" + number).getBytes(StandardCharsets.UTF_8)),
                    id,
                    number,
                    draft.lifecycleStatus(),
                    draft.displayName(),
                    draft.environment(),
                    draft.businessService(),
                    draft.businessOwner(),
                    draft.businessCriticality(),
                    draft.classificationMethod(),
                    draft.guideContractId(),
                    draft.guideRevision(),
                    ManagedAsset.CONTEXT_SOURCE,
                    sha,
                    draft.changedBy(),
                    draft.changeNote(),
                    now
            );
        }

        private static String sha256(String value) {
            try {
                return HexFormat.of().formatHex(
                        MessageDigest.getInstance("SHA-256")
                                .digest(value.getBytes(StandardCharsets.UTF_8))
                );
            } catch (java.security.NoSuchAlgorithmException exception) {
                throw new IllegalStateException(exception);
            }
        }
    }
}

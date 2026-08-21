package io.rbvm.csv;

import io.rbvm.asset.ManagedAssetRegistry;
import io.rbvm.asset.ScannerManagedAssetLink;
import io.rbvm.asset.ScannerManagedAssetLink.ChangeDraft;
import io.rbvm.asset.ScannerManagedAssetLink.LinkMethod;
import io.rbvm.asset.ScannerManagedAssetLink.LinkStatus;
import io.rbvm.asset.ScannerManagedAssetLinkRegistry;
import io.rbvm.asset.ScannerManagedAssetLinkRegistry.CurrentLookup;
import io.rbvm.asset.ScannerManagedAssetLinkRegistry.HistoryPage;
import io.rbvm.asset.ScannerManagedAssetLinkRegistry.MutationResult;
import io.rbvm.asset.ScannerManagedAssetLinkRegistry.MutationStatus;
import io.rbvm.asset.ScannerManagedAssetLinkRegistry.ScannerAssetPage;
import io.rbvm.asset.ScannerManagedAssetLinkRegistry.ScannerAssetSummary;
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

public final class CsvScannerManagedAssetLinkHttpSelfTest {
    private CsvScannerManagedAssetLinkHttpSelfTest() {
    }

    public static void main(String[] args) throws Exception {
        exposesLinkLifecycleAndHistory();
        reportsCapabilityUnavailableWithoutV19();
        protectsUnavailableCapabilityBehindAuthentication();
        System.out.println("CsvScannerManagedAssetLinkHttpSelfTest: PASS");
    }

    private static void exposesLinkLifecycleAndHistory() throws Exception {
        Path data = Files.createTempDirectory("rbvm-link-http-");
        FakeRegistry registry = new FakeRegistry();
        UUID scanner = UUID.fromString("10000000-0000-0000-0000-000000000001");
        UUID managed = UUID.fromString("20000000-0000-0000-0000-000000000001");
        registry.addScanner(scanner, "wazuh-prod-01");
        registry.managedAssets.add(managed);
        HttpClient client = client();
        try (CsvPlatformServer server = server(
                data,
                Optional.of(registry),
                ApiKeyAuthenticator.disabled()
        )) {
            server.start();
            URI base = server.baseUri();

            HttpResponse<String> health = get(client, base.resolve("/api/v1/health"), null);
            assert health.statusCode() == 200 : health.body();
            assert health.body().contains("\"scannerManagedAssetLinks\"");
            assert health.body().contains("\"historyReadEnabled\": true");

            HttpResponse<String> listed = get(client, base.resolve("/api/v1/scanner-assets?limit=10"), null);
            assert listed.statusCode() == 200 : listed.body();
            assert listed.body().contains(scanner.toString());
            assert listed.body().contains("wazuh-prod-01");
            assert listed.body().contains("\"currentLink\": null");

            URI currentUri = base.resolve("/api/v1/scanner-assets/" + scanner + "/managed-asset-link");
            HttpResponse<String> initial = get(client, currentUri, null);
            assert initial.statusCode() == 200 : initial.body();
            String zero = initial.headers().firstValue("ETag").orElseThrow();
            assert zero.startsWith("\"sma-r0-");

            String linkJson = """
                    {
                      "linkStatus": "LINKED",
                      "managedAssetId": "20000000-0000-0000-0000-000000000001",
                      "changeNote": "customer confirmed"
                    }
                    """;
            URI revisions = base.resolve("/api/v1/scanner-assets/" + scanner
                    + "/managed-asset-link/revisions");
            HttpResponse<String> missingPrecondition = postJson(client, revisions, linkJson, null, null);
            assert missingPrecondition.statusCode() == 428 : missingPrecondition.body();

            HttpResponse<String> linked = postJson(client, revisions, linkJson, zero, null);
            assert linked.statusCode() == 200 : linked.body();
            String etag1 = linked.headers().firstValue("ETag").orElseThrow();
            assert etag1.startsWith("\"sma-r1-");
            assert linked.body().contains("\"linkStatus\": \"LINKED\"");
            assert linked.body().contains("\"managedAssetId\": \"" + managed + "\"");
            assert linked.body().contains("\"changedBy\": \"local-operator\"");

            HttpResponse<String> replay = postJson(client, revisions, linkJson, zero, null);
            assert replay.statusCode() == 200 : replay.body();
            assert replay.headers().firstValue("ETag").orElseThrow().equals(etag1);
            assert registry.current(scanner).current().revision() == 1;

            HttpResponse<String> history = get(client, URI.create(revisions + "?limit=10"), null);
            assert history.statusCode() == 200 : history.body();
            assert history.body().contains("\"revision\": 1");
            assert history.body().contains("\"nextBeforeRevision\": null");

            HttpRequest delete = HttpRequest.newBuilder(currentUri)
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

    private static void reportsCapabilityUnavailableWithoutV19() throws Exception {
        Path data = Files.createTempDirectory("rbvm-link-disabled-");
        HttpClient client = client();
        try (CsvPlatformServer server = new CsvPlatformServer(
                "127.0.0.1", 0, data, 1024 * 1024)) {
            server.start();
            URI base = server.baseUri();
            HttpResponse<String> health = get(client, base.resolve("/api/v1/health"), null);
            assert health.body().contains("\"scannerManagedAssetLinks\"");
            assert health.body().contains("\"historyReadEnabled\": false");
            HttpResponse<String> unavailable = get(client, base.resolve("/api/v1/scanner-assets"), null);
            assert unavailable.statusCode() == 503 : unavailable.body();
            assert unavailable.body().contains("SCANNER MANAGED ASSET LINK PERSISTENCE UNAVAILABLE");
        } finally {
            deleteTree(data);
        }
    }

    private static void protectsUnavailableCapabilityBehindAuthentication() throws Exception {
        Path data = Files.createTempDirectory("rbvm-link-auth-");
        String viewerToken = "link-viewer-token-abcdefghijklmnopqrstuvwxyz-123";
        String operatorToken = "link-operator-token-abcdefghijklmnopqrstuvwxyz";
        Path keyRegistry = data.resolve("api-keys.conf");
        Files.writeString(
                keyRegistry,
                digest(viewerToken) + "=link-viewer|VIEWER\n"
                        + digest(operatorToken) + "=link-operator|OPERATOR\n",
                StandardCharsets.UTF_8
        );
        try {
            Files.setPosixFilePermissions(keyRegistry, Set.of(
                    PosixFilePermission.OWNER_READ,
                    PosixFilePermission.OWNER_WRITE
            ));
        } catch (UnsupportedOperationException ignored) {
        }
        HttpClient client = client();
        try (CsvPlatformServer server = server(
                data.resolve("evidence"),
                Optional.empty(),
                ApiKeyAuthenticator.fromFile(keyRegistry)
        )) {
            server.start();
            URI base = server.baseUri();
            HttpResponse<String> missing = get(client, base.resolve("/api/v1/scanner-assets"), null);
            assert missing.statusCode() == 401 : missing.body();

            HttpResponse<String> viewerUnavailable = get(
                    client,
                    base.resolve("/api/v1/scanner-assets"),
                    viewerToken
            );
            assert viewerUnavailable.statusCode() == 503 : viewerUnavailable.body();

            UUID scanner = UUID.fromString("10000000-0000-0000-0000-000000000001");
            URI revisions = base.resolve("/api/v1/scanner-assets/" + scanner
                    + "/managed-asset-link/revisions");
            String json = "{\"linkStatus\":\"UNLINKED\"}";
            HttpResponse<String> viewerDenied = postJson(client, revisions, json, "\"sma-r0-"
                    + "0".repeat(64) + "\"", viewerToken);
            assert viewerDenied.statusCode() == 403 : viewerDenied.body();

            HttpResponse<String> operatorUnavailable = postJson(client, revisions, json, "\"sma-r0-"
                    + "0".repeat(64) + "\"", operatorToken);
            assert operatorUnavailable.statusCode() == 503 : operatorUnavailable.body();
        } finally {
            deleteTree(data);
        }
    }

    private static CsvPlatformServer server(
            Path data,
            Optional<ScannerManagedAssetLinkRegistry> registry,
            ApiKeyAuthenticator authenticator
    ) throws Exception {
        return new CsvPlatformServer(
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
                Optional.empty(), Optional.empty(),
                Optional.<ManagedAssetRegistry>empty(),
                registry,
                authenticator,
                RequestRateLimiter.disabled()
        );
    }

    private static HttpClient client() {
        return HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build();
    }

    private static HttpResponse<String> get(HttpClient client, URI uri, String token) throws Exception {
        HttpRequest.Builder request = HttpRequest.newBuilder(uri)
                .timeout(Duration.ofSeconds(10));
        if (token != null) request.header("Authorization", "Bearer " + token);
        return client.send(
                request.GET().build(),
                HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8)
        );
    }

    private static HttpResponse<String> postJson(
            HttpClient client,
            URI uri,
            String json,
            String ifMatch,
            String token
    ) throws Exception {
        HttpRequest.Builder request = HttpRequest.newBuilder(uri)
                .timeout(Duration.ofSeconds(10))
                .header("Content-Type", "application/json");
        if (ifMatch != null) request.header("If-Match", ifMatch);
        if (token != null) request.header("Authorization", "Bearer " + token);
        return client.send(
                request.POST(HttpRequest.BodyPublishers.ofString(json, StandardCharsets.UTF_8)).build(),
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

    private static final class FakeRegistry implements ScannerManagedAssetLinkRegistry {
        private final Map<UUID, ScannerAssetSummary> scanners = new LinkedHashMap<>();
        private final Map<UUID, List<ScannerManagedAssetLink>> histories = new LinkedHashMap<>();
        private final Set<UUID> managedAssets = new java.util.HashSet<>();
        private long tick;

        void addScanner(UUID id, String name) {
            scanners.put(id, new ScannerAssetSummary(
                    id,
                    name,
                    "Linux",
                    "wazuh-prod",
                    "SOURCE_NAME_ONLY",
                    "LOW",
                    Instant.parse("2026-08-20T00:00:00Z"),
                    Instant.parse("2026-08-20T01:00:00Z"),
                    null
            ));
            histories.put(id, new ArrayList<>());
        }

        @Override
        public MutationResult revise(UUID scannerAssetId, int expectedRevision, ChangeDraft draft) {
            if (!scanners.containsKey(scannerAssetId)) {
                return new MutationResult(MutationStatus.SCANNER_ASSET_NOT_FOUND, null);
            }
            ScannerManagedAssetLink current = current(scannerAssetId).current();
            if (draft.linkStatus() == LinkStatus.LINKED && !managedAssets.contains(draft.managedAssetId())) {
                return new MutationResult(MutationStatus.MANAGED_ASSET_NOT_FOUND, current);
            }
            if (current == null) {
                if (expectedRevision != 0) return new MutationResult(MutationStatus.REVISION_CONFLICT, null);
                ScannerManagedAssetLink created = materialize(scannerAssetId, 1, draft);
                histories.get(scannerAssetId).add(created);
                return new MutationResult(MutationStatus.UPDATED, created);
            }
            if (current.revision() == expectedRevision + 1 && current.sameCustomerState(draft)) {
                return new MutationResult(MutationStatus.REPLAYED, current);
            }
            if (current.revision() != expectedRevision) {
                return new MutationResult(MutationStatus.REVISION_CONFLICT, current);
            }
            if (current.sameCustomerState(draft)) return new MutationResult(MutationStatus.REPLAYED, current);
            ScannerManagedAssetLink next = materialize(scannerAssetId, current.revision() + 1, draft);
            histories.get(scannerAssetId).add(next);
            return new MutationResult(MutationStatus.UPDATED, next);
        }

        @Override
        public CurrentLookup current(UUID scannerAssetId) {
            if (!scanners.containsKey(scannerAssetId)) return new CurrentLookup(false, null);
            List<ScannerManagedAssetLink> rows = histories.get(scannerAssetId);
            return new CurrentLookup(true, rows.isEmpty() ? null : rows.get(rows.size() - 1));
        }

        @Override
        public Optional<HistoryPage> history(UUID scannerAssetId, int limit, Integer beforeRevision) {
            if (!scanners.containsKey(scannerAssetId)) return Optional.empty();
            List<ScannerManagedAssetLink> all = histories.get(scannerAssetId).stream()
                    .filter(event -> beforeRevision == null || event.revision() < beforeRevision)
                    .sorted(Comparator.comparingInt(ScannerManagedAssetLink::revision).reversed())
                    .toList();
            boolean more = all.size() > limit;
            List<ScannerManagedAssetLink> page = all.subList(0, Math.min(limit, all.size()));
            Integer next = more ? page.get(page.size() - 1).revision() : null;
            return Optional.of(new HistoryPage(scannerAssetId, page, next));
        }

        @Override
        public ScannerAssetPage list(int limit, UUID afterId) {
            List<ScannerAssetSummary> all = scanners.values().stream()
                    .filter(asset -> afterId == null || asset.scannerAssetId().compareTo(afterId) > 0)
                    .sorted(Comparator.comparing(ScannerAssetSummary::scannerAssetId))
                    .map(asset -> new ScannerAssetSummary(
                            asset.scannerAssetId(), asset.observedName(), asset.osNameRaw(),
                            asset.sourceProfileKey(), asset.identityBasis(), asset.identityConfidence(),
                            asset.firstObservedAt(), asset.lastObservedAt(), current(asset.scannerAssetId()).current()
                    ))
                    .toList();
            boolean more = all.size() > limit;
            List<ScannerAssetSummary> page = all.subList(0, Math.min(limit, all.size()));
            UUID next = more ? page.get(page.size() - 1).scannerAssetId() : null;
            return new ScannerAssetPage(page, next);
        }

        private ScannerManagedAssetLink materialize(UUID scannerAssetId, int revision, ChangeDraft draft) {
            return new ScannerManagedAssetLink(
                    UUID.nameUUIDFromBytes((scannerAssetId + ":" + revision).getBytes(StandardCharsets.UTF_8)),
                    scannerAssetId,
                    revision,
                    draft.linkStatus(),
                    draft.managedAssetId(),
                    LinkMethod.CUSTOMER_CONFIRMED,
                    ScannerManagedAssetLink.evidenceSha256(
                            scannerAssetId, revision, draft.linkStatus(), draft.managedAssetId()),
                    draft.changedBy(),
                    draft.changeNote(),
                    Instant.parse("2026-08-20T10:00:00Z").plusSeconds(tick++)
            );
        }
    }
}

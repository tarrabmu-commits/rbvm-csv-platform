package io.rbvm.csv;

import io.rbvm.asset.ManagedAssetRegistry;
import io.rbvm.asset.ScannerManagedAssetLinkRegistry;
import io.rbvm.context.FindingBusinessServiceLink;
import io.rbvm.context.FindingBusinessServiceLinkRegistry;
import io.rbvm.context.FindingReachabilityScopeLink;
import io.rbvm.context.FindingReachabilityScopeLink.OriginScope;
import io.rbvm.context.FindingReachabilityScopeLink.TransportProtocol;
import io.rbvm.context.FindingReachabilityScopeLinkRegistry;
import io.rbvm.domain.InMemoryDomainCatalog;
import io.rbvm.postgres.FindingContextAssociationRuntime;
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

public final class CsvFindingContextAssociationHttpSelfTest {
    private static final UUID FINDING = UUID.fromString("10000000-0000-0000-0000-000000000001");

    private CsvFindingContextAssociationHttpSelfTest() {
    }

    public static void main(String[] args) throws Exception {
        exposesExplicitAssociationsWithRoleBoundaries();
        protectsUnavailableCapabilityBehindAuthentication();
        System.out.println("CsvFindingContextAssociationHttpSelfTest: PASS");
    }

    private static void exposesExplicitAssociationsWithRoleBoundaries() throws Exception {
        Path data = Files.createTempDirectory("rbvm-finding-context-http-");
        String viewerToken = "finding-context-viewer-token-abcdefghijklmnopqrstuvwxyz";
        String operatorToken = "finding-context-operator-token-abcdefghijklmnopqrstuv";
        Path keyRegistry = keyRegistry(data, viewerToken, operatorToken);
        FakeReachabilityRegistry reachability = new FakeReachabilityRegistry(Set.of(FINDING));
        FakeBusinessRegistry business = new FakeBusinessRegistry(Set.of(FINDING));
        FindingContextAssociationRuntime runtime = new FindingContextAssociationRuntime(
                Optional.of(reachability),
                Optional.of(business)
        );
        HttpClient client = client();

        try (CsvPlatformServer server = server(
                data.resolve("evidence"),
                runtime,
                ApiKeyAuthenticator.fromFile(keyRegistry)
        )) {
            server.start();
            URI base = server.baseUri();

            HttpResponse<String> health = get(client, base.resolve("/api/v1/health"), viewerToken);
            assert health.statusCode() == 200 : health.body();
            assert health.body().contains("\"findingContextAssociations\"");
            assert health.body().contains("\"historyReadEnabled\": true");

            HttpResponse<String> metrics = get(client, base.resolve("/api/v1/metrics"), viewerToken);
            assert metrics.statusCode() == 200 : metrics.body();
            assert metrics.body().contains("rbvm_finding_context_association_api_enabled 1");

            URI reachabilityCurrent = base.resolve("/api/v1/findings/" + FINDING
                    + "/reachability-links/current?originScope=INTERNET&originLabel=edge%20probe"
                    + "&transportProtocol=TCP&targetPort=443");
            HttpResponse<String> reachabilityInitial = get(client, reachabilityCurrent, viewerToken);
            assert reachabilityInitial.statusCode() == 200 : reachabilityInitial.body();
            assert reachabilityInitial.body().contains("\"associationState\": \"NEVER_ASSESSED\"");
            String reachabilityZero = reachabilityInitial.headers().firstValue("ETag").orElseThrow();
            assert reachabilityZero.startsWith("\"frs-r0-");

            URI reachabilityOther = base.resolve("/api/v1/findings/" + FINDING
                    + "/reachability-links/current?originScope=INTERNET&originLabel=edge%20probe"
                    + "&transportProtocol=TCP&targetPort=8443");
            String otherZero = get(client, reachabilityOther, viewerToken)
                    .headers().firstValue("ETag").orElseThrow();
            assert !reachabilityZero.equals(otherZero);

            String reachabilityJson = """
                    {
                      "linkStatus":"LINKED",
                      "originScope":"INTERNET",
                      "originLabel":"EDGE PROBE",
                      "transportProtocol":"TCP",
                      "targetPort":443,
                      "changeNote":"customer confirmed endpoint"
                    }
                    """;
            HttpResponse<String> viewerWriteDenied = postJson(
                    client, reachabilityCurrent, reachabilityJson, reachabilityZero, viewerToken);
            assert viewerWriteDenied.statusCode() == 403 : viewerWriteDenied.body();

            HttpResponse<String> linked = postJson(
                    client, reachabilityCurrent, reachabilityJson, reachabilityZero, operatorToken);
            assert linked.statusCode() == 200 : linked.body();
            assert linked.body().contains("\"associationState\": \"LINKED\"");
            assert linked.body().contains("\"changedBy\": \"finding-context-operator\"");
            String reachabilityEtag1 = linked.headers().firstValue("ETag").orElseThrow();
            assert reachabilityEtag1.startsWith("\"frs-r1-");

            HttpResponse<String> replay = postJson(
                    client,
                    reachabilityCurrent,
                    reachabilityJson.replace("customer confirmed endpoint", "network retry note"),
                    reachabilityZero,
                    operatorToken
            );
            assert replay.statusCode() == 200 : replay.body();
            assert replay.headers().firstValue("ETag").orElseThrow().equals(reachabilityEtag1);
            assert reachability.history(
                    FINDING, OriginScope.INTERNET, "edge probe", TransportProtocol.TCP, 443, 10, null)
                    .orElseThrow().events().size() == 1;

            URI reachabilityList = base.resolve("/api/v1/findings/" + FINDING
                    + "/reachability-links?limit=10");
            HttpResponse<String> reachabilityListed = get(client, reachabilityList, viewerToken);
            assert reachabilityListed.statusCode() == 200 : reachabilityListed.body();
            assert reachabilityListed.body().contains("\"targetPort\": 443");

            URI reachabilityHistory = base.resolve("/api/v1/findings/" + FINDING
                    + "/reachability-links/revisions?originScope=INTERNET&originLabel=edge%20probe"
                    + "&transportProtocol=TCP&targetPort=443&limit=10");
            HttpResponse<String> reachabilityHistoryResponse = get(
                    client, reachabilityHistory, viewerToken);
            assert reachabilityHistoryResponse.statusCode() == 200 : reachabilityHistoryResponse.body();
            assert reachabilityHistoryResponse.body().contains("\"revision\": 1");

            String spoofed = reachabilityJson.replace(
                    "\"changeNote\":\"customer confirmed endpoint\"",
                    "\"changedBy\":\"mallory\",\"changeNote\":\"customer confirmed endpoint\""
            );
            HttpResponse<String> spoofRejected = postJson(
                    client, reachabilityOther, spoofed.replace("443", "8443"), otherZero, operatorToken);
            assert spoofRejected.statusCode() == 400 : spoofRejected.body();

            URI businessCurrent = base.resolve("/api/v1/findings/" + FINDING
                    + "/business-service-links/current?businessService=Payments");
            HttpResponse<String> businessInitial = get(client, businessCurrent, viewerToken);
            assert businessInitial.statusCode() == 200 : businessInitial.body();
            String businessZero = businessInitial.headers().firstValue("ETag").orElseThrow();
            assert businessZero.startsWith("\"fbs-r0-");

            String businessJson = """
                    {
                      "linkStatus":"LINKED",
                      "businessService":"PAYMENTS",
                      "changeNote":"customer confirmed service"
                    }
                    """;
            HttpResponse<String> businessLinked = postJson(
                    client, businessCurrent, businessJson, businessZero, operatorToken);
            assert businessLinked.statusCode() == 200 : businessLinked.body();
            assert businessLinked.body().contains("\"associationState\": \"LINKED\"");
            assert businessLinked.body().contains("\"changedBy\": \"finding-context-operator\"");

            URI businessList = base.resolve("/api/v1/findings/" + FINDING
                    + "/business-service-links?limit=10");
            HttpResponse<String> businessListed = get(client, businessList, viewerToken);
            assert businessListed.statusCode() == 200 : businessListed.body();
            assert businessListed.body().contains("\"businessService\": \"payments\"");

            URI businessHistory = base.resolve("/api/v1/findings/" + FINDING
                    + "/business-service-links/revisions?businessService=payments&limit=10");
            HttpResponse<String> businessHistoryResponse = get(client, businessHistory, viewerToken);
            assert businessHistoryResponse.statusCode() == 200 : businessHistoryResponse.body();
            assert businessHistoryResponse.body().contains("\"revision\": 1");
        } finally {
            deleteTree(data);
        }
    }

    private static void protectsUnavailableCapabilityBehindAuthentication() throws Exception {
        Path data = Files.createTempDirectory("rbvm-finding-context-disabled-");
        String viewerToken = "finding-context-viewer-disabled-abcdefghijklmnopqrstuvwxyz";
        String operatorToken = "finding-context-operator-disabled-abcdefghijklmnopqrstuv";
        Path keyRegistry = keyRegistry(data, viewerToken, operatorToken);
        HttpClient client = client();

        try (CsvPlatformServer server = server(
                data.resolve("evidence"),
                FindingContextAssociationRuntime.disabled(),
                ApiKeyAuthenticator.fromFile(keyRegistry)
        )) {
            server.start();
            URI current = server.baseUri().resolve("/api/v1/findings/" + FINDING
                    + "/business-service-links/current?businessService=payments");

            HttpResponse<String> missing = get(client, current, null);
            assert missing.statusCode() == 401 : missing.body();

            HttpResponse<String> viewerUnavailable = get(client, current, viewerToken);
            assert viewerUnavailable.statusCode() == 503 : viewerUnavailable.body();
            assert viewerUnavailable.body().contains("FINDING CONTEXT ASSOCIATION PERSISTENCE UNAVAILABLE");

            String json = "{\"linkStatus\":\"LINKED\",\"businessService\":\"payments\"}";
            HttpResponse<String> viewerDenied = postJson(
                    client, current, json, "\"fbs-r0-" + "0".repeat(64) + "\"", viewerToken);
            assert viewerDenied.statusCode() == 403 : viewerDenied.body();

            HttpResponse<String> operatorUnavailable = postJson(
                    client, current, json, "\"fbs-r0-" + "0".repeat(64) + "\"", operatorToken);
            assert operatorUnavailable.statusCode() == 503 : operatorUnavailable.body();
        } finally {
            deleteTree(data);
        }
    }

    private static Path keyRegistry(Path data, String viewerToken, String operatorToken) throws Exception {
        Path keyRegistry = data.resolve("api-keys.conf");
        Files.writeString(
                keyRegistry,
                digest(viewerToken) + "=finding-context-viewer|VIEWER\n"
                        + digest(operatorToken) + "=finding-context-operator|OPERATOR\n",
                StandardCharsets.UTF_8
        );
        try {
            Files.setPosixFilePermissions(keyRegistry, Set.of(
                    PosixFilePermission.OWNER_READ,
                    PosixFilePermission.OWNER_WRITE
            ));
        } catch (UnsupportedOperationException ignored) {
        }
        return keyRegistry;
    }

    private static CsvPlatformServer server(
            Path data,
            FindingContextAssociationRuntime runtime,
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
                Optional.<ScannerManagedAssetLinkRegistry>empty(),
                runtime,
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

    private static final class FakeReachabilityRegistry implements FindingReachabilityScopeLinkRegistry {
        private final Set<UUID> findings;
        private final Map<String, List<FindingReachabilityScopeLink>> histories = new LinkedHashMap<>();
        private long tick;

        FakeReachabilityRegistry(Set<UUID> findings) {
            this.findings = Set.copyOf(findings);
        }

        @Override
        public MutationResult revise(UUID findingId, int expectedRevision, FindingReachabilityScopeLink.ChangeDraft draft) {
            if (!findings.contains(findingId)) return new MutationResult(MutationStatus.FINDING_NOT_FOUND, null);
            String key = key(findingId, draft.originScope(), draft.originLabel(), draft.transportProtocol(), draft.targetPort());
            List<FindingReachabilityScopeLink> events = histories.computeIfAbsent(key, ignored -> new ArrayList<>());
            FindingReachabilityScopeLink current = events.isEmpty() ? null : events.get(events.size() - 1);
            if (current == null) {
                if (expectedRevision != 0) return new MutationResult(MutationStatus.REVISION_CONFLICT, null);
                FindingReachabilityScopeLink created = materialize(findingId, 1, draft);
                events.add(created);
                return new MutationResult(MutationStatus.UPDATED, created);
            }
            if (current.revision() == expectedRevision + 1 && current.sameCustomerState(draft)) {
                return new MutationResult(MutationStatus.REPLAYED, current);
            }
            if (current.revision() != expectedRevision) return new MutationResult(MutationStatus.REVISION_CONFLICT, current);
            if (current.sameCustomerState(draft)) return new MutationResult(MutationStatus.REPLAYED, current);
            FindingReachabilityScopeLink next = materialize(findingId, current.revision() + 1, draft);
            events.add(next);
            return new MutationResult(MutationStatus.UPDATED, next);
        }

        @Override
        public CurrentLookup current(
                UUID findingId,
                OriginScope originScope,
                String originLabel,
                TransportProtocol transportProtocol,
                Integer targetPort
        ) {
            if (!findings.contains(findingId)) return new CurrentLookup(false, null);
            List<FindingReachabilityScopeLink> events = histories.getOrDefault(
                    key(findingId, originScope, originLabel, transportProtocol, targetPort),
                    List.of()
            );
            return new CurrentLookup(true, events.isEmpty() ? null : events.get(events.size() - 1));
        }

        @Override
        public Optional<HistoryPage> history(
                UUID findingId,
                OriginScope originScope,
                String originLabel,
                TransportProtocol transportProtocol,
                Integer targetPort,
                int limit,
                Integer beforeRevision
        ) {
            if (!findings.contains(findingId)) return Optional.empty();
            String key = key(findingId, originScope, originLabel, transportProtocol, targetPort);
            List<FindingReachabilityScopeLink> all = histories.getOrDefault(key, List.of()).stream()
                    .filter(event -> beforeRevision == null || event.revision() < beforeRevision)
                    .sorted(Comparator.comparingInt(FindingReachabilityScopeLink::revision).reversed())
                    .toList();
            boolean more = all.size() > limit;
            List<FindingReachabilityScopeLink> page = all.subList(0, Math.min(limit, all.size()));
            Integer next = more ? page.get(page.size() - 1).revision() : null;
            String scopeKey = page.isEmpty()
                    ? new FindingReachabilityScopeLink.ChangeDraft(
                            FindingReachabilityScopeLink.LinkStatus.LINKED,
                            originScope,
                            originLabel,
                            transportProtocol,
                            targetPort,
                            "test-actor",
                            "test"
                    ).originScope().name() + "|" + originLabel.trim().toLowerCase()
                            + "|" + transportProtocol.name() + "|" + (targetPort == null ? "" : targetPort)
                    : page.get(0).scopeKey();
            if (page.isEmpty()) {
                FindingReachabilityScopeLink probe = materialize(
                        findingId,
                        1,
                        new FindingReachabilityScopeLink.ChangeDraft(
                                FindingReachabilityScopeLink.LinkStatus.LINKED,
                                originScope,
                                originLabel,
                                transportProtocol,
                                targetPort,
                                "test-actor",
                                "test"
                        )
                );
                scopeKey = probe.scopeKey();
            }
            return Optional.of(new HistoryPage(findingId, scopeKey, page, next));
        }

        @Override
        public Optional<CurrentPage> listCurrent(UUID findingId, int limit, UUID afterEventId) {
            if (!findings.contains(findingId)) return Optional.empty();
            List<FindingReachabilityScopeLink> all = histories.values().stream()
                    .filter(events -> !events.isEmpty())
                    .map(events -> events.get(events.size() - 1))
                    .filter(link -> link.findingId().equals(findingId))
                    .filter(link -> afterEventId == null || link.eventId().compareTo(afterEventId) > 0)
                    .sorted(Comparator.comparing(FindingReachabilityScopeLink::eventId))
                    .toList();
            boolean more = all.size() > limit;
            List<FindingReachabilityScopeLink> page = all.subList(0, Math.min(limit, all.size()));
            UUID next = more ? page.get(page.size() - 1).eventId() : null;
            return Optional.of(new CurrentPage(findingId, page, next));
        }

        private FindingReachabilityScopeLink materialize(
                UUID findingId,
                int revision,
                FindingReachabilityScopeLink.ChangeDraft draft
        ) {
            return new FindingReachabilityScopeLink(
                    UUID.nameUUIDFromBytes((findingId + ":r:" + draft.originLabel() + ":" + draft.targetPort()
                            + ":" + revision).getBytes(StandardCharsets.UTF_8)),
                    findingId,
                    revision,
                    draft.linkStatus(),
                    draft.originScope(),
                    draft.originLabel(),
                    draft.transportProtocol(),
                    draft.targetPort(),
                    FindingReachabilityScopeLink.LinkMethod.CUSTOMER_CONFIRMED,
                    FindingReachabilityScopeLink.evidenceSha256(
                            findingId,
                            revision,
                            draft.linkStatus(),
                            draft.originScope(),
                            draft.originLabel(),
                            draft.transportProtocol(),
                            draft.targetPort()
                    ),
                    draft.changedBy(),
                    draft.changeNote(),
                    Instant.parse("2026-08-22T00:00:00Z").plusSeconds(tick++)
            );
        }

        private static String key(
                UUID findingId,
                OriginScope originScope,
                String originLabel,
                TransportProtocol protocol,
                Integer port
        ) {
            return findingId + "|" + originScope + "|" + originLabel.trim().toLowerCase()
                    + "|" + protocol + "|" + port;
        }
    }

    private static final class FakeBusinessRegistry implements FindingBusinessServiceLinkRegistry {
        private final Set<UUID> findings;
        private final Map<String, List<FindingBusinessServiceLink>> histories = new LinkedHashMap<>();
        private long tick;

        FakeBusinessRegistry(Set<UUID> findings) {
            this.findings = Set.copyOf(findings);
        }

        @Override
        public MutationResult revise(UUID findingId, int expectedRevision, FindingBusinessServiceLink.ChangeDraft draft) {
            if (!findings.contains(findingId)) return new MutationResult(MutationStatus.FINDING_NOT_FOUND, null);
            String key = key(findingId, draft.businessService());
            List<FindingBusinessServiceLink> events = histories.computeIfAbsent(key, ignored -> new ArrayList<>());
            FindingBusinessServiceLink current = events.isEmpty() ? null : events.get(events.size() - 1);
            if (current == null) {
                if (expectedRevision != 0) return new MutationResult(MutationStatus.REVISION_CONFLICT, null);
                FindingBusinessServiceLink created = materialize(findingId, 1, draft);
                events.add(created);
                return new MutationResult(MutationStatus.UPDATED, created);
            }
            if (current.revision() == expectedRevision + 1 && current.sameCustomerState(draft)) {
                return new MutationResult(MutationStatus.REPLAYED, current);
            }
            if (current.revision() != expectedRevision) return new MutationResult(MutationStatus.REVISION_CONFLICT, current);
            if (current.sameCustomerState(draft)) return new MutationResult(MutationStatus.REPLAYED, current);
            FindingBusinessServiceLink next = materialize(findingId, current.revision() + 1, draft);
            events.add(next);
            return new MutationResult(MutationStatus.UPDATED, next);
        }

        @Override
        public CurrentLookup current(UUID findingId, String businessService) {
            if (!findings.contains(findingId)) return new CurrentLookup(false, null);
            List<FindingBusinessServiceLink> events = histories.getOrDefault(key(findingId, businessService), List.of());
            return new CurrentLookup(true, events.isEmpty() ? null : events.get(events.size() - 1));
        }

        @Override
        public Optional<HistoryPage> history(
                UUID findingId,
                String businessService,
                int limit,
                Integer beforeRevision
        ) {
            if (!findings.contains(findingId)) return Optional.empty();
            String service = businessService.trim().toLowerCase();
            List<FindingBusinessServiceLink> all = histories.getOrDefault(key(findingId, service), List.of()).stream()
                    .filter(event -> beforeRevision == null || event.revision() < beforeRevision)
                    .sorted(Comparator.comparingInt(FindingBusinessServiceLink::revision).reversed())
                    .toList();
            boolean more = all.size() > limit;
            List<FindingBusinessServiceLink> page = all.subList(0, Math.min(limit, all.size()));
            Integer next = more ? page.get(page.size() - 1).revision() : null;
            return Optional.of(new HistoryPage(findingId, service, page, next));
        }

        @Override
        public Optional<CurrentPage> listCurrent(UUID findingId, int limit, UUID afterEventId) {
            if (!findings.contains(findingId)) return Optional.empty();
            List<FindingBusinessServiceLink> all = histories.values().stream()
                    .filter(events -> !events.isEmpty())
                    .map(events -> events.get(events.size() - 1))
                    .filter(link -> link.findingId().equals(findingId))
                    .filter(link -> afterEventId == null || link.eventId().compareTo(afterEventId) > 0)
                    .sorted(Comparator.comparing(FindingBusinessServiceLink::eventId))
                    .toList();
            boolean more = all.size() > limit;
            List<FindingBusinessServiceLink> page = all.subList(0, Math.min(limit, all.size()));
            UUID next = more ? page.get(page.size() - 1).eventId() : null;
            return Optional.of(new CurrentPage(findingId, page, next));
        }

        private FindingBusinessServiceLink materialize(
                UUID findingId,
                int revision,
                FindingBusinessServiceLink.ChangeDraft draft
        ) {
            return new FindingBusinessServiceLink(
                    UUID.nameUUIDFromBytes((findingId + ":b:" + draft.businessService() + ":" + revision)
                            .getBytes(StandardCharsets.UTF_8)),
                    findingId,
                    revision,
                    draft.linkStatus(),
                    draft.businessService(),
                    FindingBusinessServiceLink.LinkMethod.CUSTOMER_CONFIRMED,
                    FindingBusinessServiceLink.evidenceSha256(
                            findingId,
                            revision,
                            draft.linkStatus(),
                            draft.businessService()
                    ),
                    draft.changedBy(),
                    draft.changeNote(),
                    Instant.parse("2026-08-22T00:00:00Z").plusSeconds(tick++)
            );
        }

        private static String key(UUID findingId, String service) {
            return findingId + "|" + service.trim().toLowerCase();
        }
    }
}

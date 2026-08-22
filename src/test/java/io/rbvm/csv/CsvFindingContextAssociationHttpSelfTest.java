package io.rbvm.csv;

import io.rbvm.context.FindingBusinessServiceLink;
import io.rbvm.context.FindingBusinessServiceLinkRegistry;
import io.rbvm.context.FindingReachabilityScopeLink;
import io.rbvm.context.FindingReachabilityScopeLink.OriginScope;
import io.rbvm.context.FindingReachabilityScopeLink.TransportProtocol;
import io.rbvm.context.FindingReachabilityScopeLinkRegistry;
import io.rbvm.domain.InMemoryDomainCatalog;
import io.rbvm.security.ApiKeyAuthenticator;
import io.rbvm.security.RequestRateLimiter;

import java.net.URI;
import java.net.URLEncoder;
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

/** Socket-level proof for the explicit Finding-context association APIs. */
public final class CsvFindingContextAssociationHttpSelfTest {
    private CsvFindingContextAssociationHttpSelfTest() {
    }

    public static void main(String[] args) throws Exception {
        exposesExplicitAssociationLifecycle();
        reportsCapabilityUnavailableWithoutV21();
        protectsUnavailableCapabilityBehindAuthentication();
        System.out.println("CsvFindingContextAssociationHttpSelfTest: PASS");
    }

    private static void exposesExplicitAssociationLifecycle() throws Exception {
        Path data = Files.createTempDirectory("rbvm-finding-context-http-");
        UUID finding = UUID.fromString("30000000-0000-0000-0000-000000000001");
        FakeReachabilityRegistry reachability = new FakeReachabilityRegistry(Set.of(finding));
        FakeBusinessRegistry business = new FakeBusinessRegistry(Set.of(finding));
        HttpClient client = client();
        try (CsvPlatformServer server = new CsvPlatformServer(
                "127.0.0.1", 0, data, 1024 * 1024)) {
            server.enableFindingContextAssociationApi(reachability, business);
            server.start();
            URI base = server.baseUri();

            HttpResponse<String> health = get(client, base.resolve("/api/v1/health"), null);
            assert health.statusCode() == 200 : health.body();
            assert health.body().contains("\"findingContextAssociations\"");
            assert health.body().contains("\"historyReadEnabled\": true");

            String reachQuery = "originScope=INTERNET&originLabel=public-edge"
                    + "&transportProtocol=TCP&targetPort=443";
            URI reachCurrent = URI.create(base + "api/v1/findings/" + finding
                    + "/reachability-links/current?" + reachQuery);
            HttpResponse<String> reachInitial = get(client, reachCurrent, null);
            assert reachInitial.statusCode() == 200 : reachInitial.body();
            assert reachInitial.body().contains("\"associationState\": \"NEVER_ASSESSED\"");
            String reachZero = reachInitial.headers().firstValue("ETag").orElseThrow();
            assert reachZero.startsWith("\"frs-r0-");

            URI otherReachCurrent = URI.create(base + "api/v1/findings/" + finding
                    + "/reachability-links/current?originScope=INTERNET&originLabel=public-edge"
                    + "&transportProtocol=TCP&targetPort=8443");
            String otherZero = get(client, otherReachCurrent, null)
                    .headers().firstValue("ETag").orElseThrow();
            assert !reachZero.equals(otherZero) : "zero-state ETag must bind the exact scope";

            String reachJson = """
                    {
                      "linkStatus": "LINKED",
                      "originScope": "INTERNET",
                      "originLabel": "public-edge",
                      "transportProtocol": "TCP",
                      "targetPort": 443,
                      "changeNote": "customer confirmed public route"
                    }
                    """;
            URI reachMutation = base.resolve("/api/v1/findings/" + finding
                    + "/reachability-links/current");
            HttpResponse<String> reachMissingPrecondition = postJson(
                    client, reachMutation, reachJson, null, null);
            assert reachMissingPrecondition.statusCode() == 428 : reachMissingPrecondition.body();

            HttpResponse<String> reachLinked = postJson(
                    client, reachMutation, reachJson, reachZero, null);
            assert reachLinked.statusCode() == 200 : reachLinked.body();
            String reachEtag1 = reachLinked.headers().firstValue("ETag").orElseThrow();
            assert reachEtag1.startsWith("\"frs-r1-");
            assert reachLinked.body().contains("\"changedBy\": \"local-operator\"");
            assert reachLinked.body().contains("\"linkStatus\": \"LINKED\"");

            HttpResponse<String> reachReplay = postJson(
                    client,
                    reachMutation,
                    reachJson.replace("customer confirmed public route", "different audit note"),
                    reachZero,
                    null
            );
            assert reachReplay.statusCode() == 200 : reachReplay.body();
            assert reachReplay.headers().firstValue("ETag").orElseThrow().equals(reachEtag1);
            assert reachability.current(
                    finding, OriginScope.INTERNET, "public-edge", TransportProtocol.TCP, 443
            ).current().revision() == 1;

            String reachUnlink = reachJson.replace("LINKED", "UNLINKED");
            HttpResponse<String> stale = postJson(client, reachMutation, reachUnlink, reachZero, null);
            assert stale.statusCode() == 412 : stale.body();
            HttpResponse<String> reachUnlinked = postJson(
                    client, reachMutation, reachUnlink, reachEtag1, null);
            assert reachUnlinked.statusCode() == 200 : reachUnlinked.body();
            assert reachUnlinked.body().contains("\"associationState\": \"UNLINKED\"");

            URI reachHistory = URI.create(base + "api/v1/findings/" + finding
                    + "/reachability-links/revisions?" + reachQuery + "&limit=10");
            HttpResponse<String> reachHistoryResponse = get(client, reachHistory, null);
            assert reachHistoryResponse.statusCode() == 200 : reachHistoryResponse.body();
            assert reachHistoryResponse.body().contains("\"revision\": 2");
            assert reachHistoryResponse.body().contains("\"revision\": 1");

            URI reachList = base.resolve("/api/v1/findings/" + finding + "/reachability-links?limit=10");
            HttpResponse<String> reachListed = get(client, reachList, null);
            assert reachListed.statusCode() == 200 : reachListed.body();
            assert reachListed.body().contains("\"targetPort\": 443");

            String service = "Payments API";
            URI businessCurrent = URI.create(base + "api/v1/findings/" + finding
                    + "/business-service-links/current?businessService=" + encode(service));
            HttpResponse<String> businessInitial = get(client, businessCurrent, null);
            assert businessInitial.statusCode() == 200 : businessInitial.body();
            assert businessInitial.body().contains("\"associationState\": \"NEVER_ASSESSED\"");
            String businessZero = businessInitial.headers().firstValue("ETag").orElseThrow();
            assert businessZero.startsWith("\"fbs-r0-");

            String businessJson = """
                    {
                      "linkStatus": "LINKED",
                      "businessService": "Payments API",
                      "changeNote": "customer confirmed service ownership"
                    }
                    """;
            URI businessMutation = base.resolve("/api/v1/findings/" + finding
                    + "/business-service-links/current");
            HttpResponse<String> businessLinked = postJson(
                    client, businessMutation, businessJson, businessZero, null);
            assert businessLinked.statusCode() == 200 : businessLinked.body();
            String businessEtag1 = businessLinked.headers().firstValue("ETag").orElseThrow();
            assert businessEtag1.startsWith("\"fbs-r1-");
            assert businessLinked.body().contains("\"businessService\": \"payments api\"");
            assert businessLinked.body().contains("\"changedBy\": \"local-operator\"");

            URI businessHistory = URI.create(base + "api/v1/findings/" + finding
                    + "/business-service-links/revisions?businessService=" + encode(service)
                    + "&limit=10");
            HttpResponse<String> businessHistoryResponse = get(client, businessHistory, null);
            assert businessHistoryResponse.statusCode() == 200 : businessHistoryResponse.body();
            assert businessHistoryResponse.body().contains("\"revision\": 1");

            HttpRequest delete = HttpRequest.newBuilder(businessMutation)
                    .timeout(Duration.ofSeconds(10))
                    .DELETE()
                    .build();
            HttpResponse<String> deleteRejected = client.send(
                    delete,
                    HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8)
            );
            assert deleteRejected.statusCode() == 405 : deleteRejected.body();
            assert "GET, POST".equals(deleteRejected.headers().firstValue("Allow").orElse(null));
        } finally {
            deleteTree(data);
        }
    }

    private static void reportsCapabilityUnavailableWithoutV21() throws Exception {
        Path data = Files.createTempDirectory("rbvm-finding-context-disabled-");
        UUID finding = UUID.fromString("30000000-0000-0000-0000-000000000001");
        HttpClient client = client();
        try (CsvPlatformServer server = new CsvPlatformServer(
                "127.0.0.1", 0, data, 1024 * 1024)) {
            server.start();
            URI base = server.baseUri();
            HttpResponse<String> health = get(client, base.resolve("/api/v1/health"), null);
            assert health.body().contains("\"findingContextAssociations\"");
            assert health.body().contains("\"historyReadEnabled\": false");
            HttpResponse<String> unavailable = get(
                    client,
                    base.resolve("/api/v1/findings/" + finding + "/business-service-links"),
                    null
            );
            assert unavailable.statusCode() == 503 : unavailable.body();
            assert unavailable.body().contains("FINDING CONTEXT ASSOCIATION PERSISTENCE UNAVAILABLE");
        } finally {
            deleteTree(data);
        }
    }

    private static void protectsUnavailableCapabilityBehindAuthentication() throws Exception {
        Path data = Files.createTempDirectory("rbvm-finding-context-auth-");
        String viewerToken = "finding-context-viewer-token-abcdefghijklmnopqrstuvwxyz";
        String operatorToken = "finding-context-operator-token-abcdefghijklmnopqrstuvwxyz";
        Path keyRegistry = data.resolve("api-keys.conf");
        Files.writeString(
                keyRegistry,
                digest(viewerToken) + "=context-viewer|VIEWER\n"
                        + digest(operatorToken) + "=context-operator|OPERATOR\n",
                StandardCharsets.UTF_8
        );
        try {
            Files.setPosixFilePermissions(keyRegistry, Set.of(
                    PosixFilePermission.OWNER_READ,
                    PosixFilePermission.OWNER_WRITE
            ));
        } catch (UnsupportedOperationException ignored) {
        }
        UUID finding = UUID.fromString("30000000-0000-0000-0000-000000000001");
        HttpClient client = client();
        try (CsvPlatformServer server = new CsvPlatformServer(
                "127.0.0.1",
                0,
                data.resolve("evidence"),
                1024 * 1024,
                new NoopCanonicalProjection(),
                new InMemoryDomainCatalog(),
                ApiKeyAuthenticator.fromFile(keyRegistry),
                RequestRateLimiter.disabled()
        )) {
            server.start();
            URI list = server.baseUri().resolve(
                    "/api/v1/findings/" + finding + "/business-service-links");
            HttpResponse<String> missing = get(client, list, null);
            assert missing.statusCode() == 401 : missing.body();
            HttpResponse<String> viewerUnavailable = get(client, list, viewerToken);
            assert viewerUnavailable.statusCode() == 503 : viewerUnavailable.body();

            URI mutation = server.baseUri().resolve(
                    "/api/v1/findings/" + finding + "/business-service-links/current");
            String json = "{\"linkStatus\":\"UNLINKED\",\"businessService\":\"payments\"}";
            String zero = "\"fbs-r0-" + "0".repeat(64) + "\"";
            HttpResponse<String> viewerDenied = postJson(
                    client, mutation, json, zero, viewerToken);
            assert viewerDenied.statusCode() == 403 : viewerDenied.body();
            HttpResponse<String> operatorUnavailable = postJson(
                    client, mutation, json, zero, operatorToken);
            assert operatorUnavailable.statusCode() == 503 : operatorUnavailable.body();
        } finally {
            deleteTree(data);
        }
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

    private static String encode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
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

    private static final class FakeReachabilityRegistry
            implements FindingReachabilityScopeLinkRegistry {
        private final Set<UUID> findings;
        private final Map<UUID, Map<String, List<FindingReachabilityScopeLink>>> histories =
                new LinkedHashMap<>();
        private long tick;

        FakeReachabilityRegistry(Set<UUID> findings) {
            this.findings = Set.copyOf(findings);
            for (UUID finding : findings) histories.put(finding, new LinkedHashMap<>());
        }

        @Override
        public MutationResult revise(
                UUID findingId,
                int expectedRevision,
                FindingReachabilityScopeLink.ChangeDraft draft
        ) {
            if (!findings.contains(findingId)) {
                return new MutationResult(MutationStatus.FINDING_NOT_FOUND, null);
            }
            String key = key(draft.originScope(), draft.originLabel(),
                    draft.transportProtocol(), draft.targetPort());
            List<FindingReachabilityScopeLink> events = histories.get(findingId)
                    .computeIfAbsent(key, ignored -> new ArrayList<>());
            FindingReachabilityScopeLink current = events.isEmpty() ? null : events.get(events.size() - 1);
            if (current == null) {
                if (expectedRevision != 0) {
                    return new MutationResult(MutationStatus.REVISION_CONFLICT, null);
                }
                FindingReachabilityScopeLink created = materialize(findingId, 1, draft);
                events.add(created);
                return new MutationResult(MutationStatus.UPDATED, created);
            }
            if (current.revision() == expectedRevision + 1 && current.sameCustomerState(draft)) {
                return new MutationResult(MutationStatus.REPLAYED, current);
            }
            if (current.revision() != expectedRevision) {
                return new MutationResult(MutationStatus.REVISION_CONFLICT, current);
            }
            if (current.sameCustomerState(draft)) {
                return new MutationResult(MutationStatus.REPLAYED, current);
            }
            FindingReachabilityScopeLink next = materialize(
                    findingId, current.revision() + 1, draft);
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
            List<FindingReachabilityScopeLink> events = histories.get(findingId).get(
                    key(originScope, originLabel, transportProtocol, targetPort));
            return new CurrentLookup(
                    true,
                    events == null || events.isEmpty() ? null : events.get(events.size() - 1)
            );
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
            String key = key(originScope, originLabel, transportProtocol, targetPort);
            List<FindingReachabilityScopeLink> source = histories.get(findingId)
                    .getOrDefault(key, List.of());
            List<FindingReachabilityScopeLink> all = source.stream()
                    .filter(event -> beforeRevision == null || event.revision() < beforeRevision)
                    .sorted(Comparator.comparingInt(FindingReachabilityScopeLink::revision).reversed())
                    .toList();
            boolean more = all.size() > limit;
            List<FindingReachabilityScopeLink> page = all.subList(0, Math.min(limit, all.size()));
            Integer next = more ? page.get(page.size() - 1).revision() : null;
            String scopeKey = page.isEmpty()
                    ? new FindingReachabilityScopeLink.ChangeDraft(
                            FindingReachabilityScopeLink.LinkStatus.UNLINKED,
                            originScope,
                            originLabel,
                            transportProtocol,
                            targetPort,
                            "system",
                            ""
                    ).originScope().name() + "|" + originLabel.length() + ":"
                            + originLabel.toLowerCase() + "|" + transportProtocol.name() + "|"
                            + (targetPort == null ? "" : targetPort)
                    : page.get(0).scopeKey();
            return Optional.of(new HistoryPage(findingId, scopeKey, page, next));
        }

        @Override
        public Optional<CurrentPage> listCurrent(UUID findingId, int limit, UUID afterEventId) {
            if (!findings.contains(findingId)) return Optional.empty();
            List<FindingReachabilityScopeLink> all = histories.get(findingId).values().stream()
                    .filter(events -> !events.isEmpty())
                    .map(events -> events.get(events.size() - 1))
                    .filter(event -> afterEventId == null || event.eventId().compareTo(afterEventId) > 0)
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
            String key = key(draft.originScope(), draft.originLabel(),
                    draft.transportProtocol(), draft.targetPort());
            return new FindingReachabilityScopeLink(
                    UUID.nameUUIDFromBytes((findingId + ":" + key + ":" + revision)
                            .getBytes(StandardCharsets.UTF_8)),
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
                    Instant.parse("2026-08-22T07:00:00Z").plusSeconds(tick++)
            );
        }

        private static String key(
                OriginScope originScope,
                String originLabel,
                TransportProtocol transportProtocol,
                Integer targetPort
        ) {
            String normalized = originLabel.trim().toLowerCase();
            return originScope.name() + "|" + normalized + "|" + transportProtocol.name()
                    + "|" + (targetPort == null ? "" : targetPort);
        }
    }

    private static final class FakeBusinessRegistry implements FindingBusinessServiceLinkRegistry {
        private final Set<UUID> findings;
        private final Map<UUID, Map<String, List<FindingBusinessServiceLink>>> histories =
                new LinkedHashMap<>();
        private long tick;

        FakeBusinessRegistry(Set<UUID> findings) {
            this.findings = Set.copyOf(findings);
            for (UUID finding : findings) histories.put(finding, new LinkedHashMap<>());
        }

        @Override
        public MutationResult revise(
                UUID findingId,
                int expectedRevision,
                FindingBusinessServiceLink.ChangeDraft draft
        ) {
            if (!findings.contains(findingId)) {
                return new MutationResult(MutationStatus.FINDING_NOT_FOUND, null);
            }
            String service = draft.businessService();
            List<FindingBusinessServiceLink> events = histories.get(findingId)
                    .computeIfAbsent(service, ignored -> new ArrayList<>());
            FindingBusinessServiceLink current = events.isEmpty() ? null : events.get(events.size() - 1);
            if (current == null) {
                if (expectedRevision != 0) {
                    return new MutationResult(MutationStatus.REVISION_CONFLICT, null);
                }
                FindingBusinessServiceLink created = materialize(findingId, 1, draft);
                events.add(created);
                return new MutationResult(MutationStatus.UPDATED, created);
            }
            if (current.revision() == expectedRevision + 1 && current.sameCustomerState(draft)) {
                return new MutationResult(MutationStatus.REPLAYED, current);
            }
            if (current.revision() != expectedRevision) {
                return new MutationResult(MutationStatus.REVISION_CONFLICT, current);
            }
            if (current.sameCustomerState(draft)) {
                return new MutationResult(MutationStatus.REPLAYED, current);
            }
            FindingBusinessServiceLink next = materialize(findingId, current.revision() + 1, draft);
            events.add(next);
            return new MutationResult(MutationStatus.UPDATED, next);
        }

        @Override
        public CurrentLookup current(UUID findingId, String businessService) {
            if (!findings.contains(findingId)) return new CurrentLookup(false, null);
            String service = businessService.trim().toLowerCase();
            List<FindingBusinessServiceLink> events = histories.get(findingId).get(service);
            return new CurrentLookup(
                    true,
                    events == null || events.isEmpty() ? null : events.get(events.size() - 1)
            );
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
            List<FindingBusinessServiceLink> source = histories.get(findingId)
                    .getOrDefault(service, List.of());
            List<FindingBusinessServiceLink> all = source.stream()
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
            List<FindingBusinessServiceLink> all = histories.get(findingId).values().stream()
                    .filter(events -> !events.isEmpty())
                    .map(events -> events.get(events.size() - 1))
                    .filter(event -> afterEventId == null || event.eventId().compareTo(afterEventId) > 0)
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
                    UUID.nameUUIDFromBytes((findingId + ":" + draft.businessService() + ":" + revision)
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
                    Instant.parse("2026-08-22T07:30:00Z").plusSeconds(tick++)
            );
        }
    }
}

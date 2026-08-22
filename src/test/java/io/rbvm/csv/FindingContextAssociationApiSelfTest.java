package io.rbvm.csv;

import io.rbvm.context.FindingBusinessServiceLink;
import io.rbvm.context.FindingBusinessServiceLinkRegistry;
import io.rbvm.context.FindingReachabilityScopeLink;
import io.rbvm.context.FindingReachabilityScopeLink.OriginScope;
import io.rbvm.context.FindingReachabilityScopeLink.TransportProtocol;
import io.rbvm.context.FindingReachabilityScopeLinkRegistry;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

public final class FindingContextAssociationApiSelfTest {
    private static final UUID FINDING = UUID.fromString("10000000-0000-0000-0000-000000000001");
    private static final UUID FINDING_2 = UUID.fromString("10000000-0000-0000-0000-000000000002");
    private static final UUID MISSING = UUID.fromString("99999999-9999-9999-9999-999999999999");

    private FindingContextAssociationApiSelfTest() {
    }

    public static void main(String[] args) throws Exception {
        reachabilityApi();
        businessServiceApi();
        System.out.println("FindingContextAssociationApiSelfTest: PASS");
    }

    private static void reachabilityApi() throws Exception {
        FakeReachabilityRegistry registry = new FakeReachabilityRegistry(Set.of(FINDING, FINDING_2));
        FindingReachabilityScopeLinkApi api = new FindingReachabilityScopeLinkApi(registry);
        String currentUri = "http://localhost/api/v1/findings/" + FINDING
                + "/reachability-links/current?originScope=INTERNET&originLabel=Edge%20Probe"
                + "&transportProtocol=TCP&targetPort=443";

        var initial = api.current(FINDING, java.net.URI.create(currentUri));
        assert initial.status() == 200;
        assert initial.body().get("currentLink") == null;
        assert initial.body().get("associationState").equals("NEVER_ASSESSED");
        String zero = initial.headers().get("ETag");
        assert zero.startsWith("\"frs-r0-");

        var otherScope = api.current(FINDING, java.net.URI.create(currentUri.replace("443", "8443")));
        assert !zero.equals(otherScope.headers().get("ETag"));

        String linkedJson = """
                {
                  "linkStatus":"LINKED",
                  "originScope":"INTERNET",
                  "originLabel":"EDGE PROBE",
                  "transportProtocol":"TCP",
                  "targetPort":443,
                  "changeNote":"customer confirmed endpoint"
                }
                """;
        var linked = api.revise(FINDING, "application/json", body(linkedJson), zero, "alice");
        String etag1 = linked.headers().get("ETag");
        assert etag1.startsWith("\"frs-r1-");
        assert linked.body().get("associationState").equals("LINKED");
        assert registry.current(
                FINDING, OriginScope.INTERNET, "edge probe", TransportProtocol.TCP, 443)
                .current().changedBy().equals("alice");

        // Exact network retry may use the immediately prior zero-state validator.
        var replay = api.revise(
                FINDING,
                "application/json",
                body(linkedJson.replace("customer confirmed endpoint", "different audit note")),
                zero,
                "bob"
        );
        assert replay.headers().get("ETag").equals(etag1);
        assert registry.history(
                FINDING, OriginScope.INTERNET, "edge probe", TransportProtocol.TCP, 443, 10, null)
                .orElseThrow().events().size() == 1;
        assert registry.current(
                FINDING, OriginScope.INTERNET, "edge probe", TransportProtocol.TCP, 443)
                .current().changedBy().equals("alice");

        boolean staleConflict = false;
        try {
            api.revise(
                    FINDING,
                    "application/json",
                    body(linkedJson.replace("\"LINKED\"", "\"UNLINKED\"")),
                    zero,
                    "carol"
            );
        } catch (ManagedAssetApi.ApiProblem problem) {
            staleConflict = problem.status() == 412
                    && problem.code().equals("FINDING_REACHABILITY_LINK_PRECONDITION_FAILED");
        }
        assert staleConflict;

        boolean missingPrecondition = false;
        try {
            api.revise(FINDING, "application/json", body(linkedJson), null, "alice");
        } catch (ManagedAssetApi.ApiProblem problem) {
            missingPrecondition = problem.status() == 428;
        }
        assert missingPrecondition;

        boolean weakRejected = false;
        try {
            api.revise(FINDING, "application/json", body(linkedJson), "W/" + etag1, "alice");
        } catch (ManagedAssetApi.ApiProblem problem) {
            weakRejected = problem.status() == 400 && problem.code().equals("INVALID_IF_MATCH");
        }
        assert weakRejected;

        String unlinkJson = linkedJson.replace("\"LINKED\"", "\"UNLINKED\"")
                .replace("customer confirmed endpoint", "explicit customer unlink");
        var unlinked = api.revise(FINDING, "application/json", body(unlinkJson), etag1, "dana");
        assert unlinked.headers().get("ETag").startsWith("\"frs-r2-");
        assert unlinked.body().get("associationState").equals("UNLINKED");

        var current = api.current(FINDING, java.net.URI.create(currentUri));
        assert current.body().get("associationState").equals("UNLINKED");
        assert current.body().get("currentLink") != null;

        var history = api.history(FINDING, java.net.URI.create(
                currentUri.replace("/current?", "/revisions?&").replace("?&", "?") + "&limit=1"));
        assert ((List<?>) history.body().get("revisions")).size() == 1;
        assert history.body().get("nextBeforeRevision") != null;

        var list = api.list(FINDING, java.net.URI.create(
                "http://localhost/api/v1/findings/" + FINDING + "/reachability-links?limit=10"));
        assert ((List<?>) list.body().get("links")).size() == 1;

        boolean spoofRejected = false;
        try {
            api.revise(
                    FINDING_2,
                    "application/json",
                    body(linkedJson.replace(
                            "\"changeNote\":\"customer confirmed endpoint\"",
                            "\"changedBy\":\"mallory\",\"changeNote\":\"customer confirmed endpoint\""
                    )),
                    api.current(FINDING_2, java.net.URI.create(currentUri.replace(FINDING.toString(), FINDING_2.toString())))
                            .headers().get("ETag"),
                    "alice"
            );
        } catch (ManagedAssetApi.ApiProblem problem) {
            spoofRejected = problem.status() == 400;
        }
        assert spoofRejected;

        boolean missingFinding = false;
        try {
            api.current(MISSING, java.net.URI.create(currentUri.replace(FINDING.toString(), MISSING.toString())));
        } catch (ManagedAssetApi.ApiProblem problem) {
            missingFinding = problem.status() == 404 && problem.code().equals("FINDING_NOT_FOUND");
        }
        assert missingFinding;
    }

    private static void businessServiceApi() throws Exception {
        FakeBusinessRegistry registry = new FakeBusinessRegistry(Set.of(FINDING, FINDING_2));
        FindingBusinessServiceLinkApi api = new FindingBusinessServiceLinkApi(registry);
        String currentUri = "http://localhost/api/v1/findings/" + FINDING
                + "/business-service-links/current?businessService=Payments";

        var initial = api.current(FINDING, java.net.URI.create(currentUri));
        assert initial.body().get("associationState").equals("NEVER_ASSESSED");
        String zero = initial.headers().get("ETag");
        assert zero.startsWith("\"fbs-r0-");
        var other = api.current(FINDING, java.net.URI.create(currentUri.replace("Payments", "Identity")));
        assert !zero.equals(other.headers().get("ETag"));

        String linkedJson = """
                {
                  "linkStatus":"LINKED",
                  "businessService":"PAYMENTS",
                  "changeNote":"customer confirmed service"
                }
                """;
        var linked = api.revise(FINDING, "application/json", body(linkedJson), zero, "alice");
        String etag1 = linked.headers().get("ETag");
        assert etag1.startsWith("\"fbs-r1-");
        assert registry.current(FINDING, "payments").current().changedBy().equals("alice");

        var replay = api.revise(
                FINDING,
                "application/json",
                body(linkedJson.replace("customer confirmed service", "retry note")),
                zero,
                "bob"
        );
        assert replay.headers().get("ETag").equals(etag1);
        assert registry.history(FINDING, "payments", 10, null).orElseThrow().events().size() == 1;

        boolean staleConflict = false;
        try {
            api.revise(
                    FINDING,
                    "application/json",
                    body(linkedJson.replace("\"LINKED\"", "\"UNLINKED\"")),
                    zero,
                    "carol"
            );
        } catch (ManagedAssetApi.ApiProblem problem) {
            staleConflict = problem.status() == 412
                    && problem.code().equals("FINDING_BUSINESS_SERVICE_LINK_PRECONDITION_FAILED");
        }
        assert staleConflict;

        var unlinked = api.revise(
                FINDING,
                "application/json",
                body(linkedJson.replace("\"LINKED\"", "\"UNLINKED\"")),
                etag1,
                "dana"
        );
        assert unlinked.headers().get("ETag").startsWith("\"fbs-r2-");
        assert unlinked.body().get("associationState").equals("UNLINKED");

        var history = api.history(FINDING, java.net.URI.create(
                "http://localhost/api/v1/findings/" + FINDING
                        + "/business-service-links/revisions?businessService=payments&limit=1"));
        assert ((List<?>) history.body().get("revisions")).size() == 1;
        assert history.body().get("nextBeforeRevision") != null;

        var list = api.list(FINDING, java.net.URI.create(
                "http://localhost/api/v1/findings/" + FINDING + "/business-service-links"));
        assert ((List<?>) list.body().get("links")).size() == 1;

        boolean spoofRejected = false;
        String zero2 = api.current(FINDING_2, java.net.URI.create(currentUri.replace(FINDING.toString(), FINDING_2.toString())))
                .headers().get("ETag");
        try {
            api.revise(
                    FINDING_2,
                    "application/json",
                    body("{\"linkStatus\":\"LINKED\",\"businessService\":\"payments\","
                            + "\"changedBy\":\"mallory\"}"),
                    zero2,
                    "alice"
            );
        } catch (ManagedAssetApi.ApiProblem problem) {
            spoofRejected = problem.status() == 400;
        }
        assert spoofRejected;

        boolean missingFinding = false;
        try {
            api.current(MISSING, java.net.URI.create(currentUri.replace(FINDING.toString(), MISSING.toString())));
        } catch (ManagedAssetApi.ApiProblem problem) {
            missingFinding = problem.status() == 404 && problem.code().equals("FINDING_NOT_FOUND");
        }
        assert missingFinding;
    }

    private static ByteArrayInputStream body(String text) {
        return new ByteArrayInputStream(text.getBytes(StandardCharsets.UTF_8));
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
            if (current.revision() != expectedRevision) {
                return new MutationResult(MutationStatus.REVISION_CONFLICT, current);
            }
            if (current.sameCustomerState(draft)) return new MutationResult(MutationStatus.REPLAYED, current);
            FindingReachabilityScopeLink next = materialize(findingId, current.revision() + 1, draft);
            events.add(next);
            return new MutationResult(MutationStatus.UPDATED, next);
        }

        @Override
        public CurrentLookup current(
                UUID findingId, OriginScope originScope, String originLabel,
                TransportProtocol transportProtocol, Integer targetPort
        ) {
            if (!findings.contains(findingId)) return new CurrentLookup(false, null);
            List<FindingReachabilityScopeLink> events = histories.getOrDefault(
                    key(findingId, originScope, originLabel, transportProtocol, targetPort), List.of());
            return new CurrentLookup(true, events.isEmpty() ? null : events.get(events.size() - 1));
        }

        @Override
        public Optional<HistoryPage> history(
                UUID findingId, OriginScope originScope, String originLabel,
                TransportProtocol transportProtocol, Integer targetPort,
                int limit, Integer beforeRevision
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
                    ? originScope.name() + "|" + originLabel.trim().toLowerCase() + "|"
                            + transportProtocol.name() + "|" + (targetPort == null ? "" : targetPort)
                    : page.get(0).scopeKey();
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
                            findingId, revision, draft.linkStatus(), draft.originScope(), draft.originLabel(),
                            draft.transportProtocol(), draft.targetPort()),
                    draft.changedBy(),
                    draft.changeNote(),
                    Instant.parse("2026-08-22T00:00:00Z").plusSeconds(tick++)
            );
        }

        private static String key(
                UUID findingId, OriginScope originScope, String originLabel,
                TransportProtocol protocol, Integer port
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
        public Optional<HistoryPage> history(UUID findingId, String businessService, int limit, Integer beforeRevision) {
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
                            findingId, revision, draft.linkStatus(), draft.businessService()),
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

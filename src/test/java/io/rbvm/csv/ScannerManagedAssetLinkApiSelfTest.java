package io.rbvm.csv;

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

public final class ScannerManagedAssetLinkApiSelfTest {
    private ScannerManagedAssetLinkApiSelfTest() {
    }

    public static void main(String[] args) throws Exception {
        FakeRegistry registry = new FakeRegistry();
        UUID scanner = UUID.fromString("10000000-0000-0000-0000-000000000001");
        UUID scanner2 = UUID.fromString("10000000-0000-0000-0000-000000000002");
        UUID managed = UUID.fromString("20000000-0000-0000-0000-000000000001");
        UUID managed2 = UUID.fromString("20000000-0000-0000-0000-000000000002");
        registry.addScanner(scanner, "wazuh-prod-01", "Linux", "wazuh-prod");
        registry.addScanner(scanner2, "wazuh-prod-02", "Linux", "wazuh-prod");
        registry.managedAssets.add(managed);
        registry.managedAssets.add(managed2);
        ScannerManagedAssetLinkApi api = new ScannerManagedAssetLinkApi(registry);

        ScannerManagedAssetLinkApi.Response initial = api.current(scanner);
        assert initial.status() == 200;
        assert initial.body().get("currentLink") == null;
        String zero = initial.headers().get("ETag");
        assert zero.startsWith("\"sma-r0-");
        assert zero.equals(ScannerManagedAssetLinkApi.zeroEtag(scanner));

        String linkedJson = """
                {
                  "linkStatus": "LINKED",
                  "managedAssetId": "20000000-0000-0000-0000-000000000001",
                  "changeNote": "customer confirmed CMDB match"
                }
                """;
        ScannerManagedAssetLinkApi.Response linked = api.revise(
                scanner,
                "application/json; charset=utf-8",
                body(linkedJson),
                zero,
                "alice"
        );
        assert linked.status() == 200;
        String etag1 = linked.headers().get("ETag");
        assert etag1.startsWith("\"sma-r1-");
        ScannerManagedAssetLink current1 = registry.current(scanner).current();
        assert current1 != null;
        assert current1.revision() == 1;
        assert current1.linkStatus() == LinkStatus.LINKED;
        assert current1.managedAssetId().equals(managed);
        assert current1.changedBy().equals("alice");

        // Exact network retry with the zero-state validator is replay-safe.
        ScannerManagedAssetLinkApi.Response replay = api.revise(
                scanner,
                "application/json",
                body(linkedJson.replace("customer confirmed CMDB match", "different audit note")),
                zero,
                "bob"
        );
        assert replay.status() == 200;
        assert replay.headers().get("ETag").equals(etag1);
        assert registry.current(scanner).current().revision() == 1;
        assert registry.current(scanner).current().changedBy().equals("alice");

        boolean staleConflict = false;
        String relinked = linkedJson.replace(managed.toString(), managed2.toString());
        try {
            api.revise(scanner, "application/json", body(relinked), zero, "carol");
        } catch (ManagedAssetApi.ApiProblem problem) {
            staleConflict = problem.status() == 412;
        }
        assert staleConflict;

        boolean missingPrecondition = false;
        try {
            api.revise(scanner, "application/json", body(linkedJson), null, "carol");
        } catch (ManagedAssetApi.ApiProblem problem) {
            missingPrecondition = problem.status() == 428;
        }
        assert missingPrecondition;

        boolean weakRejected = false;
        try {
            api.revise(scanner, "application/json", body(linkedJson), "W/" + etag1, "carol");
        } catch (ManagedAssetApi.ApiProblem problem) {
            weakRejected = problem.status() == 400 && problem.code().equals("INVALID_IF_MATCH");
        }
        assert weakRejected;

        String unlinkJson = """
                {
                  "linkStatus": "UNLINKED",
                  "managedAssetId": null,
                  "changeNote": "customer removed mapping"
                }
                """;
        ScannerManagedAssetLinkApi.Response unlinked = api.revise(
                scanner,
                "application/json",
                body(unlinkJson),
                etag1,
                "dana"
        );
        assert unlinked.status() == 200;
        String etag2 = unlinked.headers().get("ETag");
        assert etag2.startsWith("\"sma-r2-");
        assert registry.current(scanner).current().linkStatus() == LinkStatus.UNLINKED;
        assert registry.current(scanner).current().managedAssetId() == null;

        ScannerManagedAssetLinkApi.Response history = api.history(
                scanner,
                java.net.URI.create("http://localhost/api/v1/scanner-assets/" + scanner
                        + "/managed-asset-link/revisions?limit=1")
        );
        assert ((List<?>) history.body().get("events")).size() == 1;
        assert history.body().get("nextBeforeRevision") != null;

        ScannerManagedAssetLinkApi.Response list = api.list(
                java.net.URI.create("http://localhost/api/v1/scanner-assets?limit=1")
        );
        assert ((List<?>) list.body().get("assets")).size() == 1;
        assert list.body().get("nextAfterId") != null;
        ScannerManagedAssetLinkApi.Response next = api.list(java.net.URI.create(
                "http://localhost/api/v1/scanner-assets?limit=1&afterId=" + list.body().get("nextAfterId")
        ));
        assert ((List<?>) next.body().get("assets")).size() == 1;
        assert next.body().get("nextAfterId") == null;

        boolean spoofRejected = false;
        String spoof = linkedJson.replace(
                "\"changeNote\": \"customer confirmed CMDB match\"",
                "\"changedBy\": \"mallory\", \"changeNote\": \"customer confirmed CMDB match\""
        );
        try {
            api.revise(scanner2, "application/json", body(spoof), ScannerManagedAssetLinkApi.zeroEtag(scanner2), "alice");
        } catch (ManagedAssetApi.ApiProblem problem) {
            spoofRejected = problem.status() == 400
                    && problem.code().equals("UNKNOWN_SCANNER_MANAGED_ASSET_LINK_FIELDS");
        }
        assert spoofRejected;

        boolean missingManagedRejected = false;
        try {
            api.revise(
                    scanner2,
                    "application/json",
                    body("{\"linkStatus\":\"LINKED\",\"changeNote\":\"bad\"}"),
                    ScannerManagedAssetLinkApi.zeroEtag(scanner2),
                    "alice"
            );
        } catch (ManagedAssetApi.ApiProblem problem) {
            missingManagedRejected = problem.status() == 422;
        }
        assert missingManagedRejected;

        boolean unknownManagedRejected = false;
        try {
            api.revise(
                    scanner2,
                    "application/json",
                    body("{\"linkStatus\":\"LINKED\",\"managedAssetId\":\"ffffffff-ffff-ffff-ffff-ffffffffffff\"}"),
                    ScannerManagedAssetLinkApi.zeroEtag(scanner2),
                    "alice"
            );
        } catch (ManagedAssetApi.ApiProblem problem) {
            unknownManagedRejected = problem.status() == 404
                    && problem.code().equals("MANAGED_ASSET_NOT_FOUND");
        }
        assert unknownManagedRejected;

        boolean missingScannerRejected = false;
        try {
            api.current(UUID.fromString("99999999-9999-9999-9999-999999999999"));
        } catch (ManagedAssetApi.ApiProblem problem) {
            missingScannerRejected = problem.status() == 404
                    && problem.code().equals("SCANNER_ASSET_NOT_FOUND");
        }
        assert missingScannerRejected;

        System.out.println("ScannerManagedAssetLinkApiSelfTest: PASS");
    }

    private static ByteArrayInputStream body(String text) {
        return new ByteArrayInputStream(text.getBytes(StandardCharsets.UTF_8));
    }

    private static final class FakeRegistry implements ScannerManagedAssetLinkRegistry {
        private final Map<UUID, ScannerAssetSummary> scanners = new LinkedHashMap<>();
        private final Map<UUID, List<ScannerManagedAssetLink>> histories = new LinkedHashMap<>();
        private final Set<UUID> managedAssets = new java.util.HashSet<>();
        private long tick;

        void addScanner(UUID id, String observedName, String os, String sourceProfile) {
            scanners.put(id, new ScannerAssetSummary(
                    id,
                    observedName,
                    os,
                    sourceProfile,
                    "SOURCE_NAME_ONLY",
                    "LOW",
                    Instant.parse("2026-08-20T00:00:00Z"),
                    Instant.parse("2026-08-20T01:00:00Z"),
                    null
            ));
            histories.put(id, new ArrayList<>());
        }

        @Override
        public MutationResult revise(UUID scannerAssetId, int expectedRevision, ChangeDraft nextState) {
            ScannerAssetSummary scanner = scanners.get(scannerAssetId);
            if (scanner == null) return new MutationResult(MutationStatus.SCANNER_ASSET_NOT_FOUND, null);
            ScannerManagedAssetLink current = current(scannerAssetId).current();
            if (nextState.linkStatus() == LinkStatus.LINKED
                    && !managedAssets.contains(nextState.managedAssetId())) {
                return new MutationResult(MutationStatus.MANAGED_ASSET_NOT_FOUND, current);
            }
            if (current == null) {
                if (expectedRevision != 0) {
                    return new MutationResult(MutationStatus.REVISION_CONFLICT, null);
                }
                ScannerManagedAssetLink created = materialize(scannerAssetId, 1, nextState);
                histories.get(scannerAssetId).add(created);
                updateCurrent(scannerAssetId, created);
                return new MutationResult(MutationStatus.UPDATED, created);
            }
            if (current.revision() == expectedRevision + 1 && current.sameCustomerState(nextState)) {
                return new MutationResult(MutationStatus.REPLAYED, current);
            }
            if (current.revision() != expectedRevision) {
                return new MutationResult(MutationStatus.REVISION_CONFLICT, current);
            }
            if (current.sameCustomerState(nextState)) {
                return new MutationResult(MutationStatus.REPLAYED, current);
            }
            ScannerManagedAssetLink next = materialize(scannerAssetId, current.revision() + 1, nextState);
            histories.get(scannerAssetId).add(next);
            updateCurrent(scannerAssetId, next);
            return new MutationResult(MutationStatus.UPDATED, next);
        }

        @Override
        public CurrentLookup current(UUID scannerAssetId) {
            ScannerAssetSummary scanner = scanners.get(scannerAssetId);
            if (scanner == null) return new CurrentLookup(false, null);
            List<ScannerManagedAssetLink> events = histories.get(scannerAssetId);
            ScannerManagedAssetLink current = events.isEmpty() ? null : events.get(events.size() - 1);
            return new CurrentLookup(true, current);
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
                    .toList();
            boolean more = all.size() > limit;
            List<ScannerAssetSummary> page = all.subList(0, Math.min(limit, all.size()));
            UUID next = more ? page.get(page.size() - 1).scannerAssetId() : null;
            return new ScannerAssetPage(page, next);
        }

        private ScannerManagedAssetLink materialize(UUID scannerAssetId, int revision, ChangeDraft draft) {
            Instant recordedAt = Instant.parse("2026-08-20T10:00:00Z").plusSeconds(tick++);
            return new ScannerManagedAssetLink(
                    UUID.nameUUIDFromBytes((scannerAssetId + ":" + revision).getBytes(StandardCharsets.UTF_8)),
                    scannerAssetId,
                    revision,
                    draft.linkStatus(),
                    draft.managedAssetId(),
                    LinkMethod.CUSTOMER_CONFIRMED,
                    ScannerManagedAssetLink.evidenceSha256(
                            scannerAssetId,
                            revision,
                            draft.linkStatus(),
                            draft.managedAssetId()
                    ),
                    draft.changedBy(),
                    draft.changeNote(),
                    recordedAt
            );
        }

        private void updateCurrent(UUID scannerAssetId, ScannerManagedAssetLink current) {
            ScannerAssetSummary prior = scanners.get(scannerAssetId);
            scanners.put(scannerAssetId, new ScannerAssetSummary(
                    prior.scannerAssetId(),
                    prior.observedName(),
                    prior.osNameRaw(),
                    prior.sourceProfileKey(),
                    prior.identityBasis(),
                    prior.identityConfidence(),
                    prior.firstObservedAt(),
                    prior.lastObservedAt(),
                    current
            ));
        }
    }
}

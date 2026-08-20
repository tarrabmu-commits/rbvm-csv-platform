package io.rbvm.csv;

import io.rbvm.asset.ManagedAsset;
import io.rbvm.asset.ManagedAsset.ClassificationMethod;
import io.rbvm.asset.ManagedAsset.LifecycleStatus;
import io.rbvm.asset.ManagedAsset.Revision;
import io.rbvm.asset.ManagedAsset.RevisionDraft;
import io.rbvm.asset.ManagedAssetRegistry;
import io.rbvm.asset.ManagedAssetRegistry.LifecycleFilter;
import io.rbvm.asset.ManagedAssetRegistry.ManagedAssetPage;
import io.rbvm.asset.ManagedAssetRegistry.MutationResult;
import io.rbvm.asset.ManagedAssetRegistry.MutationStatus;
import io.rbvm.asset.ManagedAssetRegistry.RevisionPage;
import io.rbvm.csv.AssetContextCsvEvidence.BusinessCriticality;
import io.rbvm.csv.AssetContextCsvEvidence.Environment;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

public final class ManagedAssetApiSelfTest {
  private ManagedAssetApiSelfTest() {}

  public static void main(String[] args) throws Exception {
    FakeRegistry registry = new FakeRegistry();
    ManagedAssetApi api = new ManagedAssetApi(registry);

    String create = """
      {
        "customerAssetKey":"CMDB-42",
        "displayName":"payments-prod-01",
        "environment":"PRODUCTION",
        "businessService":"Payments",
        "businessOwner":"PaymentsOps",
        "businessCriticality":"HIGH",
        "classificationMethod":"CUSTOMER_DIRECT",
        "changeNote":"initial"
      }
      """;
    ManagedAssetApi.Response created = api.create("application/json; charset=utf-8", body(create), "alice");
    assert created.status() == 201;
    assert created.headers().containsKey("Location");
    String etag1 = created.headers().get("ETag");
    String idText = String.valueOf(created.body().get("id"));
    UUID id = UUID.fromString(idText);
    assert registry.find(id).orElseThrow().currentRevision().changedBy().equals("alice");

    ManagedAssetApi.Response fetched = api.get(id);
    assert fetched.headers().get("ETag").equals(etag1);

    String revisedJson = """
      {
        "lifecycleStatus":"ACTIVE",
        "displayName":"payments-prod-01",
        "environment":"PRODUCTION",
        "businessService":"Payments",
        "businessOwner":"PaymentsOps",
        "businessCriticality":"MISSION_CRITICAL",
        "classificationMethod":"CUSTOMER_DIRECT",
        "changeNote":"customer confirmed"
      }
      """;
    ManagedAssetApi.Response revised = api.revise(id, "application/json", body(revisedJson), etag1, "bob");
    assert revised.status() == 200;
    String etag2 = revised.headers().get("ETag");
    assert !etag1.equals(etag2);
    assert registry.find(id).orElseThrow().currentRevision().revision() == 2;
    assert registry.find(id).orElseThrow().currentRevision().changedBy().equals("bob");

    // Exact retry with the immediately prior validator is replay-safe and does not append revision 3.
    ManagedAssetApi.Response replay = api.revise(id, "application/json", body(revisedJson), etag1, "bob");
    assert replay.status() == 200;
    assert replay.headers().get("ETag").equals(etag2);
    assert registry.find(id).orElseThrow().currentRevision().revision() == 2;

    boolean staleRejected = false;
    String conflicting = revisedJson.replace("MISSION_CRITICAL", "LOW");
    try {
      api.revise(id, "application/json", body(conflicting), etag1, "carol");
    } catch (ManagedAssetApi.ApiProblem problem) {
      staleRejected = problem.status() == 412;
    }
    assert staleRejected;

    boolean missingPrecondition = false;
    try {
      api.revise(id, "application/json", body(revisedJson), null, "carol");
    } catch (ManagedAssetApi.ApiProblem problem) {
      missingPrecondition = problem.status() == 428;
    }
    assert missingPrecondition;

    boolean weakTagRejected = false;
    try {
      api.revise(id, "application/json", body(revisedJson), "W/" + etag2, "carol");
    } catch (ManagedAssetApi.ApiProblem problem) {
      weakTagRejected = problem.status() == 400 && problem.code().equals("INVALID_IF_MATCH");
    }
    assert weakTagRejected;

    boolean duplicateJsonRejected = false;
    String duplicateJson = create.replace(
        "\"displayName\":\"payments-prod-01\"",
        "\"displayName\":\"payments-prod-01\",\"displayName\":\"other\""
    );
    try {
      api.create("application/json", body(duplicateJson), "alice");
    } catch (ManagedAssetApi.ApiProblem problem) {
      duplicateJsonRejected = problem.status() == 400 && problem.code().equals("INVALID_JSON");
    }
    assert duplicateJsonRejected;

    boolean unpairedSurrogateRejected = false;
    String invalidUnicode = create.replace("payments-prod-01", "bad\\uD800name")
        .replace("CMDB-42", "CMDB-UNICODE-BAD");
    try {
      api.create("application/json", body(invalidUnicode), "alice");
    } catch (ManagedAssetApi.ApiProblem problem) {
      unpairedSurrogateRejected = problem.status() == 400 && problem.code().equals("INVALID_JSON");
    }
    assert unpairedSurrogateRejected;

    String validUnicode = create.replace("payments-prod-01", "asset-\\uD83D\\uDE80")
        .replace("CMDB-42", "CMDB-UNICODE-GOOD");
    ManagedAssetApi.Response unicodeCreated = api.create("application/json", body(validUnicode), "alice");
    assert unicodeCreated.status() == 201;
    assert String.valueOf(
        ((Map<?, ?>) unicodeCreated.body().get("currentRevision")).get("displayName")
    ).contains("🚀");

    boolean guidedWithoutBasisRejected = false;
    String guidedMissingBasis = create.replace("CUSTOMER_DIRECT", "GUIDED")
        .replace("CMDB-42", "CMDB-GUIDED");
    try {
      api.create("application/json", body(guidedMissingBasis), "alice");
    } catch (ManagedAssetApi.ApiProblem problem) {
      guidedWithoutBasisRejected = problem.status() == 422;
    }
    assert guidedWithoutBasisRejected;

    boolean directWithGuideRejected = false;
    String directWithGuide = create.replace(
        "\"classificationMethod\":\"CUSTOMER_DIRECT\"",
        "\"classificationMethod\":\"CUSTOMER_DIRECT\",\"guideContractId\":\"ASSET_CLASSIFICATION_GUIDE_V1\",\"guideRevision\":1"
    ).replace("CMDB-42", "CMDB-DIRECT-GUIDE");
    try {
      api.create("application/json", body(directWithGuide), "alice");
    } catch (ManagedAssetApi.ApiProblem problem) {
      directWithGuideRejected = problem.status() == 422;
    }
    assert directWithGuideRejected;

    boolean wrongMediaTypeRejected = false;
    try {
      api.create("text/plain", body(create), "alice");
    } catch (ManagedAssetApi.ApiProblem problem) {
      wrongMediaTypeRejected = problem.status() == 415;
    }
    assert wrongMediaTypeRejected;

    boolean oversizedRejected = false;
    String oversized = "{\"displayName\":\"" + "x".repeat(ManagedAssetApi.MAXIMUM_BODY_BYTES) + "\"}";
    try {
      api.create("application/json", body(oversized), "alice");
    } catch (ManagedAssetApi.ApiProblem problem) {
      oversizedRejected = problem.status() == 413;
    }
    assert oversizedRejected;

    boolean spoofRejected = false;
    String spoof = create.replace("\"changeNote\":\"initial\"", "\"changedBy\":\"mallory\",\"changeNote\":\"initial\"");
    try {
      api.create("application/json", body(spoof), "alice");
    } catch (ManagedAssetApi.ApiProblem problem) {
      spoofRejected = problem.status() == 400 && problem.code().equals("UNKNOWN_MANAGED_ASSET_FIELDS");
    }
    assert spoofRejected;

    String secondCreate = create.replace("CMDB-42", "CMDB-43").replace("payments-prod-01", "payments-prod-02");
    ManagedAssetApi.Response second = api.create("application/json", body(secondCreate), "alice");
    assert second.status() == 201;

    ManagedAssetApi.Response list = api.list(java.net.URI.create("http://localhost/api/v1/managed-assets?limit=1&lifecycle=ALL"));
    assert ((List<?>) list.body().get("assets")).size() == 1;
    assert list.body().get("nextAfterId") != null;
    ManagedAssetApi.Response secondPage = api.list(java.net.URI.create(
        "http://localhost/api/v1/managed-assets?limit=1&lifecycle=ALL&afterId="
            + list.body().get("nextAfterId")));
    assert ((List<?>) secondPage.body().get("assets")).size() == 1;
    assert secondPage.body().get("nextAfterId") != null;
    ManagedAssetApi.Response thirdPage = api.list(java.net.URI.create(
        "http://localhost/api/v1/managed-assets?limit=1&lifecycle=ALL&afterId="
            + secondPage.body().get("nextAfterId")));
    assert ((List<?>) thirdPage.body().get("assets")).size() == 1;
    assert thirdPage.body().get("nextAfterId") == null;

    ManagedAssetApi.Response history = api.history(id, java.net.URI.create("http://localhost/api/v1/managed-assets/" + id + "/revisions?limit=1"));
    assert ((List<?>) history.body().get("revisions")).size() == 1;
    assert history.body().get("nextBeforeRevision") != null;
    ManagedAssetApi.Response olderHistory = api.history(id, java.net.URI.create(
        "http://localhost/api/v1/managed-assets/" + id + "/revisions?limit=1&beforeRevision="
            + history.body().get("nextBeforeRevision")));
    assert ((List<?>) olderHistory.body().get("revisions")).size() == 1;
    assert olderHistory.body().get("nextBeforeRevision") == null;

    String retiredJson = revisedJson.replace("\"ACTIVE\"", "\"RETIRED\"");
    ManagedAssetApi.Response retired = api.revise(id, "application/json", body(retiredJson), etag2, "dana");
    assert retired.status() == 200;
    assert registry.find(id).orElseThrow().currentRevision().lifecycleStatus() == LifecycleStatus.RETIRED;

    System.out.println("ManagedAssetApiSelfTest: PASS");
  }

  private static ByteArrayInputStream body(String text) {
    return new ByteArrayInputStream(text.getBytes(StandardCharsets.UTF_8));
  }

  private static final class FakeRegistry implements ManagedAssetRegistry {
    private final Map<UUID, ManagedAsset> assets = new LinkedHashMap<>();
    private final Map<UUID, List<Revision>> history = new LinkedHashMap<>();
    private long clock;

    @Override public MutationResult create(UUID id, String customerKey, RevisionDraft draft) {
      for (ManagedAsset a : assets.values()) {
        if (customerKey != null && customerKey.equals(a.customerAssetKey())) {
          return new MutationResult(MutationStatus.CUSTOMER_KEY_CONFLICT, a);
        }
      }
      Instant now = Instant.parse("2026-08-20T10:00:00Z").plusSeconds(clock++);
      Revision r = materialize(id, 1, draft, now);
      ManagedAsset a = new ManagedAsset(id, customerKey, now, r);
      assets.put(id, a);
      history.put(id, new ArrayList<>(List.of(r)));
      return new MutationResult(MutationStatus.CREATED, a);
    }

    @Override public MutationResult revise(UUID id, int expected, RevisionDraft draft) {
      ManagedAsset current = assets.get(id);
      if (current == null) return new MutationResult(MutationStatus.NOT_FOUND, null);
      int revision = current.currentRevision().revision();
      if (revision == expected + 1 && draft.sameCustomerState(current.currentRevision())) {
        return new MutationResult(MutationStatus.REPLAYED, current);
      }
      if (revision != expected) return new MutationResult(MutationStatus.REVISION_CONFLICT, current);
      if (draft.sameCustomerState(current.currentRevision())) return new MutationResult(MutationStatus.REPLAYED, current);
      Instant now = Instant.parse("2026-08-20T10:00:00Z").plusSeconds(clock++);
      Revision next = materialize(id, revision + 1, draft, now);
      ManagedAsset updated = new ManagedAsset(id, current.customerAssetKey(), current.createdAt(), next);
      assets.put(id, updated);
      history.get(id).add(next);
      return new MutationResult(MutationStatus.UPDATED, updated);
    }

    @Override public Optional<ManagedAsset> find(UUID id) { return Optional.ofNullable(assets.get(id)); }

    @Override public ManagedAssetPage list(int limit, UUID afterId, LifecycleFilter filter) {
      List<ManagedAsset> rows = assets.values().stream()
          .filter(a -> afterId == null || a.id().compareTo(afterId) > 0)
          .filter(a -> filter == LifecycleFilter.ALL || a.currentRevision().lifecycleStatus().name().equals(filter.name()))
          .sorted(Comparator.comparing(ManagedAsset::id))
          .toList();
      boolean more = rows.size() > limit;
      List<ManagedAsset> page = rows.subList(0, Math.min(rows.size(), limit));
      UUID next = more ? page.get(page.size() - 1).id() : null;
      return new ManagedAssetPage(page, next);
    }

    @Override public Optional<RevisionPage> history(UUID id, int limit, Integer beforeRevision) {
      List<Revision> rows = history.get(id);
      if (rows == null) return Optional.empty();
      List<Revision> ordered = rows.stream()
          .filter(r -> beforeRevision == null || r.revision() < beforeRevision)
          .sorted(Comparator.comparingInt(Revision::revision).reversed())
          .toList();
      boolean more = ordered.size() > limit;
      List<Revision> page = ordered.subList(0, Math.min(ordered.size(), limit));
      Integer next = more ? page.get(page.size() - 1).revision() : null;
      return Optional.of(new RevisionPage(id, page, next));
    }

    private static Revision materialize(UUID id, int n, RevisionDraft draft, Instant now) {
      String sha = sha(id + "|" + n + "|" + draft + "|" + now);
      return new Revision(UUID.nameUUIDFromBytes((id + ":" + n).getBytes(StandardCharsets.UTF_8)), id, n,
          draft.lifecycleStatus(), draft.displayName(), draft.environment(), draft.businessService(),
          draft.businessOwner(), draft.businessCriticality(), draft.classificationMethod(),
          draft.guideContractId(), draft.guideRevision(), ManagedAsset.CONTEXT_SOURCE, sha,
          draft.changedBy(), draft.changeNote(), now);
    }

    private static String sha(String value) {
      try {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)));
      } catch (Exception e) {
        throw new IllegalStateException(e);
      }
    }
  }
}

package io.rbvm.csv;

import io.rbvm.context.FindingBusinessServiceLink;
import io.rbvm.context.FindingBusinessServiceLink.ChangeDraft;
import io.rbvm.context.FindingBusinessServiceLink.LinkStatus;
import io.rbvm.context.FindingBusinessServiceLinkRegistry;
import io.rbvm.context.FindingBusinessServiceLinkRegistry.CurrentLookup;
import io.rbvm.context.FindingBusinessServiceLinkRegistry.CurrentPage;
import io.rbvm.context.FindingBusinessServiceLinkRegistry.HistoryPage;
import io.rbvm.context.FindingBusinessServiceLinkRegistry.MutationResult;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

/** HTTP contract logic for explicit Finding-to-business-service association decisions. */
public final class FindingBusinessServiceLinkApi {
    public static final String CONTRACT_ID = "FINDING_BUSINESS_SERVICE_LINK_API_V1";
    private static final String TAG_PREFIX = "fbs";
    private static final String QUERY_CODE = "INVALID_FINDING_BUSINESS_SERVICE_LINK_QUERY";
    private static final String REQUEST_CODE = "FINDING_BUSINESS_SERVICE_LINK_REQUEST_REJECTED";
    private static final Set<String> TARGET_QUERY_FIELDS = Set.of("businessService");
    private static final Set<String> HISTORY_QUERY_FIELDS = Set.of(
            "businessService", "limit", "beforeRevision");
    private static final Set<String> LIST_QUERY_FIELDS = Set.of("limit", "afterEventId");
    private static final Set<String> MUTATION_FIELDS = Set.of(
            "linkStatus", "businessService", "changeNote");

    private final FindingBusinessServiceLinkRegistry registry;

    public FindingBusinessServiceLinkApi(FindingBusinessServiceLinkRegistry registry) {
        this.registry = Objects.requireNonNull(registry, "registry");
    }

    public Response list(UUID findingId, URI uri) throws IOException {
        Objects.requireNonNull(findingId, "findingId");
        Map<String, String> query = FindingContextAssociationApiSupport.query(
                uri, LIST_QUERY_FIELDS, QUERY_CODE);
        int limit = FindingContextAssociationApiSupport.pageLimit(query.get("limit"), QUERY_CODE);
        UUID after = FindingContextAssociationApiSupport.optionalUuid(
                query.get("afterEventId"), "afterEventId", QUERY_CODE);
        CurrentPage page = registry.listCurrent(findingId, limit, after).orElseThrow(() ->
                FindingContextAssociationApiSupport.problem(
                        404, "FINDING_NOT_FOUND", "Finding does not exist"));
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("findingId", findingId.toString());
        body.put("links", page.links().stream().map(FindingBusinessServiceLinkApi::linkView).toList());
        body.put("nextAfterEventId",
                page.nextAfterEventId() == null ? null : page.nextAfterEventId().toString());
        return new Response(200, Map.of(), body);
    }

    public Response current(UUID findingId, URI uri) throws IOException {
        Objects.requireNonNull(findingId, "findingId");
        Map<String, String> query = FindingContextAssociationApiSupport.query(
                uri, TARGET_QUERY_FIELDS, QUERY_CODE);
        String service = targetFromQuery(query);
        CurrentLookup lookup = registry.current(findingId, service);
        if (!lookup.findingExists()) {
            throw FindingContextAssociationApiSupport.problem(
                    404, "FINDING_NOT_FOUND", "Finding does not exist");
        }
        FindingBusinessServiceLink current = lookup.currentOptional().orElse(null);
        String etag = current == null ? zeroEtag(findingId, service) : etag(current);
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("findingId", findingId.toString());
        body.put("businessService", service);
        body.put("associationState", current == null ? "NEVER_ASSESSED" : current.linkStatus().name());
        body.put("currentLink", current == null ? null : linkView(current));
        return new Response(200, Map.of("ETag", etag), body);
    }

    public Response history(UUID findingId, URI uri) throws IOException {
        Objects.requireNonNull(findingId, "findingId");
        Map<String, String> query = FindingContextAssociationApiSupport.query(
                uri, HISTORY_QUERY_FIELDS, QUERY_CODE);
        String service = targetFromQuery(query);
        int limit = FindingContextAssociationApiSupport.pageLimit(query.get("limit"), QUERY_CODE);
        Integer beforeRevision = FindingContextAssociationApiSupport.optionalPositiveInteger(
                query.get("beforeRevision"), "beforeRevision", QUERY_CODE);
        HistoryPage page = registry.history(findingId, service, limit, beforeRevision)
                .orElseThrow(() -> FindingContextAssociationApiSupport.problem(
                        404, "FINDING_NOT_FOUND", "Finding does not exist"));
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("findingId", findingId.toString());
        body.put("businessService", service);
        body.put("revisions", page.events().stream().map(FindingBusinessServiceLinkApi::linkView).toList());
        body.put("nextBeforeRevision", page.nextBeforeRevision());
        return new Response(200, Map.of(), body);
    }

    public Response revise(
            UUID findingId,
            String contentType,
            InputStream input,
            String ifMatch,
            String actorId
    ) throws IOException {
        Objects.requireNonNull(findingId, "findingId");
        ManagedAssetApi.requireJsonContentType(contentType);
        Map<String, Object> values = ManagedAssetApi.readJsonObject(input);
        FindingContextAssociationApiSupport.rejectUnknownBody(values, MUTATION_FIELDS, REQUEST_CODE);
        String service = targetFromBody(values);
        LinkStatus status = FindingContextAssociationApiSupport.requiredBodyEnum(
                values, "linkStatus", LinkStatus.class, REQUEST_CODE);
        String note = FindingContextAssociationApiSupport.optionalBodyText(
                values, "changeNote", REQUEST_CODE);
        ChangeDraft draft;
        try {
            draft = new ChangeDraft(
                    status,
                    service,
                    FindingContextAssociationApiSupport.actor(actorId),
                    note == null ? "" : note
            );
        } catch (IllegalArgumentException | NullPointerException exception) {
            throw FindingContextAssociationApiSupport.problem(422, REQUEST_CODE, exception.getMessage());
        }

        var expected = FindingContextAssociationApiSupport.requireIfMatch(
                ifMatch,
                TAG_PREFIX,
                "FINDING_BUSINESS_SERVICE_LINK_PRECONDITION_REQUIRED",
                "Finding business-service link"
        );
        CurrentLookup lookup = registry.current(findingId, service);
        if (!lookup.findingExists()) {
            throw FindingContextAssociationApiSupport.problem(
                    404, "FINDING_NOT_FOUND", "Finding does not exist");
        }
        FindingBusinessServiceLink current = lookup.currentOptional().orElse(null);
        if (!ifMatchAuthenticates(findingId, service, current, expected)) {
            throw FindingContextAssociationApiSupport.problem(
                    412,
                    "FINDING_BUSINESS_SERVICE_LINK_PRECONDITION_FAILED",
                    "If-Match does not identify this service's current revision or its immediately prior replay basis"
            );
        }

        MutationResult result = registry.revise(findingId, expected.revision(), draft);
        return switch (result.status()) {
            case UPDATED, REPLAYED -> linkResponse(result.current());
            case FINDING_NOT_FOUND -> throw FindingContextAssociationApiSupport.problem(
                    404, "FINDING_NOT_FOUND", "Finding does not exist");
            case REVISION_CONFLICT -> throw FindingContextAssociationApiSupport.problem(
                    412,
                    "FINDING_BUSINESS_SERVICE_LINK_PRECONDITION_FAILED",
                    "Finding business-service link state changed before this request was applied"
            );
        };
    }

    private boolean ifMatchAuthenticates(
            UUID findingId,
            String service,
            FindingBusinessServiceLink current,
            FindingContextAssociationApiSupport.IfMatch expected
    ) throws IOException {
        if (current == null) {
            return expected.revision() == 0 && expected.value().equals(zeroEtag(findingId, service));
        }
        if (expected.revision() == current.revision() && expected.value().equals(etag(current))) {
            return true;
        }
        if (expected.revision() != current.revision() - 1) {
            return false;
        }
        if (expected.revision() == 0) {
            return expected.value().equals(zeroEtag(findingId, service));
        }
        HistoryPage page = registry.history(findingId, service, 1, current.revision())
                .orElseThrow(() -> new IllegalStateException("Finding disappeared during ETag validation"));
        return !page.events().isEmpty() && expected.value().equals(etag(page.events().get(0)));
    }

    private static Response linkResponse(FindingBusinessServiceLink link) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("findingId", link.findingId().toString());
        body.put("businessService", link.businessService());
        body.put("associationState", link.linkStatus().name());
        body.put("currentLink", linkView(link));
        return new Response(200, Map.of("ETag", etag(link)), body);
    }

    static String etag(FindingBusinessServiceLink link) {
        return FindingContextAssociationApiSupport.eventEtag(
                TAG_PREFIX, link.revision(), link.evidenceSha256());
    }

    static String zeroEtag(UUID findingId, String service) {
        String normalized = FindingContextAssociationApiSupport.normalizedKey(
                service, "businessService", 256, 400, QUERY_CODE);
        String payload = "findingId=" + findingId + "\n"
                + "businessService=" + normalized + "\n";
        return FindingContextAssociationApiSupport.zeroEtag(
                TAG_PREFIX, CONTRACT_ID, payload);
    }

    private static String targetFromQuery(Map<String, String> query) {
        String raw = FindingContextAssociationApiSupport.requiredQueryText(
                query, "businessService", 256, QUERY_CODE);
        return FindingContextAssociationApiSupport.normalizedKey(
                raw, "businessService", 256, 400, QUERY_CODE);
    }

    private static String targetFromBody(Map<String, Object> values) {
        String raw = FindingContextAssociationApiSupport.requiredBodyText(
                values, "businessService", 256, REQUEST_CODE);
        return FindingContextAssociationApiSupport.normalizedKey(
                raw, "businessService", 256, 422, REQUEST_CODE);
    }

    private static Map<String, Object> linkView(FindingBusinessServiceLink link) {
        Map<String, Object> output = new LinkedHashMap<>();
        output.put("eventId", link.eventId().toString());
        output.put("findingId", link.findingId().toString());
        output.put("revision", link.revision());
        output.put("linkStatus", link.linkStatus().name());
        output.put("businessService", link.businessService());
        output.put("linkMethod", link.linkMethod().name());
        output.put("evidenceSha256", link.evidenceSha256());
        output.put("changedBy", link.changedBy());
        output.put("changeNote", link.changeNote());
        output.put("recordedAt", link.recordedAt().toString());
        return output;
    }

    public record Response(int status, Map<String, String> headers, Map<String, Object> body) {
        public Response {
            if (status < 200 || status > 299) {
                throw new IllegalArgumentException("response status must be successful");
            }
            headers = Map.copyOf(Objects.requireNonNull(headers, "headers"));
            body = Collections.unmodifiableMap(new LinkedHashMap<>(Objects.requireNonNull(body, "body")));
        }
    }
}

package io.rbvm.csv;

import io.rbvm.context.FindingReachabilityScopeLink;
import io.rbvm.context.FindingReachabilityScopeLink.ChangeDraft;
import io.rbvm.context.FindingReachabilityScopeLink.LinkStatus;
import io.rbvm.context.FindingReachabilityScopeLink.OriginScope;
import io.rbvm.context.FindingReachabilityScopeLink.TransportProtocol;
import io.rbvm.context.FindingReachabilityScopeLinkRegistry;
import io.rbvm.context.FindingReachabilityScopeLinkRegistry.CurrentLookup;
import io.rbvm.context.FindingReachabilityScopeLinkRegistry.CurrentPage;
import io.rbvm.context.FindingReachabilityScopeLinkRegistry.HistoryPage;
import io.rbvm.context.FindingReachabilityScopeLinkRegistry.MutationResult;
import io.rbvm.context.FindingReachabilityScopeLinkRegistry.MutationStatus;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

/** HTTP contract logic for explicit Finding-to-reachability-scope association decisions. */
public final class FindingReachabilityScopeLinkApi {
    public static final String CONTRACT_ID = "FINDING_REACHABILITY_SCOPE_LINK_API_V1";
    private static final String TAG_PREFIX = "frs";
    private static final String QUERY_CODE = "INVALID_FINDING_REACHABILITY_LINK_QUERY";
    private static final String REQUEST_CODE = "FINDING_REACHABILITY_LINK_REQUEST_REJECTED";
    private static final Set<String> TARGET_QUERY_FIELDS = Set.of(
            "originScope", "originLabel", "transportProtocol", "targetPort"
    );
    private static final Set<String> HISTORY_QUERY_FIELDS = Set.of(
            "originScope", "originLabel", "transportProtocol", "targetPort",
            "limit", "beforeRevision"
    );
    private static final Set<String> LIST_QUERY_FIELDS = Set.of("limit", "afterEventId");
    private static final Set<String> MUTATION_FIELDS = Set.of(
            "linkStatus", "originScope", "originLabel", "transportProtocol",
            "targetPort", "changeNote"
    );

    private final FindingReachabilityScopeLinkRegistry registry;

    public FindingReachabilityScopeLinkApi(FindingReachabilityScopeLinkRegistry registry) {
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
        body.put("links", page.links().stream().map(FindingReachabilityScopeLinkApi::linkView).toList());
        body.put("nextAfterEventId",
                page.nextAfterEventId() == null ? null : page.nextAfterEventId().toString());
        return new Response(200, Map.of(), body);
    }

    public Response current(UUID findingId, URI uri) throws IOException {
        Objects.requireNonNull(findingId, "findingId");
        Map<String, String> query = FindingContextAssociationApiSupport.query(
                uri, TARGET_QUERY_FIELDS, QUERY_CODE);
        Target target = Target.fromQuery(query);
        CurrentLookup lookup = registry.current(
                findingId,
                target.originScope(),
                target.originLabel(),
                target.transportProtocol(),
                target.targetPort()
        );
        if (!lookup.findingExists()) {
            throw FindingContextAssociationApiSupport.problem(
                    404, "FINDING_NOT_FOUND", "Finding does not exist");
        }
        FindingReachabilityScopeLink current = lookup.currentOptional().orElse(null);
        String etag = current == null ? zeroEtag(findingId, target) : etag(current);
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("findingId", findingId.toString());
        body.put("target", target.view());
        body.put("associationState", current == null ? "NEVER_ASSESSED" : current.linkStatus().name());
        body.put("currentLink", current == null ? null : linkView(current));
        return new Response(200, Map.of("ETag", etag), body);
    }

    public Response history(UUID findingId, URI uri) throws IOException {
        Objects.requireNonNull(findingId, "findingId");
        Map<String, String> query = FindingContextAssociationApiSupport.query(
                uri, HISTORY_QUERY_FIELDS, QUERY_CODE);
        Target target = Target.fromQuery(query);
        int limit = FindingContextAssociationApiSupport.pageLimit(query.get("limit"), QUERY_CODE);
        Integer beforeRevision = FindingContextAssociationApiSupport.optionalPositiveInteger(
                query.get("beforeRevision"), "beforeRevision", QUERY_CODE);
        HistoryPage page = registry.history(
                findingId,
                target.originScope(),
                target.originLabel(),
                target.transportProtocol(),
                target.targetPort(),
                limit,
                beforeRevision
        ).orElseThrow(() -> FindingContextAssociationApiSupport.problem(
                404, "FINDING_NOT_FOUND", "Finding does not exist"));
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("findingId", findingId.toString());
        body.put("target", target.view());
        body.put("revisions", page.events().stream().map(FindingReachabilityScopeLinkApi::linkView).toList());
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
        Target target = Target.fromBody(values);
        LinkStatus status = FindingContextAssociationApiSupport.requiredBodyEnum(
                values, "linkStatus", LinkStatus.class, REQUEST_CODE);
        String note = FindingContextAssociationApiSupport.optionalBodyText(
                values, "changeNote", REQUEST_CODE);
        ChangeDraft draft;
        try {
            draft = new ChangeDraft(
                    status,
                    target.originScope(),
                    target.originLabel(),
                    target.transportProtocol(),
                    target.targetPort(),
                    FindingContextAssociationApiSupport.actor(actorId),
                    note == null ? "" : note
            );
        } catch (IllegalArgumentException | NullPointerException exception) {
            throw FindingContextAssociationApiSupport.problem(422, REQUEST_CODE, exception.getMessage());
        }

        var expected = FindingContextAssociationApiSupport.requireIfMatch(
                ifMatch,
                TAG_PREFIX,
                "FINDING_REACHABILITY_LINK_PRECONDITION_REQUIRED",
                "Finding reachability-link"
        );
        CurrentLookup lookup = registry.current(
                findingId,
                target.originScope(),
                target.originLabel(),
                target.transportProtocol(),
                target.targetPort()
        );
        if (!lookup.findingExists()) {
            throw FindingContextAssociationApiSupport.problem(
                    404, "FINDING_NOT_FOUND", "Finding does not exist");
        }
        FindingReachabilityScopeLink current = lookup.currentOptional().orElse(null);
        if (!ifMatchAuthenticates(findingId, target, current, expected)) {
            throw FindingContextAssociationApiSupport.problem(
                    412,
                    "FINDING_REACHABILITY_LINK_PRECONDITION_FAILED",
                    "If-Match does not identify this scope's current revision or its immediately prior replay basis"
            );
        }

        MutationResult result = registry.revise(findingId, expected.revision(), draft);
        return switch (result.status()) {
            case UPDATED, REPLAYED -> linkResponse(result.current());
            case FINDING_NOT_FOUND -> throw FindingContextAssociationApiSupport.problem(
                    404, "FINDING_NOT_FOUND", "Finding does not exist");
            case REVISION_CONFLICT -> throw FindingContextAssociationApiSupport.problem(
                    412,
                    "FINDING_REACHABILITY_LINK_PRECONDITION_FAILED",
                    "Finding reachability-link state changed before this request was applied"
            );
        };
    }

    private boolean ifMatchAuthenticates(
            UUID findingId,
            Target target,
            FindingReachabilityScopeLink current,
            FindingContextAssociationApiSupport.IfMatch expected
    ) throws IOException {
        if (current == null) {
            return expected.revision() == 0 && expected.value().equals(zeroEtag(findingId, target));
        }
        if (expected.revision() == current.revision() && expected.value().equals(etag(current))) {
            return true;
        }
        if (expected.revision() != current.revision() - 1) {
            return false;
        }
        if (expected.revision() == 0) {
            return expected.value().equals(zeroEtag(findingId, target));
        }
        HistoryPage page = registry.history(
                findingId,
                target.originScope(),
                target.originLabel(),
                target.transportProtocol(),
                target.targetPort(),
                1,
                current.revision()
        ).orElseThrow(() -> new IllegalStateException("Finding disappeared during ETag validation"));
        return !page.events().isEmpty() && expected.value().equals(etag(page.events().get(0)));
    }

    private static Response linkResponse(FindingReachabilityScopeLink link) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("findingId", link.findingId().toString());
        body.put("associationState", link.linkStatus().name());
        body.put("currentLink", linkView(link));
        return new Response(200, Map.of("ETag", etag(link)), body);
    }

    static String etag(FindingReachabilityScopeLink link) {
        return FindingContextAssociationApiSupport.eventEtag(
                TAG_PREFIX, link.revision(), link.evidenceSha256());
    }

    static String zeroEtag(UUID findingId, Target target) {
        String payload = "findingId=" + findingId + "\n"
                + "originScope=" + target.originScope().name() + "\n"
                + "originLabel=" + target.originLabel() + "\n"
                + "transportProtocol=" + target.transportProtocol().name() + "\n"
                + "targetPort=" + (target.targetPort() == null ? "" : target.targetPort()) + "\n";
        return FindingContextAssociationApiSupport.zeroEtag(
                TAG_PREFIX, CONTRACT_ID, payload);
    }

    private static Map<String, Object> linkView(FindingReachabilityScopeLink link) {
        Map<String, Object> output = new LinkedHashMap<>();
        output.put("eventId", link.eventId().toString());
        output.put("findingId", link.findingId().toString());
        output.put("revision", link.revision());
        output.put("linkStatus", link.linkStatus().name());
        output.put("originScope", link.originScope().name());
        output.put("originLabel", link.originLabel());
        output.put("transportProtocol", link.transportProtocol().name());
        output.put("targetPort", link.targetPort());
        output.put("linkMethod", link.linkMethod().name());
        output.put("evidenceSha256", link.evidenceSha256());
        output.put("changedBy", link.changedBy());
        output.put("changeNote", link.changeNote());
        output.put("recordedAt", link.recordedAt().toString());
        return output;
    }

    record Target(
            OriginScope originScope,
            String originLabel,
            TransportProtocol transportProtocol,
            Integer targetPort
    ) {
        Target {
            originScope = Objects.requireNonNull(originScope, "originScope");
            originLabel = FindingContextAssociationApiSupport.normalizedKey(
                    originLabel, "originLabel", 256, 400, QUERY_CODE);
            transportProtocol = Objects.requireNonNull(transportProtocol, "transportProtocol");
            validatePort(transportProtocol, targetPort, 400, QUERY_CODE);
        }

        static Target fromQuery(Map<String, String> query) {
            return new Target(
                    FindingContextAssociationApiSupport.requiredQueryEnum(
                            query, "originScope", OriginScope.class, QUERY_CODE),
                    FindingContextAssociationApiSupport.requiredQueryText(
                            query, "originLabel", 256, QUERY_CODE),
                    FindingContextAssociationApiSupport.requiredQueryEnum(
                            query, "transportProtocol", TransportProtocol.class, QUERY_CODE),
                    FindingContextAssociationApiSupport.optionalQueryPort(
                            query.get("targetPort"), QUERY_CODE)
            );
        }

        static Target fromBody(Map<String, Object> values) {
            OriginScope originScope = FindingContextAssociationApiSupport.requiredBodyEnum(
                    values, "originScope", OriginScope.class, REQUEST_CODE);
            String originLabel = FindingContextAssociationApiSupport.requiredBodyText(
                    values, "originLabel", 256, REQUEST_CODE);
            TransportProtocol protocol = FindingContextAssociationApiSupport.requiredBodyEnum(
                    values, "transportProtocol", TransportProtocol.class, REQUEST_CODE);
            Integer port = FindingContextAssociationApiSupport.optionalBodyPort(
                    values, "targetPort", REQUEST_CODE);
            try {
                String normalized = FindingContextAssociationApiSupport.normalizedKey(
                        originLabel, "originLabel", 256, 422, REQUEST_CODE);
                validatePort(protocol, port, 422, REQUEST_CODE);
                return new Target(originScope, normalized, protocol, port);
            } catch (ManagedAssetApi.ApiProblem problem) {
                if (problem.status() == 400) {
                    throw FindingContextAssociationApiSupport.problem(422, REQUEST_CODE, problem.getMessage());
                }
                throw problem;
            }
        }

        Map<String, Object> view() {
            Map<String, Object> output = new LinkedHashMap<>();
            output.put("originScope", originScope.name());
            output.put("originLabel", originLabel);
            output.put("transportProtocol", transportProtocol.name());
            output.put("targetPort", targetPort);
            return output;
        }

        private static void validatePort(
                TransportProtocol protocol,
                Integer targetPort,
                int status,
                String code
        ) {
            if (targetPort != null && (targetPort < 1 || targetPort > 65_535)) {
                throw FindingContextAssociationApiSupport.problem(
                        status, code, "targetPort must be between 1 and 65535 when present");
            }
            if ((protocol == TransportProtocol.TCP || protocol == TransportProtocol.UDP)
                    && targetPort == null) {
                throw FindingContextAssociationApiSupport.problem(
                        status, code, "targetPort is required for TCP or UDP scope");
            }
            if (protocol == TransportProtocol.ICMP && targetPort != null) {
                throw FindingContextAssociationApiSupport.problem(
                        status, code, "targetPort must be absent for ICMP scope");
            }
        }
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

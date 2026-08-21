package io.rbvm.csv;

import io.rbvm.asset.ScannerManagedAssetLink;
import io.rbvm.asset.ScannerManagedAssetLink.ChangeDraft;
import io.rbvm.asset.ScannerManagedAssetLink.LinkStatus;
import io.rbvm.asset.ScannerManagedAssetLinkRegistry;
import io.rbvm.asset.ScannerManagedAssetLinkRegistry.CurrentLookup;
import io.rbvm.asset.ScannerManagedAssetLinkRegistry.HistoryPage;
import io.rbvm.asset.ScannerManagedAssetLinkRegistry.MutationResult;
import io.rbvm.asset.ScannerManagedAssetLinkRegistry.ScannerAssetPage;
import io.rbvm.asset.ScannerManagedAssetLinkRegistry.ScannerAssetSummary;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** HTTP-facing contract for explicit customer-confirmed scanner↔managed-asset links. */
public final class ScannerManagedAssetLinkApi {
    public static final String CONTRACT_ID = "SCANNER_MANAGED_ASSET_LINK_API_V1";
    private static final int DEFAULT_PAGE_LIMIT = 100;
    private static final int MAXIMUM_PAGE_LIMIT = 500;
    private static final Pattern ETAG = Pattern.compile(
            "^\\\"sma-r([0-9]+)-([a-f0-9]{64})\\\"$");
    private static final Set<String> REVISION_FIELDS = Set.of(
            "linkStatus", "managedAssetId", "changeNote"
    );

    private final ScannerManagedAssetLinkRegistry registry;

    public ScannerManagedAssetLinkApi(ScannerManagedAssetLinkRegistry registry) {
        this.registry = Objects.requireNonNull(registry, "registry");
    }

    public Response list(URI uri) throws IOException {
        Map<String, String> query = parseQuery(uri);
        rejectUnknownQuery(query, Set.of("limit", "afterId"));
        int limit = pageLimit(query.get("limit"));
        UUID afterId = optionalUuid(query.get("afterId"), "afterId");
        ScannerAssetPage page = registry.list(limit, afterId);
        List<Map<String, Object>> rows = page.assets().stream()
                .map(ScannerManagedAssetLinkApi::scannerAssetView)
                .toList();
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("assets", rows);
        body.put("nextAfterId", page.nextAfterId() == null ? null : page.nextAfterId().toString());
        return new Response(200, Map.of(), body);
    }

    public Response current(UUID scannerAssetId) throws IOException {
        CurrentLookup lookup = registry.current(scannerAssetId);
        if (!lookup.scannerAssetExists()) {
            throw new ManagedAssetApi.ApiProblem(
                    404,
                    "SCANNER_ASSET_NOT_FOUND",
                    "Scanner asset does not exist"
            );
        }
        return currentResponse(scannerAssetId, lookup.current());
    }

    public Response history(UUID scannerAssetId, URI uri) throws IOException {
        Map<String, String> query = parseQuery(uri);
        rejectUnknownQuery(query, Set.of("limit", "beforeRevision"));
        int limit = pageLimit(query.get("limit"));
        Integer beforeRevision = optionalPositiveInteger(query.get("beforeRevision"), "beforeRevision");
        HistoryPage page = registry.history(scannerAssetId, limit, beforeRevision)
                .orElseThrow(() -> new ManagedAssetApi.ApiProblem(
                        404,
                        "SCANNER_ASSET_NOT_FOUND",
                        "Scanner asset does not exist"
                ));
        List<Map<String, Object>> events = page.events().stream()
                .map(ScannerManagedAssetLinkApi::linkView)
                .toList();
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("scannerAssetId", scannerAssetId.toString());
        body.put("events", events);
        body.put("nextBeforeRevision", page.nextBeforeRevision());
        return new Response(200, Map.of(), body);
    }

    public Response revise(
            UUID scannerAssetId,
            String contentType,
            InputStream input,
            String ifMatch,
            String actorId
    ) throws IOException {
        ManagedAssetApi.requireJsonContentType(contentType);
        IfMatch expected = requireIfMatch(ifMatch);
        Map<String, Object> values = ManagedAssetApi.readJsonObject(input);
        rejectUnknownBody(values);
        ChangeDraft draft = changeDraft(values, actorId);

        CurrentLookup before = registry.current(scannerAssetId);
        if (!before.scannerAssetExists()) {
            throw new ManagedAssetApi.ApiProblem(
                    404,
                    "SCANNER_ASSET_NOT_FOUND",
                    "Scanner asset does not exist"
            );
        }
        if (!ifMatchAuthenticatesRevision(scannerAssetId, before.current(), expected)) {
            throw new ManagedAssetApi.ApiProblem(
                    412,
                    "SCANNER_MANAGED_ASSET_LINK_PRECONDITION_FAILED",
                    "If-Match does not identify the current link decision or its immediately prior replay basis"
            );
        }

        MutationResult result = registry.revise(scannerAssetId, expected.revision(), draft);
        return switch (result.status()) {
            case UPDATED, REPLAYED -> currentResponse(scannerAssetId, result.current());
            case SCANNER_ASSET_NOT_FOUND -> throw new ManagedAssetApi.ApiProblem(
                    404,
                    "SCANNER_ASSET_NOT_FOUND",
                    "Scanner asset does not exist"
            );
            case MANAGED_ASSET_NOT_FOUND -> throw new ManagedAssetApi.ApiProblem(
                    404,
                    "MANAGED_ASSET_NOT_FOUND",
                    "Target managed asset does not exist"
            );
            case REVISION_CONFLICT -> throw new ManagedAssetApi.ApiProblem(
                    412,
                    "SCANNER_MANAGED_ASSET_LINK_PRECONDITION_FAILED",
                    "Scanner-managed-asset link changed after the supplied If-Match validator"
            );
        };
    }

    private boolean ifMatchAuthenticatesRevision(
            UUID scannerAssetId,
            ScannerManagedAssetLink current,
            IfMatch expected
    ) throws IOException {
        if (current == null) {
            return expected.revision() == 0 && expected.value().equals(zeroEtag(scannerAssetId));
        }
        if (expected.value().equals(etag(current))) {
            return expected.revision() == current.revision();
        }
        if (current.revision() != expected.revision() + 1) {
            return false;
        }
        if (expected.revision() == 0) {
            return expected.value().equals(zeroEtag(scannerAssetId));
        }
        HistoryPage history = registry.history(scannerAssetId, 2, null).orElse(null);
        if (history == null) {
            return false;
        }
        for (ScannerManagedAssetLink event : history.events()) {
            if (event.revision() == expected.revision()) {
                return expected.value().equals(etag(event));
            }
        }
        return false;
    }

    private static Response currentResponse(UUID scannerAssetId, ScannerManagedAssetLink current) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("scannerAssetId", scannerAssetId.toString());
        body.put("currentLink", current == null ? null : linkView(current));
        String etag = current == null ? zeroEtag(scannerAssetId) : etag(current);
        return new Response(200, Map.of("ETag", etag), body);
    }

    static String etag(ScannerManagedAssetLink event) {
        return "\"sma-r" + event.revision() + '-' + event.evidenceSha256() + "\"";
    }

    static String zeroEtag(UUID scannerAssetId) {
        Objects.requireNonNull(scannerAssetId, "scannerAssetId");
        String payload = CONTRACT_ID + "\n"
                + "scannerAssetId=" + scannerAssetId + "\n"
                + "revision=0\n"
                + "state=NEVER_ASSESSED\n";
        try {
            String sha = HexFormat.of().formatHex(
                    MessageDigest.getInstance("SHA-256")
                            .digest(payload.getBytes(StandardCharsets.UTF_8))
            );
            return "\"sma-r0-" + sha + "\"";
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is unavailable", exception);
        }
    }

    private static Map<String, Object> scannerAssetView(ScannerAssetSummary asset) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("id", asset.scannerAssetId().toString());
        body.put("observedName", asset.observedName());
        body.put("osNameRaw", asset.osNameRaw());
        body.put("sourceProfileKey", asset.sourceProfileKey());
        body.put("identityBasis", asset.identityBasis());
        body.put("identityConfidence", asset.identityConfidence());
        body.put("firstObservedAt", asset.firstObservedAt().toString());
        body.put("lastObservedAt", asset.lastObservedAt().toString());
        body.put("currentLink", asset.current() == null ? null : linkView(asset.current()));
        return body;
    }

    private static Map<String, Object> linkView(ScannerManagedAssetLink event) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("eventId", event.eventId().toString());
        body.put("scannerAssetId", event.scannerAssetId().toString());
        body.put("revision", event.revision());
        body.put("linkStatus", event.linkStatus().name());
        body.put("managedAssetId", event.managedAssetId() == null ? null : event.managedAssetId().toString());
        body.put("linkMethod", event.linkMethod().name());
        body.put("evidenceSha256", event.evidenceSha256());
        body.put("changedBy", event.changedBy());
        body.put("changeNote", event.changeNote());
        body.put("recordedAt", event.recordedAt().toString());
        return body;
    }

    private static ChangeDraft changeDraft(Map<String, Object> values, String actorId) {
        String statusText = requiredString(values, "linkStatus");
        LinkStatus status;
        try {
            status = LinkStatus.valueOf(statusText.toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException exception) {
            throw new ManagedAssetApi.ApiProblem(
                    422,
                    "SCANNER_MANAGED_ASSET_LINK_REQUEST_REJECTED",
                    "linkStatus must be LINKED or UNLINKED"
            );
        }
        UUID managedAssetId = optionalUuidValue(values.get("managedAssetId"), "managedAssetId");
        String changeNote = optionalString(values.get("changeNote"), "changeNote");
        if (changeNote == null) changeNote = "";
        String actor = requireActor(actorId);
        try {
            return new ChangeDraft(status, managedAssetId, actor, changeNote);
        } catch (IllegalArgumentException exception) {
            throw new ManagedAssetApi.ApiProblem(
                    422,
                    "SCANNER_MANAGED_ASSET_LINK_REQUEST_REJECTED",
                    exception.getMessage()
            );
        }
    }

    private static String requireActor(String actorId) {
        if (actorId == null || actorId.isBlank()) {
            throw new ManagedAssetApi.ApiProblem(
                    500,
                    "AUTHENTICATED_ACTOR_UNAVAILABLE",
                    "Authenticated actor identity is unavailable"
            );
        }
        return actorId.trim();
    }

    private static void rejectUnknownBody(Map<String, Object> values) {
        Set<String> unknown = new HashSet<>(values.keySet());
        unknown.removeAll(REVISION_FIELDS);
        if (!unknown.isEmpty()) {
            throw new ManagedAssetApi.ApiProblem(
                    400,
                    "UNKNOWN_SCANNER_MANAGED_ASSET_LINK_FIELDS",
                    "Unknown request fields: " + unknown
            );
        }
    }

    private static String requiredString(Map<String, Object> values, String field) {
        Object value = values.get(field);
        if (!(value instanceof String text) || text.isBlank()) {
            throw new ManagedAssetApi.ApiProblem(
                    422,
                    "SCANNER_MANAGED_ASSET_LINK_REQUEST_REJECTED",
                    field + " is required"
            );
        }
        return text.trim();
    }

    private static String optionalString(Object value, String field) {
        if (value == null) return null;
        if (!(value instanceof String text)) {
            throw new ManagedAssetApi.ApiProblem(
                    422,
                    "SCANNER_MANAGED_ASSET_LINK_REQUEST_REJECTED",
                    field + " must be a string or null"
            );
        }
        return text;
    }

    private static UUID optionalUuidValue(Object value, String field) {
        if (value == null) return null;
        if (!(value instanceof String text)) {
            throw new ManagedAssetApi.ApiProblem(
                    422,
                    "SCANNER_MANAGED_ASSET_LINK_REQUEST_REJECTED",
                    field + " must be a canonical UUID or null"
            );
        }
        String trimmed = text.trim();
        try {
            UUID parsed = UUID.fromString(trimmed);
            if (!parsed.toString().equalsIgnoreCase(trimmed)) {
                throw new IllegalArgumentException("non-canonical UUID");
            }
            return parsed;
        } catch (IllegalArgumentException exception) {
            throw new ManagedAssetApi.ApiProblem(
                    422,
                    "SCANNER_MANAGED_ASSET_LINK_REQUEST_REJECTED",
                    field + " must be a canonical UUID or null"
            );
        }
    }

    private static IfMatch requireIfMatch(String value) {
        if (value == null || value.isBlank()) {
            throw new ManagedAssetApi.ApiProblem(
                    428,
                    "SCANNER_MANAGED_ASSET_LINK_PRECONDITION_REQUIRED",
                    "Link revisions require If-Match from a prior current-state response"
            );
        }
        String trimmed = value.trim();
        if (trimmed.indexOf(',') >= 0 || trimmed.startsWith("W/") || trimmed.equals("*")) {
            throw new ManagedAssetApi.ApiProblem(
                    400,
                    "INVALID_IF_MATCH",
                    "If-Match must contain exactly one strong scanner-managed-asset link ETag"
            );
        }
        Matcher matcher = ETAG.matcher(trimmed);
        if (!matcher.matches()) {
            throw new ManagedAssetApi.ApiProblem(
                    400,
                    "INVALID_IF_MATCH",
                    "If-Match does not contain a valid scanner-managed-asset link ETag"
            );
        }
        int revision;
        try {
            revision = Integer.parseInt(matcher.group(1));
        } catch (NumberFormatException exception) {
            throw new ManagedAssetApi.ApiProblem(
                    400,
                    "INVALID_IF_MATCH",
                    "If-Match revision is out of range"
            );
        }
        return new IfMatch(trimmed, revision);
    }

    private static Map<String, String> parseQuery(URI uri) {
        Map<String, String> output = new LinkedHashMap<>();
        String encoded = uri.getRawQuery();
        if (encoded == null || encoded.isBlank()) return output;
        for (String parameter : encoded.split("&")) {
            String[] pair = parameter.split("=", 2);
            String name;
            String value;
            try {
                name = URLDecoder.decode(pair[0], StandardCharsets.UTF_8);
                value = URLDecoder.decode(pair.length == 2 ? pair[1] : "", StandardCharsets.UTF_8);
            } catch (IllegalArgumentException exception) {
                throw new ManagedAssetApi.ApiProblem(
                        400,
                        "INVALID_SCANNER_ASSET_QUERY",
                        "Invalid query encoding"
                );
            }
            if (name.isBlank()) {
                throw new ManagedAssetApi.ApiProblem(
                        400,
                        "INVALID_SCANNER_ASSET_QUERY",
                        "Query parameter name cannot be empty"
                );
            }
            if (output.putIfAbsent(name, value) != null) {
                throw new ManagedAssetApi.ApiProblem(
                        400,
                        "INVALID_SCANNER_ASSET_QUERY",
                        "Duplicate query parameter: " + name
                );
            }
        }
        return output;
    }

    private static void rejectUnknownQuery(Map<String, String> query, Set<String> allowed) {
        Set<String> unknown = new HashSet<>(query.keySet());
        unknown.removeAll(allowed);
        if (!unknown.isEmpty()) {
            throw new ManagedAssetApi.ApiProblem(
                    400,
                    "INVALID_SCANNER_ASSET_QUERY",
                    "Unknown query parameters: " + unknown
            );
        }
    }

    private static int pageLimit(String value) {
        if (value == null || value.isBlank()) return DEFAULT_PAGE_LIMIT;
        try {
            int limit = Integer.parseInt(value.trim());
            if (limit < 1 || limit > MAXIMUM_PAGE_LIMIT) throw new NumberFormatException();
            return limit;
        } catch (NumberFormatException exception) {
            throw new ManagedAssetApi.ApiProblem(
                    400,
                    "INVALID_SCANNER_ASSET_QUERY",
                    "limit must be between 1 and " + MAXIMUM_PAGE_LIMIT
            );
        }
    }

    private static UUID optionalUuid(String value, String field) {
        if (value == null || value.isBlank()) return null;
        try {
            String trimmed = value.trim();
            UUID parsed = UUID.fromString(trimmed);
            if (!parsed.toString().equalsIgnoreCase(trimmed)) throw new IllegalArgumentException();
            return parsed;
        } catch (IllegalArgumentException exception) {
            throw new ManagedAssetApi.ApiProblem(
                    400,
                    "INVALID_SCANNER_ASSET_QUERY",
                    field + " must be a canonical UUID"
            );
        }
    }

    private static Integer optionalPositiveInteger(String value, String field) {
        if (value == null || value.isBlank()) return null;
        try {
            int parsed = Integer.parseInt(value.trim());
            if (parsed < 1) throw new NumberFormatException();
            return parsed;
        } catch (NumberFormatException exception) {
            throw new ManagedAssetApi.ApiProblem(
                    400,
                    "INVALID_SCANNER_ASSET_QUERY",
                    field + " must be a positive integer"
            );
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

    private record IfMatch(String value, int revision) {
    }
}

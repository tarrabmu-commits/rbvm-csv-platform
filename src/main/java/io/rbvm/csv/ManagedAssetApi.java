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

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Collections;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** HTTP-facing managed-asset contract logic, independent from authentication and socket routing. */
public final class ManagedAssetApi {
    static final int MAXIMUM_BODY_BYTES = 16 * 1024;
    private static final int DEFAULT_PAGE_LIMIT = 100;
    private static final int MAXIMUM_PAGE_LIMIT = 500;
    private static final Pattern ETAG = Pattern.compile(
            "^\\\"ma-r([1-9][0-9]*)-([a-f0-9]{64})\\\"$");
    private static final Set<String> CREATE_FIELDS = Set.of(
            "customerAssetKey", "displayName", "environment", "businessService",
            "businessOwner", "businessCriticality", "classificationMethod",
            "guideContractId", "guideRevision", "changeNote"
    );
    private static final Set<String> REVISION_FIELDS = Set.of(
            "lifecycleStatus", "displayName", "environment", "businessService",
            "businessOwner", "businessCriticality", "classificationMethod",
            "guideContractId", "guideRevision", "changeNote"
    );

    private final ManagedAssetRegistry registry;

    public ManagedAssetApi(ManagedAssetRegistry registry) {
        this.registry = Objects.requireNonNull(registry, "registry");
    }

    public Response list(URI uri) throws IOException {
        Map<String, String> query = parseQuery(uri);
        rejectUnknownQuery(query, Set.of("limit", "afterId", "lifecycle"));
        int limit = pageLimit(query.get("limit"));
        UUID afterId = optionalUuid(query.get("afterId"), "afterId");
        LifecycleFilter filter = lifecycleFilter(query.get("lifecycle"));
        ManagedAssetPage page = registry.list(limit, afterId, filter);

        List<Map<String, Object>> assets = page.assets().stream()
                .map(ManagedAssetApi::assetView)
                .toList();
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("assets", assets);
        body.put("nextAfterId", page.nextAfterId() == null ? null : page.nextAfterId().toString());
        return new Response(200, Map.of(), body);
    }

    public Response create(String contentType, InputStream input, String actorId) throws IOException {
        requireJsonContentType(contentType);
        Map<String, Object> values = readJsonObject(input);
        rejectUnknownBody(values, CREATE_FIELDS);

        RevisionDraft draft = revisionDraft(values, LifecycleStatus.ACTIVE, actorId);
        String customerAssetKey = optionalString(values, "customerAssetKey");
        UUID managedAssetId = UUID.randomUUID();
        MutationResult result = registry.create(managedAssetId, customerAssetKey, draft);
        return switch (result.status()) {
            case CREATED -> assetResponse(
                    201,
                    result.asset(),
                    Map.of("Location", "/api/v1/managed-assets/" + result.asset().id())
            );
            case REPLAYED -> assetResponse(200, result.asset(), Map.of());
            case CUSTOMER_KEY_CONFLICT -> throw new ApiProblem(
                    409,
                    "MANAGED_ASSET_CUSTOMER_KEY_CONFLICT",
                    "customerAssetKey already belongs to another managed asset"
            );
            case ASSET_ID_CONFLICT -> throw new ApiProblem(
                    409,
                    "MANAGED_ASSET_ID_CONFLICT",
                    "Generated managed asset identity conflicts with an existing asset"
            );
            case NOT_FOUND, UPDATED, REVISION_CONFLICT -> throw new IllegalStateException(
                    "Unexpected managed asset create status: " + result.status());
        };
    }

    public Response get(UUID managedAssetId) throws IOException {
        ManagedAsset asset = registry.find(managedAssetId).orElseThrow(() -> new ApiProblem(
                404,
                "MANAGED_ASSET_NOT_FOUND",
                "Managed asset does not exist"
        ));
        return assetResponse(200, asset, Map.of());
    }

    public Response history(UUID managedAssetId, URI uri) throws IOException {
        Map<String, String> query = parseQuery(uri);
        rejectUnknownQuery(query, Set.of("limit", "beforeRevision"));
        int limit = pageLimit(query.get("limit"));
        Integer beforeRevision = optionalPositiveInteger(
                query.get("beforeRevision"),
                "beforeRevision"
        );
        RevisionPage page = registry.history(managedAssetId, limit, beforeRevision)
                .orElseThrow(() -> new ApiProblem(
                        404,
                        "MANAGED_ASSET_NOT_FOUND",
                        "Managed asset does not exist"
                ));

        List<Map<String, Object>> revisions = page.revisions().stream()
                .map(ManagedAssetApi::revisionView)
                .toList();
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("managedAssetId", managedAssetId.toString());
        body.put("revisions", revisions);
        body.put("nextBeforeRevision", page.nextBeforeRevision());
        return new Response(200, Map.of(), body);
    }

    public Response revise(
            UUID managedAssetId,
            String contentType,
            InputStream input,
            String ifMatch,
            String actorId
    ) throws IOException {
        requireJsonContentType(contentType);
        IfMatch expected = requireIfMatch(ifMatch);
        Map<String, Object> values = readJsonObject(input);
        rejectUnknownBody(values, REVISION_FIELDS);
        LifecycleStatus lifecycle = requiredEnum(
                values,
                "lifecycleStatus",
                LifecycleStatus.class
        );
        RevisionDraft draft = revisionDraft(values, lifecycle, actorId);

        ManagedAsset current = registry.find(managedAssetId).orElseThrow(() -> new ApiProblem(
                404,
                "MANAGED_ASSET_NOT_FOUND",
                "Managed asset does not exist"
        ));
        if (!ifMatchAuthenticatesRevision(managedAssetId, current, expected)) {
            throw new ApiProblem(
                    412,
                    "MANAGED_ASSET_PRECONDITION_FAILED",
                    "If-Match does not identify the current revision or its immediately prior replay basis"
            );
        }

        MutationResult result = registry.revise(managedAssetId, expected.revision(), draft);
        return switch (result.status()) {
            case UPDATED, REPLAYED -> assetResponse(200, result.asset(), Map.of());
            case NOT_FOUND -> throw new ApiProblem(
                    404,
                    "MANAGED_ASSET_NOT_FOUND",
                    "Managed asset does not exist"
            );
            case REVISION_CONFLICT -> throw new ApiProblem(
                    412,
                    "MANAGED_ASSET_PRECONDITION_FAILED",
                    "Managed asset changed after the supplied If-Match validator"
            );
            case ASSET_ID_CONFLICT, CUSTOMER_KEY_CONFLICT -> throw new ApiProblem(
                    409,
                    "MANAGED_ASSET_CONFLICT",
                    "Managed asset revision conflicts with the registry"
            );
            case CREATED -> throw new IllegalStateException(
                    "Unexpected managed asset revision status: " + result.status());
        };
    }

    private boolean ifMatchAuthenticatesRevision(
            UUID managedAssetId,
            ManagedAsset current,
            IfMatch expected
    ) throws IOException {
        if (expected.value().equals(etag(current.currentRevision()))) {
            return expected.revision() == current.currentRevision().revision();
        }
        if (current.currentRevision().revision() != expected.revision() + 1) {
            return false;
        }
        RevisionPage history = registry.history(managedAssetId, 2, null).orElse(null);
        if (history == null) {
            return false;
        }
        for (Revision revision : history.revisions()) {
            if (revision.revision() == expected.revision()) {
                return expected.value().equals(etag(revision));
            }
        }
        return false;
    }

    private static Response assetResponse(
            int status,
            ManagedAsset asset,
            Map<String, String> additionalHeaders
    ) {
        Map<String, String> headers = new LinkedHashMap<>(additionalHeaders);
        headers.put("ETag", etag(asset.currentRevision()));
        return new Response(status, headers, assetView(asset));
    }

    private static Map<String, Object> assetView(ManagedAsset asset) {
        Map<String, Object> output = new LinkedHashMap<>();
        output.put("id", asset.id().toString());
        output.put("customerAssetKey", asset.customerAssetKey());
        output.put("createdAt", asset.createdAt().toString());
        output.put("currentRevision", revisionView(asset.currentRevision()));
        return output;
    }

    private static Map<String, Object> revisionView(Revision revision) {
        Map<String, Object> output = new LinkedHashMap<>();
        output.put("id", revision.id().toString());
        output.put("managedAssetId", revision.managedAssetId().toString());
        output.put("revision", revision.revision());
        output.put("lifecycleStatus", revision.lifecycleStatus().name());
        output.put("displayName", revision.displayName());
        output.put("environment", revision.environment().name());
        output.put("businessService", revision.businessService());
        output.put("businessOwner", revision.businessOwner());
        output.put("businessCriticality", revision.businessCriticality().name());
        output.put("classificationMethod", revision.classificationMethod().name());
        output.put("guideContractId", revision.guideContractId());
        output.put("guideRevision", revision.guideRevision());
        output.put("contextSource", revision.contextSource());
        output.put("evidenceSha256", revision.evidenceSha256());
        output.put("changedBy", revision.changedBy());
        output.put("changeNote", revision.changeNote());
        output.put("recordedAt", revision.recordedAt().toString());
        return output;
    }

    static String etag(Revision revision) {
        return "\"ma-r" + revision.revision() + '-' + revision.evidenceSha256() + "\"";
    }

    private static RevisionDraft revisionDraft(
            Map<String, Object> values,
            LifecycleStatus lifecycle,
            String actorId
    ) {
        try {
            return new RevisionDraft(
                    lifecycle,
                    requiredString(values, "displayName"),
                    requiredEnum(values, "environment", Environment.class),
                    requiredString(values, "businessService"),
                    requiredString(values, "businessOwner"),
                    requiredEnum(values, "businessCriticality", BusinessCriticality.class),
                    requiredEnum(values, "classificationMethod", ClassificationMethod.class),
                    optionalString(values, "guideContractId"),
                    optionalInteger(values, "guideRevision"),
                    requireActor(actorId),
                    optionalStringOrEmpty(values, "changeNote")
            );
        } catch (IllegalArgumentException exception) {
            throw new ApiProblem(
                    422,
                    "MANAGED_ASSET_REQUEST_REJECTED",
                    exception.getMessage()
            );
        }
    }

    private static String requireActor(String actorId) {
        if (actorId == null || actorId.isBlank()) {
            throw new IllegalArgumentException("authenticated actorId is required");
        }
        return actorId.trim();
    }

    static void requireJsonContentType(String contentType) {
        if (contentType == null) {
            throw new ApiProblem(
                    415,
                    "UNSUPPORTED_MEDIA_TYPE",
                    "Content-Type must be application/json"
            );
        }
        String mediaType = contentType.split(";", 2)[0].trim();
        if (!mediaType.equalsIgnoreCase("application/json")) {
            throw new ApiProblem(
                    415,
                    "UNSUPPORTED_MEDIA_TYPE",
                    "Content-Type must be application/json"
            );
        }
    }

    private static IfMatch requireIfMatch(String value) {
        if (value == null || value.isBlank()) {
            throw new ApiProblem(
                    428,
                    "MANAGED_ASSET_PRECONDITION_REQUIRED",
                    "Managed asset revisions require If-Match from a prior GET response"
            );
        }
        String trimmed = value.trim();
        if (trimmed.indexOf(',') >= 0 || trimmed.startsWith("W/") || trimmed.equals("*")) {
            throw new ApiProblem(
                    400,
                    "INVALID_IF_MATCH",
                    "If-Match must contain exactly one strong managed-asset ETag"
            );
        }
        Matcher matcher = ETAG.matcher(trimmed);
        if (!matcher.matches()) {
            throw new ApiProblem(
                    400,
                    "INVALID_IF_MATCH",
                    "If-Match does not contain a valid managed-asset ETag"
            );
        }
        int revision;
        try {
            revision = Integer.parseInt(matcher.group(1));
        } catch (NumberFormatException exception) {
            throw new ApiProblem(400, "INVALID_IF_MATCH", "If-Match revision is out of range");
        }
        return new IfMatch(trimmed, revision);
    }

    static Map<String, Object> readJsonObject(InputStream input) throws IOException {
        byte[] bytes = input.readNBytes(MAXIMUM_BODY_BYTES + 1);
        if (bytes.length > MAXIMUM_BODY_BYTES) {
            throw new ApiProblem(
                    413,
                    "MANAGED_ASSET_BODY_TOO_LARGE",
                    "Managed asset request body exceeds 16 KiB"
            );
        }
        String text;
        try {
            text = StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(bytes))
                    .toString();
        } catch (CharacterCodingException exception) {
            throw new ApiProblem(
                    400,
                    "INVALID_JSON",
                    "Managed asset JSON must be valid UTF-8"
            );
        }
        try {
            return new JsonObjectParser(text).parse();
        } catch (IllegalArgumentException exception) {
            throw new ApiProblem(400, "INVALID_JSON", exception.getMessage());
        }
    }

    private static void rejectUnknownBody(Map<String, Object> values, Set<String> allowed) {
        Set<String> unknown = new HashSet<>(values.keySet());
        unknown.removeAll(allowed);
        if (!unknown.isEmpty()) {
            throw new ApiProblem(
                    400,
                    "UNKNOWN_MANAGED_ASSET_FIELDS",
                    "Unknown request fields: " + unknown
            );
        }
    }

    private static String requiredString(Map<String, Object> values, String field) {
        Object value = values.get(field);
        if (!(value instanceof String text) || text.isBlank()) {
            throw new ApiProblem(422, "MANAGED_ASSET_REQUEST_REJECTED", field + " is required");
        }
        return text.trim();
    }

    private static String optionalString(Map<String, Object> values, String field) {
        Object value = values.get(field);
        if (value == null) {
            return null;
        }
        if (!(value instanceof String text)) {
            throw new ApiProblem(
                    422,
                    "MANAGED_ASSET_REQUEST_REJECTED",
                    field + " must be a string or null"
            );
        }
        String trimmed = text.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }

    private static String optionalStringOrEmpty(Map<String, Object> values, String field) {
        String value = optionalString(values, field);
        return value == null ? "" : value;
    }

    private static Integer optionalInteger(Map<String, Object> values, String field) {
        Object value = values.get(field);
        if (value == null) {
            return null;
        }
        if (!(value instanceof Long number) || number < Integer.MIN_VALUE || number > Integer.MAX_VALUE) {
            throw new ApiProblem(
                    422,
                    "MANAGED_ASSET_REQUEST_REJECTED",
                    field + " must be an integer or null"
            );
        }
        return number.intValue();
    }

    private static <E extends Enum<E>> E requiredEnum(
            Map<String, Object> values,
            String field,
            Class<E> type
    ) {
        String value = requiredString(values, field);
        try {
            return Enum.valueOf(type, value.toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException exception) {
            throw new ApiProblem(
                    422,
                    "MANAGED_ASSET_REQUEST_REJECTED",
                    field + " contains an unsupported value"
            );
        }
    }

    private static Map<String, String> parseQuery(URI uri) {
        Map<String, String> output = new LinkedHashMap<>();
        String encoded = uri.getRawQuery();
        if (encoded == null || encoded.isBlank()) {
            return output;
        }
        for (String parameter : encoded.split("&")) {
            String[] pair = parameter.split("=", 2);
            String name;
            String value;
            try {
                name = URLDecoder.decode(pair[0], StandardCharsets.UTF_8);
                value = URLDecoder.decode(pair.length == 2 ? pair[1] : "", StandardCharsets.UTF_8);
            } catch (IllegalArgumentException exception) {
                throw new ApiProblem(400, "INVALID_MANAGED_ASSET_QUERY", "Invalid query encoding");
            }
            if (name.isBlank()) {
                throw new ApiProblem(
                        400,
                        "INVALID_MANAGED_ASSET_QUERY",
                        "Query parameter name cannot be empty"
                );
            }
            if (output.putIfAbsent(name, value) != null) {
                throw new ApiProblem(
                        400,
                        "INVALID_MANAGED_ASSET_QUERY",
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
            throw new ApiProblem(
                    400,
                    "INVALID_MANAGED_ASSET_QUERY",
                    "Unknown query parameters: " + unknown
            );
        }
    }

    private static int pageLimit(String value) {
        if (value == null || value.isBlank()) {
            return DEFAULT_PAGE_LIMIT;
        }
        try {
            int limit = Integer.parseInt(value);
            if (limit < 1 || limit > MAXIMUM_PAGE_LIMIT) {
                throw new NumberFormatException("out of range");
            }
            return limit;
        } catch (NumberFormatException exception) {
            throw new ApiProblem(
                    400,
                    "INVALID_MANAGED_ASSET_QUERY",
                    "limit must be between 1 and " + MAXIMUM_PAGE_LIMIT
            );
        }
    }

    private static UUID optionalUuid(String value, String field) {
        if (value == null || value.isBlank()) {
            return null;
        }
        try {
            UUID parsed = UUID.fromString(value.trim());
            if (!parsed.toString().equalsIgnoreCase(value.trim())) {
                throw new IllegalArgumentException("non-canonical UUID");
            }
            return parsed;
        } catch (IllegalArgumentException exception) {
            throw new ApiProblem(
                    400,
                    "INVALID_MANAGED_ASSET_QUERY",
                    field + " must be a canonical UUID"
            );
        }
    }

    private static Integer optionalPositiveInteger(String value, String field) {
        if (value == null || value.isBlank()) {
            return null;
        }
        try {
            int parsed = Integer.parseInt(value.trim());
            if (parsed < 1) {
                throw new NumberFormatException("not positive");
            }
            return parsed;
        } catch (NumberFormatException exception) {
            throw new ApiProblem(
                    400,
                    "INVALID_MANAGED_ASSET_QUERY",
                    field + " must be a positive integer"
            );
        }
    }

    private static LifecycleFilter lifecycleFilter(String value) {
        if (value == null || value.isBlank()) {
            return LifecycleFilter.ALL;
        }
        try {
            return LifecycleFilter.valueOf(value.trim().toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException exception) {
            throw new ApiProblem(
                    400,
                    "INVALID_MANAGED_ASSET_QUERY",
                    "lifecycle must be ACTIVE, RETIRED, or ALL"
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

    public static final class ApiProblem extends RuntimeException {
        private static final long serialVersionUID = 1L;
        private final int status;
        private final String code;

        ApiProblem(int status, String code, String detail) {
            super(Objects.requireNonNull(detail, "detail"));
            this.status = status;
            this.code = Objects.requireNonNull(code, "code");
        }

        public int status() {
            return status;
        }

        public String code() {
            return code;
        }
    }

    private record IfMatch(String value, int revision) {
    }

    /** Strict flat JSON-object parser for this API contract; nested values are deliberately rejected. */
    private static final class JsonObjectParser {
        private final String text;
        private int index;

        JsonObjectParser(String text) {
            this.text = Objects.requireNonNull(text, "text");
        }

        Map<String, Object> parse() {
            skipWhitespace();
            expect('{');
            Map<String, Object> output = new LinkedHashMap<>();
            skipWhitespace();
            if (peek('}')) {
                index++;
                finish();
                return output;
            }
            while (true) {
                skipWhitespace();
                String key = parseString();
                skipWhitespace();
                expect(':');
                skipWhitespace();
                Object value = parseValue();
                if (output.containsKey(key)) {
                    throw error("Duplicate JSON member: " + key);
                }
                output.put(key, value);
                skipWhitespace();
                if (peek(',')) {
                    index++;
                    continue;
                }
                expect('}');
                finish();
                return output;
            }
        }

        private Object parseValue() {
            if (index >= text.length()) {
                throw error("Missing JSON value");
            }
            char ch = text.charAt(index);
            if (ch == '"') {
                return parseString();
            }
            if (ch == 'n' && consume("null")) {
                return null;
            }
            if (ch == 't' && consume("true")) {
                return Boolean.TRUE;
            }
            if (ch == 'f' && consume("false")) {
                return Boolean.FALSE;
            }
            if (ch == '-' || Character.isDigit(ch)) {
                return parseInteger();
            }
            if (ch == '{' || ch == '[') {
                throw error("Nested JSON values are not supported by the managed asset contract");
            }
            throw error("Unsupported JSON value");
        }

        private Long parseInteger() {
            int start = index;
            if (peek('-')) {
                index++;
            }
            if (index >= text.length() || !Character.isDigit(text.charAt(index))) {
                throw error("Invalid JSON integer");
            }
            if (text.charAt(index) == '0') {
                index++;
                if (index < text.length() && Character.isDigit(text.charAt(index))) {
                    throw error("Invalid leading zero in JSON integer");
                }
            } else {
                while (index < text.length() && Character.isDigit(text.charAt(index))) {
                    index++;
                }
            }
            if (index < text.length()) {
                char next = text.charAt(index);
                if (next == '.' || next == 'e' || next == 'E') {
                    throw error("Managed asset numeric fields must be integers");
                }
            }
            try {
                return Long.parseLong(text.substring(start, index));
            } catch (NumberFormatException exception) {
                throw error("JSON integer is out of range");
            }
        }

        private String parseString() {
            expect('"');
            StringBuilder output = new StringBuilder();
            while (index < text.length()) {
                char ch = text.charAt(index++);
                if (ch == '"') {
                    return output.toString();
                }
                if (ch == '\\') {
                    if (index >= text.length()) {
                        throw error("Incomplete JSON escape");
                    }
                    char escape = text.charAt(index++);
                    switch (escape) {
                        case '"', '\\', '/' -> output.append(escape);
                        case 'b' -> output.append('\b');
                        case 'f' -> output.append('\f');
                        case 'n' -> output.append('\n');
                        case 'r' -> output.append('\r');
                        case 't' -> output.append('\t');
                        case 'u' -> appendUnicodeEscape(output);
                        default -> throw error("Invalid JSON escape");
                    }
                    continue;
                }
                if (ch < 0x20) {
                    throw error("Unescaped JSON control character");
                }
                output.append(ch);
            }
            throw error("Unterminated JSON string");
        }

        private void appendUnicodeEscape(StringBuilder output) {
            char first = parseUnicodeCodeUnit();
            if (Character.isLowSurrogate(first)) {
                throw error("Unpaired low surrogate in JSON unicode escape");
            }
            if (!Character.isHighSurrogate(first)) {
                output.append(first);
                return;
            }
            if (index + 2 > text.length() || text.charAt(index) != '\\'
                    || text.charAt(index + 1) != 'u') {
                throw error("High surrogate must be followed by a low-surrogate unicode escape");
            }
            index += 2;
            char second = parseUnicodeCodeUnit();
            if (!Character.isLowSurrogate(second)) {
                throw error("High surrogate must be followed by a low surrogate");
            }
            output.appendCodePoint(Character.toCodePoint(first, second));
        }

        private char parseUnicodeCodeUnit() {
            if (index + 4 > text.length()) {
                throw error("Incomplete JSON unicode escape");
            }
            int value = 0;
            for (int i = 0; i < 4; i++) {
                int digit = Character.digit(text.charAt(index++), 16);
                if (digit < 0) {
                    throw error("Invalid JSON unicode escape");
                }
                value = (value << 4) | digit;
            }
            return (char) value;
        }

        private boolean consume(String token) {
            if (text.regionMatches(index, token, 0, token.length())) {
                index += token.length();
                return true;
            }
            return false;
        }

        private void finish() {
            skipWhitespace();
            if (index != text.length()) {
                throw error("Unexpected content after JSON object");
            }
        }

        private void skipWhitespace() {
            while (index < text.length()) {
                char ch = text.charAt(index);
                if (ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n') {
                    index++;
                } else {
                    break;
                }
            }
        }

        private boolean peek(char expected) {
            return index < text.length() && text.charAt(index) == expected;
        }

        private void expect(char expected) {
            if (!peek(expected)) {
                throw error("Expected '" + expected + "'");
            }
            index++;
        }

        private IllegalArgumentException error(String message) {
            return new IllegalArgumentException(message + " at character " + index);
        }
    }
}

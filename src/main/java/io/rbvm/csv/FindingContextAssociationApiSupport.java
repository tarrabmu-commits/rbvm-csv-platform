package io.rbvm.csv;

import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.Normalizer;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Shared strict parsing primitives for the two narrow Finding-context association APIs. */
final class FindingContextAssociationApiSupport {
    static final int DEFAULT_PAGE_LIMIT = 100;
    static final int MAXIMUM_PAGE_LIMIT = 500;

    private FindingContextAssociationApiSupport() {
    }

    static Map<String, String> query(URI uri, Set<String> allowed, String code) {
        Objects.requireNonNull(uri, "uri");
        Map<String, String> output = new LinkedHashMap<>();
        String encoded = uri.getRawQuery();
        if (encoded != null && !encoded.isBlank()) {
            for (String parameter : encoded.split("&")) {
                String[] pair = parameter.split("=", 2);
                String name;
                String value;
                try {
                    name = URLDecoder.decode(pair[0], StandardCharsets.UTF_8);
                    value = URLDecoder.decode(pair.length == 2 ? pair[1] : "", StandardCharsets.UTF_8);
                } catch (IllegalArgumentException exception) {
                    throw problem(400, code, "Invalid query encoding");
                }
                if (name.isBlank()) {
                    throw problem(400, code, "Query parameter name cannot be empty");
                }
                if (output.putIfAbsent(name, value) != null) {
                    throw problem(400, code, "Duplicate query parameter: " + name);
                }
            }
        }
        Set<String> unknown = new HashSet<>(output.keySet());
        unknown.removeAll(allowed);
        if (!unknown.isEmpty()) {
            throw problem(400, code, "Unknown query parameters: " + unknown);
        }
        return output;
    }

    static int pageLimit(String value, String code) {
        if (value == null || value.isBlank()) return DEFAULT_PAGE_LIMIT;
        try {
            int parsed = Integer.parseInt(value.trim());
            if (parsed < 1 || parsed > MAXIMUM_PAGE_LIMIT) {
                throw new NumberFormatException("out of range");
            }
            return parsed;
        } catch (NumberFormatException exception) {
            throw problem(400, code, "limit must be between 1 and " + MAXIMUM_PAGE_LIMIT);
        }
    }

    static Integer optionalPositiveInteger(String value, String field, String code) {
        if (value == null || value.isBlank()) return null;
        try {
            int parsed = Integer.parseInt(value.trim());
            if (parsed < 1) throw new NumberFormatException("not positive");
            return parsed;
        } catch (NumberFormatException exception) {
            throw problem(400, code, field + " must be a positive integer");
        }
    }

    static UUID optionalUuid(String value, String field, String code) {
        if (value == null || value.isBlank()) return null;
        try {
            String trimmed = value.trim();
            UUID parsed = UUID.fromString(trimmed);
            if (!parsed.toString().equalsIgnoreCase(trimmed)) {
                throw new IllegalArgumentException("non-canonical UUID");
            }
            return parsed;
        } catch (IllegalArgumentException exception) {
            throw problem(400, code, field + " must be a canonical UUID");
        }
    }

    static String requiredQueryText(
            Map<String, String> query,
            String field,
            int maximumLength,
            String code
    ) {
        String value = query.get(field);
        if (value == null || value.isBlank()) {
            throw problem(400, code, field + " is required");
        }
        String trimmed = value.trim();
        if (trimmed.length() > maximumLength || trimmed.indexOf('\u0000') >= 0) {
            throw problem(400, code, field + " is invalid or too long");
        }
        return trimmed;
    }

    static <E extends Enum<E>> E requiredQueryEnum(
            Map<String, String> query,
            String field,
            Class<E> type,
            String code
    ) {
        String text = requiredQueryText(query, field, 64, code);
        try {
            return Enum.valueOf(type, text.toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException exception) {
            throw problem(400, code, field + " contains an unsupported value");
        }
    }

    static Integer optionalQueryPort(String value, String code) {
        if (value == null || value.isBlank()) return null;
        try {
            int parsed = Integer.parseInt(value.trim());
            if (parsed < 1 || parsed > 65_535) throw new NumberFormatException("out of range");
            return parsed;
        } catch (NumberFormatException exception) {
            throw problem(400, code, "targetPort must be between 1 and 65535 when present");
        }
    }

    static void rejectUnknownBody(Map<String, Object> values, Set<String> allowed, String code) {
        Set<String> unknown = new HashSet<>(values.keySet());
        unknown.removeAll(allowed);
        if (!unknown.isEmpty()) {
            throw problem(400, code, "Unknown request fields: " + unknown);
        }
    }

    static String requiredBodyText(
            Map<String, Object> values,
            String field,
            int maximumLength,
            String code
    ) {
        Object value = values.get(field);
        if (!(value instanceof String text) || text.isBlank()) {
            throw problem(422, code, field + " is required");
        }
        String trimmed = text.trim();
        if (trimmed.length() > maximumLength || trimmed.indexOf('\u0000') >= 0) {
            throw problem(422, code, field + " is invalid or too long");
        }
        return trimmed;
    }

    static String optionalBodyText(Map<String, Object> values, String field, String code) {
        Object value = values.get(field);
        if (value == null) return null;
        if (!(value instanceof String text)) {
            throw problem(422, code, field + " must be a string or null");
        }
        if (text.indexOf('\u0000') >= 0) {
            throw problem(422, code, field + " is invalid");
        }
        return text;
    }

    static Integer optionalBodyPort(Map<String, Object> values, String field, String code) {
        Object value = values.get(field);
        if (value == null) return null;
        if (!(value instanceof Long number) || number < 1 || number > 65_535) {
            throw problem(422, code, field + " must be an integer between 1 and 65535 or null");
        }
        return number.intValue();
    }

    static <E extends Enum<E>> E requiredBodyEnum(
            Map<String, Object> values,
            String field,
            Class<E> type,
            String code
    ) {
        String text = requiredBodyText(values, field, 64, code);
        try {
            return Enum.valueOf(type, text.toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException exception) {
            throw problem(422, code, field + " contains an unsupported value");
        }
    }

    static String actor(String actorId) {
        if (actorId == null || actorId.isBlank()) {
            throw problem(
                    500,
                    "AUTHENTICATED_ACTOR_UNAVAILABLE",
                    "Authenticated actor identity is unavailable"
            );
        }
        return actorId.trim();
    }

    static IfMatch requireIfMatch(
            String value,
            String tagPrefix,
            String preconditionCode,
            String noun
    ) {
        if (value == null || value.isBlank()) {
            throw problem(
                    428,
                    preconditionCode,
                    noun + " revisions require If-Match from a prior current-state response"
            );
        }
        String trimmed = value.trim();
        if (trimmed.indexOf(',') >= 0 || trimmed.startsWith("W/") || trimmed.equals("*")) {
            throw problem(
                    400,
                    "INVALID_IF_MATCH",
                    "If-Match must contain exactly one strong " + noun + " ETag"
            );
        }
        Pattern pattern = Pattern.compile(
                "^\\\"" + Pattern.quote(tagPrefix) + "-r([0-9]+)-([a-f0-9]{64})\\\"$");
        Matcher matcher = pattern.matcher(trimmed);
        if (!matcher.matches()) {
            throw problem(
                    400,
                    "INVALID_IF_MATCH",
                    "If-Match does not contain a valid " + noun + " ETag"
            );
        }
        try {
            return new IfMatch(trimmed, Integer.parseInt(matcher.group(1)));
        } catch (NumberFormatException exception) {
            throw problem(400, "INVALID_IF_MATCH", "If-Match revision is out of range");
        }
    }

    static String zeroEtag(String tagPrefix, String contractId, String identityPayload) {
        return '"' + tagPrefix + "-r0-" + sha256(
                contractId + "\n" + identityPayload + "revision=0\nstate=NEVER_ASSESSED\n"
        ) + '"';
    }

    static String eventEtag(String tagPrefix, int revision, String evidenceSha256) {
        return '"' + tagPrefix + "-r" + revision + '-' + evidenceSha256 + '"';
    }

    static String normalizedKey(String value, String field, int maximumLength, int status, String code) {
        if (value == null) throw problem(status, code, field + " is required");
        String trimmed = value.trim();
        if (trimmed.isEmpty() || trimmed.length() > maximumLength || trimmed.indexOf('\u0000') >= 0) {
            throw problem(status, code, field + " is blank, invalid, or too long");
        }
        return Normalizer.normalize(trimmed, Normalizer.Form.NFKC).toLowerCase(Locale.ROOT);
    }

    static ManagedAssetApi.ApiProblem problem(int status, String code, String detail) {
        return new ManagedAssetApi.ApiProblem(status, code, detail);
    }

    private static String sha256(String value) {
        try {
            return HexFormat.of().formatHex(
                    MessageDigest.getInstance("SHA-256")
                            .digest(value.getBytes(StandardCharsets.UTF_8))
            );
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is unavailable", exception);
        }
    }

    record IfMatch(String value, int revision) {
    }
}

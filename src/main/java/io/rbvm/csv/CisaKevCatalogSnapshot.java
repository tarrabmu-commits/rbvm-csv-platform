package io.rbvm.csv;

import java.net.URI;
import java.time.Instant;
import java.util.Locale;
import java.util.Objects;
import java.util.regex.Pattern;

/** Provenance token for one validated complete CISA KEV catalog snapshot. */
public record CisaKevCatalogSnapshot(
        String catalogVersion,
        String source,
        Instant observedAt,
        String sha256,
        int declaredCount,
        int parsedCount
) {
    private static final Pattern SHA256 = Pattern.compile("^[a-f0-9]{64}$");

    public CisaKevCatalogSnapshot {
        catalogVersion = requireText(catalogVersion, "KEV_Catalog_Version");
        source = requireHttps(source, "KEV_Source");
        observedAt = Objects.requireNonNull(observedAt, "KEV_Observed_At");
        sha256 = requireText(sha256, "KEV_Catalog_SHA256").toLowerCase(Locale.ROOT);
        if (!SHA256.matcher(sha256).matches()) {
            throw new IllegalArgumentException("KEV_Catalog_SHA256 must be 64 lowercase hex characters");
        }
        if (declaredCount <= 0 || parsedCount <= 0) {
            throw new IllegalArgumentException("KEV catalog counts must be positive");
        }
        if (declaredCount != parsedCount) {
            throw new IllegalArgumentException(
                    "KEV complete snapshot requires declaredCount to equal parsedCount"
            );
        }
    }

    public String snapshotKey() {
        return catalogVersion + "|" + sha256;
    }

    private static String requireHttps(String value, String field) {
        String normalized = requireText(value, field);
        URI uri;
        try {
            uri = URI.create(normalized);
        } catch (IllegalArgumentException exception) {
            throw new IllegalArgumentException(field + " must be a valid HTTPS URL", exception);
        }
        if (!"https".equalsIgnoreCase(uri.getScheme()) || uri.getHost() == null) {
            throw new IllegalArgumentException(field + " must be a valid HTTPS URL");
        }
        return normalized;
    }

    private static String requireText(String value, String field) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(field + " is required");
        }
        return value.trim();
    }
}

package io.rbvm.csv;

import java.net.URI;
import java.time.Instant;
import java.time.LocalDate;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Pattern;

/**
 * CVE-scoped evidence derived from a CISA Known Exploited Vulnerabilities catalog snapshot.
 *
 * <p>This type represents threat evidence only. It deliberately does not derive remediation
 * priority, organizational risk, SLA, EPSS, asset criticality, or business impact.</p>
 */
public final class CisaKevEvidence {
    public enum Status {
        LISTED,
        NOT_LISTED,
        UNKNOWN
    }

    /** CISA catalog value for the "Known To Be Used in Ransomware Campaigns?" field. */
    public enum RansomwareCampaignUse {
        KNOWN,
        UNKNOWN
    }

    private static final Pattern CVE_PATTERN = Pattern.compile("^CVE-[0-9]{4}-[0-9]{4,}$");

    private final String cveId;
    private final Status status;
    private final String catalogVersion;
    private final String source;
    private final Instant observedAt;
    private final LocalDate dateAdded;
    private final LocalDate dueDate;
    private final RansomwareCampaignUse ransomwareCampaignUse;

    private CisaKevEvidence(
            String cveId,
            Status status,
            String catalogVersion,
            String source,
            Instant observedAt,
            LocalDate dateAdded,
            LocalDate dueDate,
            RansomwareCampaignUse ransomwareCampaignUse
    ) {
        this.cveId = normalizeCve(cveId);
        this.status = Objects.requireNonNull(status, "status");
        this.catalogVersion = catalogVersion;
        this.source = source;
        this.observedAt = observedAt;
        this.dateAdded = dateAdded;
        this.dueDate = dueDate;
        this.ransomwareCampaignUse = ransomwareCampaignUse;
        validate();
    }

    /**
     * No usable KEV catalog evidence is currently attached to this CVE.
     *
     * <p>Collection failure or absence of an observed snapshot is not converted into
     * NOT_LISTED.</p>
     */
    public static CisaKevEvidence unknown(String cveId) {
        return new CisaKevEvidence(
                cveId,
                Status.UNKNOWN,
                null,
                null,
                null,
                null,
                null,
                null
        );
    }

    /** Positive membership evidence from a successfully observed complete CISA KEV snapshot. */
    public static CisaKevEvidence listed(
            String cveId,
            String catalogVersion,
            String source,
            Instant observedAt,
            LocalDate dateAdded,
            LocalDate dueDate,
            RansomwareCampaignUse ransomwareCampaignUse
    ) {
        return new CisaKevEvidence(
                cveId,
                Status.LISTED,
                requireText(catalogVersion, "KEV_Catalog_Version"),
                requireHttps(source, "KEV_Source"),
                Objects.requireNonNull(observedAt, "KEV_Observed_At"),
                Objects.requireNonNull(dateAdded, "KEV_Date_Added"),
                Objects.requireNonNull(dueDate, "KEV_Due_Date"),
                Objects.requireNonNull(ransomwareCampaignUse, "Known_Ransomware_Campaign_Use")
        );
    }

    /**
     * Negative membership evidence from a successfully observed complete CISA KEV snapshot.
     *
     * <p>NOT_LISTED means only that the CVE was absent from that catalog snapshot. It is not a
     * claim that exploitation has never occurred.</p>
     */
    public static CisaKevEvidence notListed(
            String cveId,
            String catalogVersion,
            String source,
            Instant observedAt
    ) {
        return new CisaKevEvidence(
                cveId,
                Status.NOT_LISTED,
                requireText(catalogVersion, "KEV_Catalog_Version"),
                requireHttps(source, "KEV_Source"),
                Objects.requireNonNull(observedAt, "KEV_Observed_At"),
                null,
                null,
                null
        );
    }

    private void validate() {
        if (status == Status.UNKNOWN) {
            if (catalogVersion != null || source != null || observedAt != null
                    || dateAdded != null || dueDate != null || ransomwareCampaignUse != null) {
                throw new IllegalArgumentException(
                        "UNKNOWN KEV evidence must not fabricate catalog provenance or listing metadata"
                );
            }
            return;
        }

        requireText(catalogVersion, "KEV_Catalog_Version");
        requireHttps(source, "KEV_Source");
        Objects.requireNonNull(observedAt, "KEV_Observed_At");

        if (status == Status.LISTED) {
            Objects.requireNonNull(dateAdded, "KEV_Date_Added");
            Objects.requireNonNull(dueDate, "KEV_Due_Date");
            Objects.requireNonNull(ransomwareCampaignUse, "Known_Ransomware_Campaign_Use");
        } else if (dateAdded != null || dueDate != null || ransomwareCampaignUse != null) {
            throw new IllegalArgumentException(
                    "NOT_LISTED KEV evidence must not carry listing-only metadata"
            );
        }
    }

    public String cveId() {
        return cveId;
    }

    public Status status() {
        return status;
    }

    public String catalogVersion() {
        return catalogVersion;
    }

    public String source() {
        return source;
    }

    public Instant observedAt() {
        return observedAt;
    }

    public LocalDate dateAdded() {
        return dateAdded;
    }

    public LocalDate dueDate() {
        return dueDate;
    }

    public RansomwareCampaignUse ransomwareCampaignUse() {
        return ransomwareCampaignUse;
    }

    public boolean hasCatalogEvidence() {
        return status != Status.UNKNOWN;
    }

    public Map<String, Object> toMap() {
        Map<String, Object> output = new LinkedHashMap<>();
        output.put("cveId", cveId);
        output.put("kevStatus", status.name());
        output.put("kevEvidenceObserved", hasCatalogEvidence());
        if (catalogVersion != null) {
            output.put("kevCatalogVersion", catalogVersion);
            output.put("kevSource", source);
            output.put("kevObservedAt", observedAt.toString());
        }
        if (status == Status.LISTED) {
            output.put("kevDateAdded", dateAdded.toString());
            output.put("kevDueDate", dueDate.toString());
            output.put("knownRansomwareCampaignUse", ransomwareCampaignUse.name());
        }
        return Map.copyOf(output);
    }

    private static String normalizeCve(String value) {
        String normalized = requireText(value, "CVE_ID").toUpperCase(Locale.ROOT);
        if (!CVE_PATTERN.matcher(normalized).matches()) {
            throw new IllegalArgumentException("CVE_ID must match CVE-YYYY-NNNN or longer");
        }
        return normalized;
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

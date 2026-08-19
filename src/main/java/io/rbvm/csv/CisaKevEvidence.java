package io.rbvm.csv;

import java.time.LocalDate;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Pattern;

/**
 * CVE-scoped evidence derived from a validated complete CISA Known Exploited Vulnerabilities
 * catalog snapshot.
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
    private final CisaKevCatalogSnapshot snapshot;
    private final LocalDate dateAdded;
    private final LocalDate dueDate;
    private final RansomwareCampaignUse ransomwareCampaignUse;

    private CisaKevEvidence(
            String cveId,
            Status status,
            CisaKevCatalogSnapshot snapshot,
            LocalDate dateAdded,
            LocalDate dueDate,
            RansomwareCampaignUse ransomwareCampaignUse
    ) {
        this.cveId = normalizeCve(cveId);
        this.status = Objects.requireNonNull(status, "status");
        this.snapshot = snapshot;
        this.dateAdded = dateAdded;
        this.dueDate = dueDate;
        this.ransomwareCampaignUse = ransomwareCampaignUse;
        validate();
    }

    /**
     * No usable KEV catalog evidence is currently attached to this CVE.
     *
     * <p>Collection failure or absence of a validated complete snapshot is not converted into
     * NOT_LISTED.</p>
     */
    public static CisaKevEvidence unknown(String cveId) {
        return new CisaKevEvidence(
                cveId,
                Status.UNKNOWN,
                null,
                null,
                null,
                null
        );
    }

    /** Positive membership evidence from a validated complete CISA KEV snapshot. */
    public static CisaKevEvidence listed(
            String cveId,
            CisaKevCatalogSnapshot snapshot,
            LocalDate dateAdded,
            LocalDate dueDate,
            RansomwareCampaignUse ransomwareCampaignUse
    ) {
        return new CisaKevEvidence(
                cveId,
                Status.LISTED,
                Objects.requireNonNull(snapshot, "snapshot"),
                Objects.requireNonNull(dateAdded, "KEV_Date_Added"),
                Objects.requireNonNull(dueDate, "KEV_Due_Date"),
                Objects.requireNonNull(ransomwareCampaignUse, "Known_Ransomware_Campaign_Use")
        );
    }

    /**
     * Negative membership evidence from a validated complete CISA KEV snapshot.
     *
     * <p>NOT_LISTED means only that the CVE was absent from that catalog snapshot. It is not a
     * claim that exploitation has never occurred.</p>
     */
    public static CisaKevEvidence notListed(
            String cveId,
            CisaKevCatalogSnapshot snapshot
    ) {
        return new CisaKevEvidence(
                cveId,
                Status.NOT_LISTED,
                Objects.requireNonNull(snapshot, "snapshot"),
                null,
                null,
                null
        );
    }

    private void validate() {
        if (status == Status.UNKNOWN) {
            if (snapshot != null || dateAdded != null || dueDate != null
                    || ransomwareCampaignUse != null) {
                throw new IllegalArgumentException(
                        "UNKNOWN KEV evidence must not fabricate snapshot or listing metadata"
                );
            }
            return;
        }

        Objects.requireNonNull(snapshot, "snapshot");
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

    public CisaKevCatalogSnapshot snapshot() {
        return snapshot;
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
        if (snapshot != null) {
            output.put("kevCatalogVersion", snapshot.catalogVersion());
            output.put("kevCatalogSha256", snapshot.sha256());
            output.put("kevCatalogCount", snapshot.declaredCount());
            output.put("kevSource", snapshot.source());
            output.put("kevObservedAt", snapshot.observedAt().toString());
        }
        if (status == Status.LISTED) {
            output.put("kevDateAdded", dateAdded.toString());
            output.put("kevDueDate", dueDate.toString());
            output.put("knownRansomwareCampaignUse", ransomwareCampaignUse.name());
        }
        return Map.copyOf(output);
    }

    private static String normalizeCve(String value) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("CVE_ID is required");
        }
        String normalized = value.trim().toUpperCase(Locale.ROOT);
        if (!CVE_PATTERN.matcher(normalized).matches()) {
            throw new IllegalArgumentException("CVE_ID must match CVE-YYYY-NNNN or longer");
        }
        return normalized;
    }
}

package io.rbvm.csv;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.function.Consumer;

/** Streaming validator/parser for CISA_KEV_CSV_V1. */
public final class CisaKevCsvAnalyzer {
    private static final int MAX_ISSUE_SAMPLES = 100;

    public CisaKevCsvAnalysisReport analyze(Path path, int previewLimit) throws IOException {
        return analyze(path, previewLimit, ignored -> { });
    }

    public CisaKevCsvAnalysisReport analyze(
            Path path,
            int previewLimit,
            Consumer<CisaKevCsvEvidence> evidenceSink
    ) throws IOException {
        Objects.requireNonNull(path, "path");
        Objects.requireNonNull(evidenceSink, "evidenceSink");
        if (previewLimit < 0 || previewLimit > 100) {
            throw new IllegalArgumentException("previewLimit must be between 0 and 100");
        }

        long logicalRows = 0;
        long acceptedRows = 0;
        long deduplicatedRows = 0;
        long quarantinedRows = 0;
        long listedRows = 0;
        long notListedRows = 0;
        List<ValidationIssue> issues = new ArrayList<>();
        List<Map<String, Object>> preview = new ArrayList<>();
        Map<String, String> acceptedEvidenceKeys = new LinkedHashMap<>();
        Set<String> cves = new HashSet<>();
        Set<String> snapshots = new HashSet<>();

        CisaKevCsvContract.HeaderMapping mapping;
        try (InputStream input = new BufferedInputStream(Files.newInputStream(path));
             BufferedReader decoded = new BufferedReader(
                     new InputStreamReader(input, strictUtf8Decoder()));
             Rfc4180CsvReader csv = new Rfc4180CsvReader(decoded)) {

            List<String> rawHeaders = csv.readRow();
            if (rawHeaders == null) {
                throw new CsvContractException("KEV CSV file is empty");
            }
            mapping = CisaKevCsvContract.mapHeaders(rawHeaders);

            List<String> row;
            while ((row = csv.readRow()) != null) {
                logicalRows++;
                long sourceRowNumber = logicalRows + 1;

                CisaKevCsvEvidence parsed;
                try {
                    parsed = CisaKevCsvContract.parseEvidence(mapping, row, sourceRowNumber);
                } catch (IllegalArgumentException exception) {
                    quarantinedRows++;
                    addIssue(issues, new ValidationIssue(
                            sourceRowNumber,
                            ValidationIssue.Level.ERROR,
                            issueCode(exception.getMessage()),
                            exception.getMessage()
                    ));
                    continue;
                }

                String priorContent = acceptedEvidenceKeys.get(parsed.evidenceKey());
                if (priorContent != null) {
                    if (priorContent.equals(parsed.normalizedContentKey())) {
                        deduplicatedRows++;
                    } else {
                        quarantinedRows++;
                        addIssue(issues, new ValidationIssue(
                                sourceRowNumber,
                                ValidationIssue.Level.ERROR,
                                "CONFLICTING_KEV_EVIDENCE_TIMESTAMP",
                                "The same CVE_ID, KEV_Source, and KEV_Observed_At must not carry conflicting KEV snapshot evidence"
                        ));
                    }
                    continue;
                }

                acceptedEvidenceKeys.put(parsed.evidenceKey(), parsed.normalizedContentKey());
                acceptedRows++;
                if (parsed.evidence().status() == CisaKevEvidence.Status.LISTED) {
                    listedRows++;
                } else {
                    notListedRows++;
                }
                cves.add(parsed.evidence().cveId());
                CisaKevCatalogSnapshot snapshot = parsed.evidence().snapshot();
                snapshots.add(snapshot.source() + "\u001F" + snapshot.catalogVersion()
                        + "\u001F" + snapshot.sha256() + "\u001F" + snapshot.observedAt());
                evidenceSink.accept(parsed);

                if (preview.size() < previewLimit) {
                    Map<String, Object> item = new LinkedHashMap<>();
                    item.put("rowNumber", sourceRowNumber);
                    item.putAll(parsed.evidence().toMap());
                    preview.add(Map.copyOf(item));
                }
            }
        } catch (CharacterCodingException exception) {
            throw new CsvContractException("KEV CSV must be valid UTF-8", exception);
        }

        return new CisaKevCsvAnalysisReport(
                CisaKevCsvContract.ID,
                CisaKevCsvContract.SEMANTICS,
                mapping.headers(),
                mapping.additionalHeaders(),
                logicalRows,
                acceptedRows,
                deduplicatedRows,
                quarantinedRows,
                listedRows,
                notListedRows,
                cves.size(),
                snapshots.size(),
                issues,
                preview
        );
    }

    private static String issueCode(String message) {
        if (message == null) {
            return "INVALID_CISA_KEV_EVIDENCE";
        }
        if (message.startsWith("Expected ")) return "COLUMN_COUNT_MISMATCH";
        if (message.startsWith("Missing values:")) return "MISSING_REQUIRED_VALUE";
        if (message.startsWith("CVE_ID")) return "INVALID_CVE_ID";
        if (message.startsWith("KEV_Status")) return "INVALID_KEV_STATUS";
        if (message.startsWith("KEV_Catalog_Version")) return "INVALID_KEV_CATALOG_VERSION";
        if (message.startsWith("KEV_Catalog_SHA256")) return "INVALID_KEV_CATALOG_SHA256";
        if (message.startsWith("KEV_Catalog_Count") || message.startsWith("KEV catalog counts")) {
            return "INVALID_KEV_CATALOG_COUNT";
        }
        if (message.startsWith("KEV_Source")) return "INVALID_KEV_SOURCE";
        if (message.startsWith("KEV_Observed_At")) return "INVALID_KEV_OBSERVED_AT";
        if (message.startsWith("KEV_Date_Added")) return "INVALID_KEV_DATE_ADDED";
        if (message.startsWith("KEV_Due_Date")) return "INVALID_KEV_DUE_DATE";
        if (message.startsWith("Known_Ransomware_Campaign_Use")) {
            return "INVALID_KEV_RANSOMWARE_USE";
        }
        return "INVALID_CISA_KEV_EVIDENCE";
    }

    private static void addIssue(List<ValidationIssue> issues, ValidationIssue issue) {
        if (issues.size() < MAX_ISSUE_SAMPLES) {
            issues.add(issue);
        }
    }

    private static java.nio.charset.CharsetDecoder strictUtf8Decoder() {
        return StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT);
    }
}

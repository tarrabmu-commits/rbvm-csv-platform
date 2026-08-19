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

/** Streaming validator/parser for CVSS_V31_CSV_V1. */
public final class CvssV31CsvAnalyzer {
    private static final int MAX_ISSUE_SAMPLES = 100;

    public CvssV31CsvAnalysisReport analyze(Path path, int previewLimit) throws IOException {
        return analyze(path, previewLimit, ignored -> { });
    }

    public CvssV31CsvAnalysisReport analyze(
            Path path,
            int previewLimit,
            Consumer<CvssV31CsvEvidence> evidenceSink
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
        List<ValidationIssue> issues = new ArrayList<>();
        List<Map<String, Object>> preview = new ArrayList<>();
        Map<String, String> acceptedEvidenceKeys = new LinkedHashMap<>();
        Set<String> cves = new HashSet<>();
        Set<String> sources = new HashSet<>();

        CvssV31CsvContract.HeaderMapping mapping;
        try (InputStream input = new BufferedInputStream(Files.newInputStream(path));
             BufferedReader decoded = new BufferedReader(
                     new InputStreamReader(input, strictUtf8Decoder()));
             Rfc4180CsvReader csv = new Rfc4180CsvReader(decoded)) {

            List<String> rawHeaders = csv.readRow();
            if (rawHeaders == null) {
                throw new CsvContractException("CVSS CSV file is empty");
            }
            mapping = CvssV31CsvContract.mapHeaders(rawHeaders);

            List<String> row;
            while ((row = csv.readRow()) != null) {
                logicalRows++;
                long sourceRowNumber = logicalRows + 1;

                CvssV31CsvEvidence parsed;
                try {
                    parsed = CvssV31CsvContract.parseEvidence(mapping, row, sourceRowNumber);
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
                                "CONFLICTING_CVSS_EVIDENCE_TIMESTAMP",
                                "The same CVE_ID, CVSS_Source, and CVSS_Observed_At must not carry conflicting CVSS v3.1 Base evidence"
                        ));
                    }
                    continue;
                }

                acceptedEvidenceKeys.put(parsed.evidenceKey(), parsed.normalizedContentKey());
                acceptedRows++;
                cves.add(parsed.evidence().cveId());
                sources.add(parsed.evidence().source());
                evidenceSink.accept(parsed);

                if (preview.size() < previewLimit) {
                    Map<String, Object> item = new LinkedHashMap<>();
                    item.put("rowNumber", sourceRowNumber);
                    item.putAll(parsed.evidence().toMap());
                    preview.add(Map.copyOf(item));
                }
            }
        } catch (CharacterCodingException exception) {
            throw new CsvContractException("CVSS CSV must be valid UTF-8", exception);
        }

        return new CvssV31CsvAnalysisReport(
                CvssV31CsvContract.ID,
                CvssV31CsvContract.SEMANTICS,
                mapping.headers(),
                mapping.additionalHeaders(),
                logicalRows,
                acceptedRows,
                deduplicatedRows,
                quarantinedRows,
                cves.size(),
                sources.size(),
                issues,
                preview
        );
    }

    private static String issueCode(String message) {
        if (message == null) {
            return "INVALID_CVSS_V31_EVIDENCE";
        }
        if (message.startsWith("Expected ")) {
            return "COLUMN_COUNT_MISMATCH";
        }
        if (message.startsWith("Missing values:")) {
            return "MISSING_REQUIRED_VALUE";
        }
        if (message.startsWith("CVE_ID")) {
            return "INVALID_CVE_ID";
        }
        if (message.startsWith("CVSS_Version")) {
            return "INVALID_CVSS_VERSION";
        }
        if (message.startsWith("CVSS_Base_Score")) {
            return "INVALID_CVSS_BASE_SCORE";
        }
        if (message.startsWith("CVSS_Vector")) {
            return "INVALID_CVSS_VECTOR";
        }
        if (message.startsWith("CVSS_Source")) {
            return "INVALID_CVSS_SOURCE";
        }
        if (message.startsWith("CVSS_Observed_At")) {
            return "INVALID_CVSS_OBSERVED_AT";
        }
        return "INVALID_CVSS_V31_EVIDENCE";
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

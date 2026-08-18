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
import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Consumer;

/**
 * Streaming validator/parser for APPLICABILITY_CSV_V1.
 *
 * <p>The analyzer validates only the assessment contract. Whether Finding_ID exists in the selected
 * tenant is intentionally a persistence-stage concern.</p>
 */
public final class ApplicabilityCsvAnalyzer {
    private static final int MAX_ISSUE_SAMPLES = 100;

    public ApplicabilityCsvAnalysisReport analyze(Path path, int previewLimit) throws IOException {
        return analyze(path, previewLimit, ignored -> { });
    }

    public ApplicabilityCsvAnalysisReport analyze(
            Path path,
            int previewLimit,
            Consumer<ApplicabilityCsvAssessment> assessmentSink
    ) throws IOException {
        Objects.requireNonNull(path, "path");
        Objects.requireNonNull(assessmentSink, "assessmentSink");
        if (previewLimit < 0 || previewLimit > 100) {
            throw new IllegalArgumentException("previewLimit must be between 0 and 100");
        }

        long logicalRows = 0;
        long acceptedRows = 0;
        long deduplicatedRows = 0;
        long quarantinedRows = 0;
        List<ValidationIssue> issues = new ArrayList<>();
        List<Map<String, Object>> preview = new ArrayList<>();
        Map<String, String> acceptedAssessmentKeys = new LinkedHashMap<>();
        Map<ApplicabilityEvidence.Status, Long> statusCounts = new EnumMap<>(ApplicabilityEvidence.Status.class);
        for (ApplicabilityEvidence.Status status : ApplicabilityEvidence.Status.values()) {
            statusCounts.put(status, 0L);
        }

        ApplicabilityCsvContract.HeaderMapping mapping;
        try (InputStream input = new BufferedInputStream(Files.newInputStream(path));
             BufferedReader decoded = new BufferedReader(new InputStreamReader(input, strictUtf8Decoder()));
             Rfc4180CsvReader csv = new Rfc4180CsvReader(decoded)) {

            List<String> rawHeaders = csv.readRow();
            if (rawHeaders == null) {
                throw new CsvContractException("Applicability CSV file is empty");
            }
            mapping = ApplicabilityCsvContract.mapHeaders(rawHeaders);

            List<String> row;
            while ((row = csv.readRow()) != null) {
                logicalRows++;
                long sourceRowNumber = logicalRows + 1;

                ApplicabilityCsvAssessment assessment;
                try {
                    assessment = ApplicabilityCsvContract.parseAssessment(mapping, row, sourceRowNumber);
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

                String priorContent = acceptedAssessmentKeys.get(assessment.assessmentKey());
                if (priorContent != null) {
                    if (priorContent.equals(assessment.normalizedContentKey())) {
                        deduplicatedRows++;
                    } else {
                        quarantinedRows++;
                        addIssue(issues, new ValidationIssue(
                                sourceRowNumber,
                                ValidationIssue.Level.ERROR,
                                "CONFLICTING_ASSESSMENT_TIMESTAMP",
                                "The same Finding_ID and Evaluated_At must not carry conflicting applicability evidence"
                        ));
                    }
                    continue;
                }

                acceptedAssessmentKeys.put(assessment.assessmentKey(), assessment.normalizedContentKey());
                acceptedRows++;
                statusCounts.compute(assessment.status(), (ignored, count) -> count + 1);
                assessmentSink.accept(assessment);

                if (preview.size() < previewLimit) {
                    Map<String, Object> item = new LinkedHashMap<>();
                    item.put("rowNumber", sourceRowNumber);
                    item.put("findingId", assessment.findingId().toString());
                    item.put("applicabilityStatus", assessment.status().name());
                    item.put("applicabilityReason", assessment.reason());
                    item.put("evidenceSource", assessment.evidenceSource());
                    item.put("evaluatedAt", assessment.evaluatedAt().toString());
                    preview.add(Map.copyOf(item));
                }
            }
        } catch (CharacterCodingException exception) {
            throw new CsvContractException("Applicability CSV must be valid UTF-8", exception);
        }

        Map<String, Long> outputCounts = new LinkedHashMap<>();
        for (ApplicabilityEvidence.Status status : ApplicabilityEvidence.Status.values()) {
            outputCounts.put(status.name(), statusCounts.get(status));
        }

        return new ApplicabilityCsvAnalysisReport(
                ApplicabilityCsvContract.ID,
                ApplicabilityCsvContract.SEMANTICS,
                mapping.headers(),
                mapping.additionalHeaders(),
                logicalRows,
                acceptedRows,
                deduplicatedRows,
                quarantinedRows,
                outputCounts,
                issues,
                preview
        );
    }

    private static String issueCode(String message) {
        if (message == null) {
            return "INVALID_APPLICABILITY_ASSESSMENT";
        }
        if (message.startsWith("Expected ")) {
            return "COLUMN_COUNT_MISMATCH";
        }
        if (message.startsWith("Missing values:")) {
            return "MISSING_REQUIRED_VALUE";
        }
        if (message.startsWith("Finding_ID")) {
            return "INVALID_FINDING_ID";
        }
        if (message.startsWith("Applicability_Status")) {
            return "INVALID_APPLICABILITY_STATUS";
        }
        if (message.startsWith("Evaluated_At")) {
            return "INVALID_EVALUATED_AT";
        }
        return "INVALID_APPLICABILITY_ASSESSMENT";
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

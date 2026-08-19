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

/** Streaming validator/parser for ASSET_CONTEXT_CSV_V1. */
public final class AssetContextCsvAnalyzer {
    private static final int MAX_ISSUE_SAMPLES = 100;

    public AssetContextCsvAnalysisReport analyze(Path path, int previewLimit) throws IOException {
        return analyze(path, previewLimit, ignored -> { });
    }

    public AssetContextCsvAnalysisReport analyze(
            Path path,
            int previewLimit,
            Consumer<AssetContextCsvEvidence> evidenceSink
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
        Map<String, String> acceptedObservationKeys = new LinkedHashMap<>();
        Map<AssetContextCsvEvidence.Environment, Long> environments =
                new EnumMap<>(AssetContextCsvEvidence.Environment.class);
        Map<AssetContextCsvEvidence.BusinessCriticality, Long> criticalities =
                new EnumMap<>(AssetContextCsvEvidence.BusinessCriticality.class);
        for (AssetContextCsvEvidence.Environment value : AssetContextCsvEvidence.Environment.values()) {
            environments.put(value, 0L);
        }
        for (AssetContextCsvEvidence.BusinessCriticality value
                : AssetContextCsvEvidence.BusinessCriticality.values()) {
            criticalities.put(value, 0L);
        }

        AssetContextCsvContract.HeaderMapping mapping;
        try (InputStream input = new BufferedInputStream(Files.newInputStream(path));
             BufferedReader decoded = new BufferedReader(new InputStreamReader(input, strictUtf8Decoder()));
             Rfc4180CsvReader csv = new Rfc4180CsvReader(decoded)) {

            List<String> rawHeaders = csv.readRow();
            if (rawHeaders == null) {
                throw new CsvContractException("Asset context CSV file is empty");
            }
            mapping = AssetContextCsvContract.mapHeaders(rawHeaders);

            List<String> row;
            while ((row = csv.readRow()) != null) {
                logicalRows++;
                long sourceRowNumber = logicalRows + 1;
                AssetContextCsvEvidence evidence;
                try {
                    evidence = AssetContextCsvContract.parseEvidence(mapping, row, sourceRowNumber);
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

                String priorContent = acceptedObservationKeys.get(evidence.observationKey());
                if (priorContent != null) {
                    if (priorContent.equals(evidence.normalizedContentKey())) {
                        deduplicatedRows++;
                    } else {
                        quarantinedRows++;
                        addIssue(issues, new ValidationIssue(
                                sourceRowNumber,
                                ValidationIssue.Level.ERROR,
                                "CONFLICTING_ASSET_CONTEXT_OBSERVATION",
                                "The same source profile, asset, context source, and observation time must not carry conflicting context evidence"
                        ));
                    }
                    continue;
                }

                acceptedObservationKeys.put(evidence.observationKey(), evidence.normalizedContentKey());
                acceptedRows++;
                environments.compute(evidence.environment(), (ignored, count) -> count + 1);
                criticalities.compute(evidence.businessCriticality(), (ignored, count) -> count + 1);
                evidenceSink.accept(evidence);

                if (preview.size() < previewLimit) {
                    Map<String, Object> item = new LinkedHashMap<>();
                    item.put("rowNumber", sourceRowNumber);
                    item.put("sourceProfileKey", evidence.sourceProfileKey());
                    item.put("assetName", evidence.assetObservedName());
                    item.put("normalizedAssetName", evidence.normalizedAssetName());
                    item.put("environment", evidence.environment().name());
                    item.put("businessService", evidence.businessService());
                    item.put("businessOwner", evidence.businessOwner());
                    item.put("businessCriticality", evidence.businessCriticality().name());
                    item.put("contextSource", evidence.contextSource());
                    item.put("contextObservedAt", evidence.contextObservedAt().toString());
                    item.put("contextSourceSha256", evidence.contextSourceSha256());
                    preview.add(Map.copyOf(item));
                }
            }
        } catch (CharacterCodingException exception) {
            throw new CsvContractException("Asset context CSV must be valid UTF-8", exception);
        }

        Map<String, Long> environmentOutput = new LinkedHashMap<>();
        for (AssetContextCsvEvidence.Environment value : AssetContextCsvEvidence.Environment.values()) {
            environmentOutput.put(value.name(), environments.get(value));
        }
        Map<String, Long> criticalityOutput = new LinkedHashMap<>();
        for (AssetContextCsvEvidence.BusinessCriticality value
                : AssetContextCsvEvidence.BusinessCriticality.values()) {
            criticalityOutput.put(value.name(), criticalities.get(value));
        }

        return new AssetContextCsvAnalysisReport(
                AssetContextCsvContract.ID,
                AssetContextCsvContract.SEMANTICS,
                mapping.headers(),
                mapping.additionalHeaders(),
                logicalRows,
                acceptedRows,
                deduplicatedRows,
                quarantinedRows,
                environmentOutput,
                criticalityOutput,
                issues,
                preview
        );
    }

    private static String issueCode(String message) {
        if (message == null) {
            return "INVALID_ASSET_CONTEXT_EVIDENCE";
        }
        if (message.startsWith("Expected ")) {
            return "COLUMN_COUNT_MISMATCH";
        }
        if (message.startsWith("Missing values:")) {
            return "MISSING_REQUIRED_VALUE";
        }
        if (message.startsWith("Environment")) {
            return "INVALID_ENVIRONMENT";
        }
        if (message.startsWith("Business_Criticality")) {
            return "INVALID_BUSINESS_CRITICALITY";
        }
        if (message.startsWith("Context_Observed_At")) {
            return "INVALID_CONTEXT_OBSERVED_AT";
        }
        if (message.startsWith("Context_Source_SHA256")) {
            return "INVALID_CONTEXT_SOURCE_SHA256";
        }
        return "INVALID_ASSET_CONTEXT_EVIDENCE";
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

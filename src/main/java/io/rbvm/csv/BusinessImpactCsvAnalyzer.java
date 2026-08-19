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

/** Streaming validator/parser for BUSINESS_IMPACT_CSV_V1. */
public final class BusinessImpactCsvAnalyzer {
    private static final int MAX_ISSUE_SAMPLES = 100;

    public BusinessImpactCsvAnalysisReport analyze(Path path, int previewLimit) throws IOException {
        return analyze(path, previewLimit, ignored -> { });
    }

    public BusinessImpactCsvAnalysisReport analyze(
            Path path,
            int previewLimit,
            Consumer<BusinessImpactCsvEvidence> evidenceSink
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
        Map<BusinessImpactCsvEvidence.ImpactDimension, Long> dimensions =
                new EnumMap<>(BusinessImpactCsvEvidence.ImpactDimension.class);
        Map<BusinessImpactCsvEvidence.ImpactLevel, Long> levels =
                new EnumMap<>(BusinessImpactCsvEvidence.ImpactLevel.class);
        Map<BusinessImpactCsvEvidence.ImpactMethod, Long> methods =
                new EnumMap<>(BusinessImpactCsvEvidence.ImpactMethod.class);
        initialize(dimensions, BusinessImpactCsvEvidence.ImpactDimension.values());
        initialize(levels, BusinessImpactCsvEvidence.ImpactLevel.values());
        initialize(methods, BusinessImpactCsvEvidence.ImpactMethod.values());

        BusinessImpactCsvContract.HeaderMapping mapping;
        try (InputStream input = new BufferedInputStream(Files.newInputStream(path));
             BufferedReader decoded = new BufferedReader(new InputStreamReader(input, strictUtf8Decoder()));
             Rfc4180CsvReader csv = new Rfc4180CsvReader(decoded)) {
            List<String> rawHeaders = csv.readRow();
            if (rawHeaders == null) {
                throw new CsvContractException("Business Impact CSV file is empty");
            }
            mapping = BusinessImpactCsvContract.mapHeaders(rawHeaders);
            List<String> row;
            while ((row = csv.readRow()) != null) {
                logicalRows++;
                long sourceRowNumber = logicalRows + 1;
                BusinessImpactCsvEvidence evidence;
                try {
                    evidence = BusinessImpactCsvContract.parseEvidence(mapping, row, sourceRowNumber);
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
                                "CONFLICTING_BUSINESS_IMPACT_OBSERVATION",
                                "The same asset, business service, impact dimension, source, and observation time must not carry conflicting impact evidence"
                        ));
                    }
                    continue;
                }

                acceptedObservationKeys.put(evidence.observationKey(), evidence.normalizedContentKey());
                acceptedRows++;
                dimensions.compute(evidence.impactDimension(), (ignored, count) -> count + 1);
                levels.compute(evidence.impactLevel(), (ignored, count) -> count + 1);
                methods.compute(evidence.impactMethod(), (ignored, count) -> count + 1);
                evidenceSink.accept(evidence);

                if (preview.size() < previewLimit) {
                    Map<String, Object> item = new LinkedHashMap<>();
                    item.put("rowNumber", sourceRowNumber);
                    item.put("sourceProfileKey", evidence.sourceProfileKey());
                    item.put("assetIdentityBasis", evidence.assetIdentityBasis().name());
                    item.put("assetName", evidence.assetObservedName());
                    item.put("assetSourceId", evidence.assetSourceId());
                    item.put("normalizedAssetIdentityKey", evidence.normalizedAssetIdentityKey());
                    item.put("businessService", evidence.businessService());
                    item.put("impactDimension", evidence.impactDimension().name());
                    item.put("impactLevel", evidence.impactLevel().name());
                    item.put("impactMethod", evidence.impactMethod().name());
                    item.put("impactStatement", evidence.impactStatement());
                    item.put("impactSource", evidence.impactSource());
                    item.put("impactObservedAt", evidence.impactObservedAt().toString());
                    item.put("impactSourceSha256", evidence.impactSourceSha256());
                    preview.add(Map.copyOf(item));
                }
            }
        } catch (CharacterCodingException exception) {
            throw new CsvContractException("Business Impact CSV must be valid UTF-8", exception);
        }

        return new BusinessImpactCsvAnalysisReport(
                BusinessImpactCsvContract.ID,
                BusinessImpactCsvContract.SEMANTICS,
                mapping.headers(),
                mapping.additionalHeaders(),
                logicalRows,
                acceptedRows,
                deduplicatedRows,
                quarantinedRows,
                names(dimensions),
                names(levels),
                names(methods),
                issues,
                preview
        );
    }

    private static String issueCode(String message) {
        if (message == null) return "INVALID_BUSINESS_IMPACT_EVIDENCE";
        if (message.startsWith("Expected ")) return "COLUMN_COUNT_MISMATCH";
        if (message.startsWith("Missing values:")) return "MISSING_REQUIRED_VALUE";
        if (message.startsWith("Asset_Identity_Basis") || message.startsWith("Asset_Source_ID")) {
            return "INVALID_ASSET_IDENTITY";
        }
        if (message.startsWith("Impact_Dimension")) return "INVALID_IMPACT_DIMENSION";
        if (message.startsWith("Impact_Level")) return "INVALID_IMPACT_LEVEL";
        if (message.startsWith("Impact_Method")) return "INVALID_IMPACT_METHOD";
        if (message.startsWith("Impact_Observed_At")) return "INVALID_IMPACT_OBSERVED_AT";
        if (message.startsWith("Impact_Source_SHA256")) return "INVALID_IMPACT_SOURCE_SHA256";
        if (message.contains("too long")) return "VALUE_TOO_LONG";
        return "INVALID_BUSINESS_IMPACT_EVIDENCE";
    }

    private static <E extends Enum<E>> void initialize(Map<E, Long> output, E[] values) {
        for (E value : values) output.put(value, 0L);
    }

    private static <E extends Enum<E>> Map<String, Long> names(Map<E, Long> input) {
        Map<String, Long> output = new LinkedHashMap<>();
        for (Map.Entry<E, Long> entry : input.entrySet()) {
            output.put(entry.getKey().name(), entry.getValue());
        }
        return output;
    }

    private static void addIssue(List<ValidationIssue> issues, ValidationIssue issue) {
        if (issues.size() < MAX_ISSUE_SAMPLES) issues.add(issue);
    }

    private static java.nio.charset.CharsetDecoder strictUtf8Decoder() {
        return StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT);
    }
}

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

/** Streaming validator/parser for NETWORK_REACHABILITY_CSV_V1. */
public final class NetworkReachabilityCsvAnalyzer {
    private static final int MAX_ISSUE_SAMPLES = 100;

    public NetworkReachabilityCsvAnalysisReport analyze(Path path, int previewLimit) throws IOException {
        return analyze(path, previewLimit, ignored -> { });
    }

    public NetworkReachabilityCsvAnalysisReport analyze(
            Path path,
            int previewLimit,
            Consumer<NetworkReachabilityCsvEvidence> evidenceSink
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
        Map<NetworkReachabilityCsvEvidence.OriginScope, Long> origins =
                new EnumMap<>(NetworkReachabilityCsvEvidence.OriginScope.class);
        Map<NetworkReachabilityCsvEvidence.TransportProtocol, Long> protocols =
                new EnumMap<>(NetworkReachabilityCsvEvidence.TransportProtocol.class);
        Map<NetworkReachabilityCsvEvidence.ReachabilityStatus, Long> statuses =
                new EnumMap<>(NetworkReachabilityCsvEvidence.ReachabilityStatus.class);
        Map<NetworkReachabilityCsvEvidence.ReachabilityMethod, Long> methods =
                new EnumMap<>(NetworkReachabilityCsvEvidence.ReachabilityMethod.class);
        initialize(origins, NetworkReachabilityCsvEvidence.OriginScope.values());
        initialize(protocols, NetworkReachabilityCsvEvidence.TransportProtocol.values());
        initialize(statuses, NetworkReachabilityCsvEvidence.ReachabilityStatus.values());
        initialize(methods, NetworkReachabilityCsvEvidence.ReachabilityMethod.values());

        NetworkReachabilityCsvContract.HeaderMapping mapping;
        try (InputStream input = new BufferedInputStream(Files.newInputStream(path));
             BufferedReader decoded = new BufferedReader(new InputStreamReader(input, strictUtf8Decoder()));
             Rfc4180CsvReader csv = new Rfc4180CsvReader(decoded)) {

            List<String> rawHeaders = csv.readRow();
            if (rawHeaders == null) {
                throw new CsvContractException("Network reachability CSV file is empty");
            }
            mapping = NetworkReachabilityCsvContract.mapHeaders(rawHeaders);

            List<String> row;
            while ((row = csv.readRow()) != null) {
                logicalRows++;
                long sourceRowNumber = logicalRows + 1;
                NetworkReachabilityCsvEvidence evidence;
                try {
                    evidence = NetworkReachabilityCsvContract.parseEvidence(
                            mapping, row, sourceRowNumber);
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
                                "CONFLICTING_NETWORK_REACHABILITY_OBSERVATION",
                                "The same asset, origin scope/label, transport endpoint, evidence source, and observation time must not carry conflicting reachability evidence"
                        ));
                    }
                    continue;
                }

                acceptedObservationKeys.put(evidence.observationKey(), evidence.normalizedContentKey());
                acceptedRows++;
                origins.compute(evidence.originScope(), (ignored, count) -> count + 1);
                protocols.compute(evidence.transportProtocol(), (ignored, count) -> count + 1);
                statuses.compute(evidence.reachabilityStatus(), (ignored, count) -> count + 1);
                methods.compute(evidence.reachabilityMethod(), (ignored, count) -> count + 1);
                evidenceSink.accept(evidence);

                if (preview.size() < previewLimit) {
                    Map<String, Object> item = new LinkedHashMap<>();
                    item.put("rowNumber", sourceRowNumber);
                    item.put("sourceProfileKey", evidence.sourceProfileKey());
                    item.put("assetIdentityBasis", evidence.assetIdentityBasis().name());
                    item.put("assetName", evidence.assetObservedName());
                    item.put("assetSourceId", evidence.assetSourceId());
                    item.put("normalizedAssetIdentityKey", evidence.normalizedAssetIdentityKey());
                    item.put("originScope", evidence.originScope().name());
                    item.put("originLabel", evidence.originLabel());
                    item.put("transportProtocol", evidence.transportProtocol().name());
                    item.put("targetPort", evidence.targetPort() == null ? "" : evidence.targetPort());
                    item.put("targetService", evidence.targetService());
                    item.put("reachabilityStatus", evidence.reachabilityStatus().name());
                    item.put("reachabilityMethod", evidence.reachabilityMethod().name());
                    item.put("evidenceSource", evidence.evidenceSource());
                    item.put("evidenceObservedAt", evidence.evidenceObservedAt().toString());
                    item.put("evidenceSourceSha256", evidence.evidenceSourceSha256());
                    preview.add(Map.copyOf(item));
                }
            }
        } catch (CharacterCodingException exception) {
            throw new CsvContractException("Network reachability CSV must be valid UTF-8", exception);
        }

        return new NetworkReachabilityCsvAnalysisReport(
                NetworkReachabilityCsvContract.ID,
                NetworkReachabilityCsvContract.SEMANTICS,
                mapping.headers(),
                mapping.additionalHeaders(),
                logicalRows,
                acceptedRows,
                deduplicatedRows,
                quarantinedRows,
                names(origins),
                names(protocols),
                names(statuses),
                names(methods),
                issues,
                preview
        );
    }

    private static String issueCode(String message) {
        if (message == null) {
            return "INVALID_NETWORK_REACHABILITY_EVIDENCE";
        }
        if (message.startsWith("Expected ")) return "COLUMN_COUNT_MISMATCH";
        if (message.startsWith("Missing values:")) return "MISSING_REQUIRED_VALUE";
        if (message.startsWith("Asset_Identity_Basis")
                || message.startsWith("Asset_Source_ID")) return "INVALID_ASSET_IDENTITY";
        if (message.startsWith("Origin_Scope")) return "INVALID_ORIGIN_SCOPE";
        if (message.startsWith("Transport_Protocol")) return "INVALID_TRANSPORT_PROTOCOL";
        if (message.startsWith("Target_Port")) return "INVALID_TARGET_PORT";
        if (message.startsWith("Reachability_Status")) return "INVALID_REACHABILITY_STATUS";
        if (message.startsWith("Reachability_Method")) return "INVALID_REACHABILITY_METHOD";
        if (message.startsWith("Evidence_Observed_At")) return "INVALID_EVIDENCE_OBSERVED_AT";
        if (message.startsWith("Evidence_Source_SHA256")) return "INVALID_EVIDENCE_SOURCE_SHA256";
        return "INVALID_NETWORK_REACHABILITY_EVIDENCE";
    }

    private static <E extends Enum<E>> void initialize(Map<E, Long> output, E[] values) {
        for (E value : values) {
            output.put(value, 0L);
        }
    }

    private static <E extends Enum<E>> Map<String, Long> names(Map<E, Long> input) {
        Map<String, Long> output = new LinkedHashMap<>();
        for (Map.Entry<E, Long> entry : input.entrySet()) {
            output.put(entry.getKey().name(), entry.getValue());
        }
        return output;
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

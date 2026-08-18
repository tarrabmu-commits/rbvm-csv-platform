package io.rbvm.csv;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

public final class CanonicalFindingStateSelfTest {
    private CanonicalFindingStateSelfTest() {
    }

    public static void main(String[] args) throws Exception {
        aggregatesRepeatedV1ObservationsWithoutInventingLifecycle();
        appliesExplicitV2ResolutionAndReopenEvidence();
        activeWinsSameTimestampLifecycleConflict();
        rejectsObservationFromDifferentFinding();
        System.out.println("CanonicalFindingStateSelfTest: PASS");
    }

    private static void aggregatesRepeatedV1ObservationsWithoutInventingLifecycle() throws Exception {
        String csv = v1Headers()
                + "hodor-aio,CVE-2026-25087,High,description,pyarrow,https://example.test/1,Ubuntu,2026-06-11T17:53:10.302Z\r\n"
                + "hodor-aio,CVE-2026-25087,High,description,pyarrow,https://example.test/2,Ubuntu,2026-06-11T17:53:10.342Z\r\n";
        List<WazuhObservation> observations = analyze(csv, CsvContractV1.ID);
        CanonicalFindingState state = CanonicalFindingState.from(observations.get(0))
                .observe(observations.get(1));

        assert state.observationCount() == 2;
        assert state.firstObservedAt().equals(Instant.parse("2026-06-11T17:53:10.302Z"));
        assert state.lastObservedAt().equals(Instant.parse("2026-06-11T17:53:10.342Z"));
        assert state.stateEvidenceAt().equals(state.lastObservedAt());
        assert state.sourceState() == CanonicalFindingState.SourceState.OBSERVED_ONLY;
        assert !state.explicitLifecycle();

        CanonicalFindingState replayed = state.observe(observations.get(1));
        assert replayed == state;
        assert replayed.observationCount() == 2;
    }

    private static void appliesExplicitV2ResolutionAndReopenEvidence() throws Exception {
        String csv = v2Headers()
                + "agent,001,CVE-2026-4321,High,description,openssl,3.0.2,amd64,https://example.test/1,Ubuntu,ACTIVE,2026-08-01T10:00:00Z,\r\n"
                + "agent,001,CVE-2026-4321,High,description,openssl,3.0.2,amd64,https://example.test/2,Ubuntu,RESOLVED,2026-08-01T10:00:00Z,2026-08-02T10:00:00Z\r\n"
                + "agent,001,CVE-2026-4321,High,description,openssl,3.0.2,amd64,https://example.test/3,Ubuntu,ACTIVE,2026-08-03T10:00:00Z,\r\n";
        List<WazuhObservation> observations = analyze(csv, CsvContractV2.ID);

        CanonicalFindingState resolved = CanonicalFindingState.from(observations.get(0))
                .observe(observations.get(1));
        assert resolved.sourceState() == CanonicalFindingState.SourceState.RESOLVED;
        assert resolved.explicitLifecycle();
        assert resolved.stateEvidenceAt().equals(Instant.parse("2026-08-02T10:00:00Z"));

        CanonicalFindingState reopened = resolved.observe(observations.get(2));
        assert reopened.sourceState() == CanonicalFindingState.SourceState.ACTIVE;
        assert reopened.observationCount() == 3;
        assert reopened.firstObservedAt().equals(Instant.parse("2026-08-01T10:00:00Z"));
        assert reopened.lastObservedAt().equals(Instant.parse("2026-08-03T10:00:00Z"));
        assert reopened.stateEvidenceAt().equals(Instant.parse("2026-08-03T10:00:00Z"));
    }

    private static void activeWinsSameTimestampLifecycleConflict() throws Exception {
        String csv = v2Headers()
                + "agent,001,CVE-2026-5000,High,description,pkg,1.0,amd64,https://example.test/1,Ubuntu,RESOLVED,2026-08-01T10:00:00Z,2026-08-02T10:00:00Z\r\n"
                + "agent,001,CVE-2026-5000,High,description,pkg,1.0,amd64,https://example.test/2,Ubuntu,ACTIVE,2026-08-02T10:00:00Z,\r\n";
        List<WazuhObservation> observations = analyze(csv, CsvContractV2.ID);
        CanonicalFindingState state = CanonicalFindingState.from(observations.get(0))
                .observe(observations.get(1));

        assert state.stateEvidenceAt().equals(Instant.parse("2026-08-02T10:00:00Z"));
        assert state.sourceState() == CanonicalFindingState.SourceState.ACTIVE;
    }

    private static void rejectsObservationFromDifferentFinding() throws Exception {
        String csv = v2Headers()
                + "agent,001,CVE-2026-6000,High,description,pkg,1.0,amd64,https://example.test/1,Ubuntu,ACTIVE,2026-08-01T10:00:00Z,\r\n"
                + "agent,001,CVE-2026-6000,High,description,pkg,2.0,amd64,https://example.test/2,Ubuntu,ACTIVE,2026-08-02T10:00:00Z,\r\n";
        List<WazuhObservation> observations = analyze(csv, CsvContractV2.ID);
        CanonicalFindingState state = CanonicalFindingState.from(observations.get(0));
        boolean rejected = false;
        try {
            state.observe(observations.get(1));
        } catch (IllegalArgumentException expected) {
            rejected = expected.getMessage().contains("different canonical finding identity");
        }
        assert rejected;
    }

    private static List<WazuhObservation> analyze(String csv, String contractId) throws Exception {
        Path file = Files.createTempFile("canonical-finding-state-", ".csv");
        try {
            Files.writeString(file, csv, StandardCharsets.UTF_8);
            List<WazuhObservation> observations = new ArrayList<>();
            new WazuhCsvAnalyzer("canonical-state-test", contractId)
                    .analyze(file, 0, observations::add);
            return observations;
        } finally {
            Files.deleteIfExists(file);
        }
    }

    private static String v1Headers() {
        return "Agent,CVE_ID,Severity,CVE_Description,Affected_Product,References,OS_name,Detected_At\r\n";
    }

    private static String v2Headers() {
        return "Agent,Agent_ID,CVE_ID,Severity,CVE_Description,Affected_Product,"
                + "Package_Version,Package_Architecture,References,OS_name,Finding_Status,"
                + "Detected_At,Resolved_At\r\n";
    }
}

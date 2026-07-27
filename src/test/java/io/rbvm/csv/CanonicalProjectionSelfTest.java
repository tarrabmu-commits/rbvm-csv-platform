package io.rbvm.csv;

import io.rbvm.domain.CaseActionCommand;
import io.rbvm.domain.CaseActionType;
import io.rbvm.domain.CaseAuditEvent;
import io.rbvm.domain.CaseQuery;
import io.rbvm.domain.InMemoryDomainCatalog;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Stream;

public final class CanonicalProjectionSelfTest {
    private static final Clock CLOCK = Clock.fixed(
            Instant.parse("2026-07-20T12:00:00Z"),
            ZoneOffset.UTC
    );

    private CanonicalProjectionSelfTest() {
    }

    public static void main(String[] args) throws Exception {
        retriesProjectionWithoutDuplicatingDomainOrWorkflow();
        System.out.println("CanonicalProjectionSelfTest: PASS");
    }

    private static void retriesProjectionWithoutDuplicatingDomainOrWorkflow() throws Exception {
        Path data = Files.createTempDirectory("rbvm-projection-self-test-");
        String csv = "Agent,CVE_ID,Severity,CVE_Description,Affected_Product,References,OS_name,Detected_At\r\n"
                + "agent-a,CVE-2026-1234,High,description,pkg-a,https://example.test/1,Ubuntu,2026-07-01T10:15:30Z\r\n";
        UUID importId;
        String caseId;
        try {
            RecordingProjection projection = new RecordingProjection();
            try (CsvImportService service = new CsvImportService(
                    data,
                    1024 * 1024,
                    CLOCK,
                    new InMemoryDomainCatalog(),
                    projection
            )) {
                CsvImportService.CreateResult created = service.create(
                        new ByteArrayInputStream(csv.getBytes(StandardCharsets.UTF_8)),
                        csv.getBytes(StandardCharsets.UTF_8).length,
                        "projection-test",
                        "projection-create-0001"
                );
                importId = UUID.fromString(created.importView().get("importId").toString());

                projection.failNextImport = true;
                boolean failed = false;
                try {
                    service.confirm(importId);
                } catch (IOException expected) {
                    failed = expected.getMessage().contains("synthetic import projection failure");
                }
                assert failed;
                assert service.find(importId).orElseThrow().get("status").equals("PREVIEW_READY");
                assert service.catalogSummary().get("observations").equals(1L);

                CsvImportService.ConfirmResult confirmed = service.confirm(importId);
                assert confirmed.importView().get("status").equals("COMPLETED");
                assert projection.importAttempts == 2;
                assert projection.successfulImports == 1;
                assert projection.lastImport.analysis().acceptedRows() == 1;

                Map<String, Object> firstCase = service.queryCases(CaseQuery.firstPage(1));
                @SuppressWarnings("unchecked")
                Map<String, Object> caseView = (Map<String, Object>)
                        ((java.util.List<?>) firstCase.get("cases")).get(0);
                caseId = caseView.get("caseId").toString();

                projection.failNextEvent = true;
                boolean eventFailed = false;
                try {
                    service.actOnCase(
                            caseId,
                            new CaseActionCommand(
                                    CaseActionType.COMMENT,
                                    "projection retry check",
                                    null,
                                    null
                            ),
                            "projection-event-0001"
                    );
                } catch (IOException expected) {
                    eventFailed = expected.getMessage().contains("synthetic event projection failure");
                }
                assert eventFailed;

                CsvImportService.CaseActionResult replayed = service.actOnCase(
                        caseId,
                        new CaseActionCommand(
                                CaseActionType.COMMENT,
                                "projection retry check",
                                null,
                                null
                        ),
                        "projection-event-0001"
                );
                assert replayed.replayed();
                assert projection.eventAttempts == 2;
                assert projection.successfulEvents == 1;
                @SuppressWarnings("unchecked")
                java.util.List<Map<String, Object>> events = (java.util.List<Map<String, Object>>)
                        replayed.caseView().get("auditEvents");
                assert events.size() == 1;

                @SuppressWarnings("unchecked")
                Map<String, Object> projectionHealth = (Map<String, Object>)
                        service.health().get("canonicalProjection");
                assert projectionHealth.get("backend").equals("TEST");
                assert service.health().get("status").equals("UP");
            }

            RecordingProjection recoveredProjection = new RecordingProjection();
            try (CsvImportService recovered = new CsvImportService(
                    data,
                    1024 * 1024,
                    CLOCK,
                    new InMemoryDomainCatalog(),
                    recoveredProjection
            )) {
                assert recoveredProjection.successfulImports == 1;
                assert recoveredProjection.successfulEvents == 1;
                Map<String, Object> detail = recovered.caseDetail(caseId).orElseThrow();
                assert detail.get("workflowVersion").equals(1L);
                assert ((java.util.List<?>) detail.get("auditEvents")).size() == 1;
            }
        } finally {
            deleteTree(data);
        }
    }

    private static void deleteTree(Path root) throws IOException {
        if (!Files.exists(root)) {
            return;
        }
        try (Stream<Path> paths = Files.walk(root)) {
            for (Path path : paths.sorted(Comparator.reverseOrder()).toList()) {
                Files.deleteIfExists(path);
            }
        }
    }

    private static final class RecordingProjection implements CanonicalProjection {
        private int importAttempts;
        private int eventAttempts;
        private int successfulImports;
        private int successfulEvents;
        private boolean failNextImport;
        private boolean failNextEvent;
        private ProjectionImport lastImport;

        @Override
        public void synchronizeImport(ProjectionImport input) throws IOException {
            importAttempts++;
            if (failNextImport) {
                failNextImport = false;
                throw new IOException("synthetic import projection failure");
            }
            successfulImports++;
            lastImport = input;
        }

        @Override
        public void synchronizeCaseEvent(CaseAuditEvent event) throws IOException {
            eventAttempts++;
            if (failNextEvent) {
                failNextEvent = false;
                throw new IOException("synthetic event projection failure");
            }
            successfulEvents++;
        }

        @Override
        public Map<String, Object> health() {
            Map<String, Object> output = new LinkedHashMap<>();
            output.put("backend", "TEST");
            output.put("status", "UP");
            return output;
        }
    }
}

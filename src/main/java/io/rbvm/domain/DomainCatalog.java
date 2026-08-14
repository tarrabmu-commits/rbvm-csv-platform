package io.rbvm.domain;

import java.io.IOException;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

public interface DomainCatalog {
    default String backend() {
        return "LOCAL_MEMORY_REBUILD";
    }

    DomainMaterializationResult materialize(UUID importId, Path csvPath, String sourceProfileId)
            throws IOException;

    CatalogSnapshot snapshot();

    CasePage queryCases(CaseQuery query);

    default List<Map<String, Object>> casePreview(int limit) {
        return queryCases(CaseQuery.firstPage(limit)).cases();
    }

    Optional<Map<String, Object>> caseDetail(String caseId);

    PreparedCaseAction prepareCaseAction(
            long sequence,
            String caseId,
            CaseActionCommand command,
            String idempotencyKey,
            String actorId,
            String actorAssurance,
            Instant occurredAt
    );

    Map<String, Object> applyCaseEvent(CaseAuditEvent event);

    boolean isMaterialized(UUID importId);
}

package io.rbvm.csv;

import io.rbvm.domain.CaseAuditEvent;

import java.io.IOException;
import java.util.Map;

/** Optional durable projection fed from the local evidence and workflow journals. */
public interface CanonicalProjection extends AutoCloseable {
    void synchronizeImport(ProjectionImport input) throws IOException;

    void synchronizeCaseEvent(CaseAuditEvent event) throws IOException;

    Map<String, Object> health();

    @Override
    default void close() {
        // Implementations using per-operation JDBC connections have nothing to close.
    }
}

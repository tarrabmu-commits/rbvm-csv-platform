package io.rbvm.csv;

import io.rbvm.domain.CaseAuditEvent;

import java.util.LinkedHashMap;
import java.util.Map;

public final class NoopCanonicalProjection implements CanonicalProjection {
    @Override
    public void synchronizeImport(ProjectionImport input) {
        // Local raw evidence and the reconstructable in-memory catalog remain authoritative.
    }

    @Override
    public void synchronizeCaseEvent(CaseAuditEvent event) {
        // The local append-only workflow journal already owns durability.
    }

    @Override
    public Map<String, Object> health() {
        Map<String, Object> output = new LinkedHashMap<>();
        output.put("backend", "DISABLED");
        output.put("status", "NOT_CONFIGURED");
        return output;
    }
}

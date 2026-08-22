package io.rbvm.decision;

import java.util.List;
import java.util.Locale;
import java.util.Optional;

/** Deterministic catalog of implemented derived risk methodologies. Order has no precedence. */
public final class RbvmDerivedRiskMethodologyCatalog {
    private static final List<RbvmDerivedRiskMethodology> METHODOLOGIES = List.of(
            MicrosoftProbabilityDamageDerivedV1.INSTANCE,
            OwaspDerivedRiskV1.INSTANCE
    );

    private RbvmDerivedRiskMethodologyCatalog() {
    }

    public static List<RbvmDerivedRiskMethodology.Definition> definitions() {
        return METHODOLOGIES.stream()
                .map(RbvmDerivedRiskMethodology::definition)
                .toList();
    }

    public static Optional<RbvmDerivedRiskMethodology> find(String methodologyId) {
        if (methodologyId == null || methodologyId.trim().isEmpty()) {
            return Optional.empty();
        }
        String normalized = methodologyId.trim().toUpperCase(Locale.ROOT);
        return METHODOLOGIES.stream()
                .filter(value -> value.definition().methodologyId().equals(normalized))
                .findFirst();
    }
}

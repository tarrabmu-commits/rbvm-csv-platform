package io.rbvm.postgres;

import java.io.IOException;
import java.util.Set;

/** Reads the exact annual NVD feeds that have already completed V30 admission. */
@FunctionalInterface
public interface PublicIntelligenceNvdBootstrapStateReader {
    Set<Integer> completedAnnualYears() throws IOException;
}

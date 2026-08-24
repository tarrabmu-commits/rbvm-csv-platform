package io.rbvm.postgres;

import java.io.IOException;
import java.util.Set;

/** Reads the exact currently-active CVE identities for one global public-intelligence provider. */
@FunctionalInterface
public interface PublicIntelligenceCurrentCveReader {
    Set<String> currentCves(PostgresPublicIntelligenceStore.Provider provider) throws IOException;
}

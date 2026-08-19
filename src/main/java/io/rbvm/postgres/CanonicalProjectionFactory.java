package io.rbvm.postgres;

import io.rbvm.csv.CanonicalProjection;
import io.rbvm.csv.NoopCanonicalProjection;
import io.rbvm.domain.DomainCatalog;
import io.rbvm.domain.InMemoryDomainCatalog;

import java.io.IOException;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

public final class CanonicalProjectionFactory {
    private CanonicalProjectionFactory() {
    }

    public static CanonicalProjection fromEnvironment(Map<String, String> environment)
            throws IOException {
        return runtimeFromEnvironment(environment).canonicalProjection();
    }

    public static RuntimeComponents runtimeFromEnvironment(Map<String, String> environment)
            throws IOException {
        PostgresProjectionSettings settings = PostgresProjectionSettings.fromEnvironment(environment);
        if (!settings.enabled()) {
            return new RuntimeComponents(
                    new NoopCanonicalProjection(),
                    new InMemoryDomainCatalog(),
                    Optional.empty(),
                    Optional.empty(),
                    Optional.empty(),
                    Optional.empty()
            );
        }
        JdbcConnectionFactory connections = new DriverManagerConnectionFactory(
                settings.jdbcUrl(),
                settings.user(),
                settings.password()
        );
        PostgresCanonicalProjection projection = new PostgresCanonicalProjection(
                connections,
                settings.migrate()
        );
        PostgresReadCatalog postgresReadCatalog = new PostgresReadCatalog(connections);
        DomainCatalog readCatalog = postgresReadCatalog;
        int installedVersion = new PostgresMigrator(connections).installedVersion();
        Optional<ApplicabilityImporter> applicabilityImporter = Optional.empty();
        Optional<ApplicabilityFindingExporter> applicabilityFindingExporter = Optional.empty();
        Optional<CvssV31Importer> cvssV31Importer = Optional.empty();
        Optional<CvssV31EvidenceReader> cvssV31EvidenceReader = Optional.empty();
        if (installedVersion >= 9) {
            PostgresApplicabilityImporter importer = new PostgresApplicabilityImporter(
                    connections,
                    false
            );
            applicabilityImporter = Optional.of(importer::importFile);
            applicabilityFindingExporter = Optional.of(
                    new PostgresApplicabilityFindingExporter(connections)
            );
            readCatalog = new PostgresApplicabilityAwareCatalog(postgresReadCatalog, connections);
        }
        if (installedVersion >= 10) {
            PostgresCvssV31Importer importer = new PostgresCvssV31Importer(connections, false);
            cvssV31Importer = Optional.of(importer::importFile);
            cvssV31EvidenceReader = Optional.of(new PostgresCvssV31EvidenceReader(connections));
        }
        return new RuntimeComponents(
                projection,
                readCatalog,
                applicabilityImporter,
                applicabilityFindingExporter,
                cvssV31Importer,
                cvssV31EvidenceReader
        );
    }

    public record RuntimeComponents(
            CanonicalProjection canonicalProjection,
            DomainCatalog readCatalog,
            Optional<ApplicabilityImporter> applicabilityImporter,
            Optional<ApplicabilityFindingExporter> applicabilityFindingExporter,
            Optional<CvssV31Importer> cvssV31Importer,
            Optional<CvssV31EvidenceReader> cvssV31EvidenceReader
    ) {
        public RuntimeComponents {
            Objects.requireNonNull(canonicalProjection, "canonicalProjection");
            Objects.requireNonNull(readCatalog, "readCatalog");
            applicabilityImporter = Objects.requireNonNull(
                    applicabilityImporter,
                    "applicabilityImporter"
            );
            applicabilityFindingExporter = Objects.requireNonNull(
                    applicabilityFindingExporter,
                    "applicabilityFindingExporter"
            );
            cvssV31Importer = Objects.requireNonNull(cvssV31Importer, "cvssV31Importer");
            cvssV31EvidenceReader = Objects.requireNonNull(
                    cvssV31EvidenceReader,
                    "cvssV31EvidenceReader"
            );
        }

        public RuntimeComponents(
                CanonicalProjection canonicalProjection,
                DomainCatalog readCatalog
        ) {
            this(
                    canonicalProjection,
                    readCatalog,
                    Optional.empty(),
                    Optional.empty(),
                    Optional.empty(),
                    Optional.empty()
            );
        }

        public RuntimeComponents(
                CanonicalProjection canonicalProjection,
                DomainCatalog readCatalog,
                Optional<ApplicabilityImporter> applicabilityImporter,
                Optional<ApplicabilityFindingExporter> applicabilityFindingExporter
        ) {
            this(
                    canonicalProjection,
                    readCatalog,
                    applicabilityImporter,
                    applicabilityFindingExporter,
                    Optional.empty(),
                    Optional.empty()
            );
        }
    }
}

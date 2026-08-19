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
                    Optional.empty(),
                    Optional.empty(),
                    Optional.empty(),
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
        Optional<CisaKevImporter> cisaKevImporter = Optional.empty();
        Optional<CisaKevEvidenceReader> cisaKevEvidenceReader = Optional.empty();
        Optional<EpssImporter> epssImporter = Optional.empty();
        Optional<EpssEvidenceReader> epssEvidenceReader = Optional.empty();
        Optional<AssetContextImporter> assetContextImporter = Optional.empty();
        Optional<AssetContextEvidenceReader> assetContextEvidenceReader = Optional.empty();
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
        if (installedVersion >= 11) {
            PostgresCisaKevImporter importer = new PostgresCisaKevImporter(connections, false);
            cisaKevImporter = Optional.of(importer::importFile);
            cisaKevEvidenceReader = Optional.of(new PostgresCisaKevEvidenceReader(connections));
        }
        if (installedVersion >= 12) {
            PostgresEpssImporter importer = new PostgresEpssImporter(connections, false);
            epssImporter = Optional.of(importer::importFile);
            epssEvidenceReader = Optional.of(new PostgresEpssEvidenceReader(connections));
        }
        if (installedVersion >= 13) {
            PostgresAssetContextImporter importer = new PostgresAssetContextImporter(connections, false);
            assetContextImporter = Optional.of(importer::importFile);
            assetContextEvidenceReader = Optional.of(
                    new PostgresAssetContextEvidenceReader(connections)
            );
        }
        return new RuntimeComponents(
                projection,
                readCatalog,
                applicabilityImporter,
                applicabilityFindingExporter,
                cvssV31Importer,
                cvssV31EvidenceReader,
                cisaKevImporter,
                cisaKevEvidenceReader,
                epssImporter,
                epssEvidenceReader,
                assetContextImporter,
                assetContextEvidenceReader
        );
    }

    public record RuntimeComponents(
            CanonicalProjection canonicalProjection,
            DomainCatalog readCatalog,
            Optional<ApplicabilityImporter> applicabilityImporter,
            Optional<ApplicabilityFindingExporter> applicabilityFindingExporter,
            Optional<CvssV31Importer> cvssV31Importer,
            Optional<CvssV31EvidenceReader> cvssV31EvidenceReader,
            Optional<CisaKevImporter> cisaKevImporter,
            Optional<CisaKevEvidenceReader> cisaKevEvidenceReader,
            Optional<EpssImporter> epssImporter,
            Optional<EpssEvidenceReader> epssEvidenceReader,
            Optional<AssetContextImporter> assetContextImporter,
            Optional<AssetContextEvidenceReader> assetContextEvidenceReader
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
            cisaKevImporter = Objects.requireNonNull(cisaKevImporter, "cisaKevImporter");
            cisaKevEvidenceReader = Objects.requireNonNull(
                    cisaKevEvidenceReader,
                    "cisaKevEvidenceReader"
            );
            epssImporter = Objects.requireNonNull(epssImporter, "epssImporter");
            epssEvidenceReader = Objects.requireNonNull(epssEvidenceReader, "epssEvidenceReader");
            assetContextImporter = Objects.requireNonNull(
                    assetContextImporter,
                    "assetContextImporter"
            );
            assetContextEvidenceReader = Objects.requireNonNull(
                    assetContextEvidenceReader,
                    "assetContextEvidenceReader"
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
                    Optional.empty(),
                    Optional.empty(),
                    Optional.empty(),
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
                    Optional.empty(),
                    Optional.empty(),
                    Optional.empty(),
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
                Optional<ApplicabilityFindingExporter> applicabilityFindingExporter,
                Optional<CvssV31Importer> cvssV31Importer,
                Optional<CvssV31EvidenceReader> cvssV31EvidenceReader
        ) {
            this(
                    canonicalProjection,
                    readCatalog,
                    applicabilityImporter,
                    applicabilityFindingExporter,
                    cvssV31Importer,
                    cvssV31EvidenceReader,
                    Optional.empty(),
                    Optional.empty(),
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
                Optional<ApplicabilityFindingExporter> applicabilityFindingExporter,
                Optional<CvssV31Importer> cvssV31Importer,
                Optional<CvssV31EvidenceReader> cvssV31EvidenceReader,
                Optional<CisaKevImporter> cisaKevImporter,
                Optional<CisaKevEvidenceReader> cisaKevEvidenceReader
        ) {
            this(
                    canonicalProjection,
                    readCatalog,
                    applicabilityImporter,
                    applicabilityFindingExporter,
                    cvssV31Importer,
                    cvssV31EvidenceReader,
                    cisaKevImporter,
                    cisaKevEvidenceReader,
                    Optional.empty(),
                    Optional.empty(),
                    Optional.empty(),
                    Optional.empty()
            );
        }

        /** Backward-compatible constructor through the EPSS V12 runtime capability layer. */
        public RuntimeComponents(
                CanonicalProjection canonicalProjection,
                DomainCatalog readCatalog,
                Optional<ApplicabilityImporter> applicabilityImporter,
                Optional<ApplicabilityFindingExporter> applicabilityFindingExporter,
                Optional<CvssV31Importer> cvssV31Importer,
                Optional<CvssV31EvidenceReader> cvssV31EvidenceReader,
                Optional<CisaKevImporter> cisaKevImporter,
                Optional<CisaKevEvidenceReader> cisaKevEvidenceReader,
                Optional<EpssImporter> epssImporter,
                Optional<EpssEvidenceReader> epssEvidenceReader
        ) {
            this(
                    canonicalProjection,
                    readCatalog,
                    applicabilityImporter,
                    applicabilityFindingExporter,
                    cvssV31Importer,
                    cvssV31EvidenceReader,
                    cisaKevImporter,
                    cisaKevEvidenceReader,
                    epssImporter,
                    epssEvidenceReader,
                    Optional.empty(),
                    Optional.empty()
            );
        }
    }
}

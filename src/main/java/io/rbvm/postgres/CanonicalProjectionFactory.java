package io.rbvm.postgres;

import io.rbvm.asset.ManagedAssetRegistry;
import io.rbvm.asset.ScannerManagedAssetLinkRegistry;
import io.rbvm.context.FindingBusinessServiceLinkRegistry;
import io.rbvm.context.FindingReachabilityScopeLinkRegistry;
import io.rbvm.csv.CanonicalProjection;
import io.rbvm.csv.NoopCanonicalProjection;
import io.rbvm.decision.DecisionInputEvidenceResolver;
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

    /**
     * Builds the explicit Finding-context association capability when PostgreSQL V21+ exists.
     * Kept separate from RuntimeComponents so older constructor compatibility remains untouched.
     */
    public static Optional<FindingContextAssociationRuntime>
            findingContextAssociationRuntimeFromEnvironment(Map<String, String> environment)
            throws IOException {
        PostgresProjectionSettings settings = PostgresProjectionSettings.fromEnvironment(environment);
        if (!settings.enabled()) {
            return Optional.empty();
        }
        JdbcConnectionFactory connections = new DriverManagerConnectionFactory(
                settings.jdbcUrl(),
                settings.user(),
                settings.password()
        );
        PostgresMigrator migrator = new PostgresMigrator(connections);
        int installedVersion = settings.migrate() ? migrator.migrate() : migrator.installedVersion();
        if (installedVersion < 21) {
            return Optional.empty();
        }
        return Optional.of(new FindingContextAssociationRuntime(
                new PostgresFindingReachabilityScopeLinkRegistry(connections, false),
                new PostgresFindingBusinessServiceLinkRegistry(connections, false)
        ));
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
        Optional<NetworkReachabilityImporter> networkReachabilityImporter = Optional.empty();
        Optional<NetworkReachabilityEvidenceReader> networkReachabilityEvidenceReader = Optional.empty();
        Optional<BusinessImpactImporter> businessImpactImporter = Optional.empty();
        Optional<BusinessImpactEvidenceReader> businessImpactEvidenceReader = Optional.empty();
        Optional<DecisionRuntime> decisionRuntime = Optional.empty();
        Optional<ManagedAssetRegistry> managedAssetRegistry = Optional.empty();
        Optional<ScannerManagedAssetLinkRegistry> scannerManagedAssetLinkRegistry = Optional.empty();
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
        if (installedVersion >= 14) {
            PostgresNetworkReachabilityImporter importer =
                    new PostgresNetworkReachabilityImporter(connections, false);
            networkReachabilityImporter = Optional.of(importer::importFile);
            networkReachabilityEvidenceReader = Optional.of(
                    new PostgresNetworkReachabilityEvidenceReader(connections)
            );
        }
        if (installedVersion >= 15) {
            PostgresBusinessImpactImporter importer = new PostgresBusinessImpactImporter(
                    connections,
                    false
            );
            businessImpactImporter = Optional.of(importer::importFile);
            businessImpactEvidenceReader = Optional.of(
                    new PostgresBusinessImpactEvidenceReader(connections)
            );
        }
        if (installedVersion >= 17) {
            PostgresDecisionMethodologyPolicyStore methodologyPolicies =
                    new PostgresDecisionMethodologyPolicyStore(connections, false);
            PostgresDecisionInputSnapshotStore snapshots =
                    new PostgresDecisionInputSnapshotStore(connections, false);
            PostgresDecisionInputSnapshotBuilder builder =
                    new PostgresDecisionInputSnapshotBuilder(
                            connections,
                            methodologyPolicies,
                            installedVersion
                    );
            PostgresDecisionInputEvidenceResolver evidenceResolver =
                    new PostgresDecisionInputEvidenceResolver(connections, installedVersion);
            decisionRuntime = Optional.of(new DecisionRuntime(
                    methodologyPolicies,
                    snapshots,
                    new DefaultDecisionInputSnapshotMaterializer(builder, snapshots),
                    Optional.of(evidenceResolver)
            ));
        }
        if (installedVersion >= 18) {
            managedAssetRegistry = Optional.of(
                    new PostgresManagedAssetRegistry(connections, false)
            );
        }
        if (installedVersion >= 19) {
            scannerManagedAssetLinkRegistry = Optional.of(
                    new PostgresScannerManagedAssetLinkRegistry(connections, false)
            );
        }
        if (installedVersion >= 12) {
            readCatalog = new PostgresEvidenceAwareCatalog(readCatalog, connections);
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
                assetContextEvidenceReader,
                networkReachabilityImporter,
                networkReachabilityEvidenceReader,
                businessImpactImporter,
                businessImpactEvidenceReader,
                decisionRuntime,
                managedAssetRegistry,
                scannerManagedAssetLinkRegistry
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
            Optional<AssetContextEvidenceReader> assetContextEvidenceReader,
            Optional<NetworkReachabilityImporter> networkReachabilityImporter,
            Optional<NetworkReachabilityEvidenceReader> networkReachabilityEvidenceReader,
            Optional<BusinessImpactImporter> businessImpactImporter,
            Optional<BusinessImpactEvidenceReader> businessImpactEvidenceReader,
            Optional<DecisionRuntime> decisionRuntime,
            Optional<ManagedAssetRegistry> managedAssetRegistry,
            Optional<ScannerManagedAssetLinkRegistry> scannerManagedAssetLinkRegistry
    ) {
        public RuntimeComponents {
            Objects.requireNonNull(canonicalProjection, "canonicalProjection");
            Objects.requireNonNull(readCatalog, "readCatalog");
            applicabilityImporter = Objects.requireNonNull(applicabilityImporter, "applicabilityImporter");
            applicabilityFindingExporter = Objects.requireNonNull(applicabilityFindingExporter, "applicabilityFindingExporter");
            cvssV31Importer = Objects.requireNonNull(cvssV31Importer, "cvssV31Importer");
            cvssV31EvidenceReader = Objects.requireNonNull(cvssV31EvidenceReader, "cvssV31EvidenceReader");
            cisaKevImporter = Objects.requireNonNull(cisaKevImporter, "cisaKevImporter");
            cisaKevEvidenceReader = Objects.requireNonNull(cisaKevEvidenceReader, "cisaKevEvidenceReader");
            epssImporter = Objects.requireNonNull(epssImporter, "epssImporter");
            epssEvidenceReader = Objects.requireNonNull(epssEvidenceReader, "epssEvidenceReader");
            assetContextImporter = Objects.requireNonNull(assetContextImporter, "assetContextImporter");
            assetContextEvidenceReader = Objects.requireNonNull(assetContextEvidenceReader, "assetContextEvidenceReader");
            networkReachabilityImporter = Objects.requireNonNull(networkReachabilityImporter, "networkReachabilityImporter");
            networkReachabilityEvidenceReader = Objects.requireNonNull(networkReachabilityEvidenceReader, "networkReachabilityEvidenceReader");
            businessImpactImporter = Objects.requireNonNull(businessImpactImporter, "businessImpactImporter");
            businessImpactEvidenceReader = Objects.requireNonNull(businessImpactEvidenceReader, "businessImpactEvidenceReader");
            decisionRuntime = Objects.requireNonNull(decisionRuntime, "decisionRuntime");
            managedAssetRegistry = Objects.requireNonNull(managedAssetRegistry, "managedAssetRegistry");
            scannerManagedAssetLinkRegistry = Objects.requireNonNull(
                    scannerManagedAssetLinkRegistry,
                    "scannerManagedAssetLinkRegistry"
            );
        }

        /** Backward-compatible constructor through the complete V20 runtime layer. */
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
                Optional<EpssEvidenceReader> epssEvidenceReader,
                Optional<AssetContextImporter> assetContextImporter,
                Optional<AssetContextEvidenceReader> assetContextEvidenceReader,
                Optional<NetworkReachabilityImporter> networkReachabilityImporter,
                Optional<NetworkReachabilityEvidenceReader> networkReachabilityEvidenceReader,
                Optional<BusinessImpactImporter> businessImpactImporter,
                Optional<BusinessImpactEvidenceReader> businessImpactEvidenceReader,
                Optional<DecisionRuntime> decisionRuntime,
                Optional<ManagedAssetRegistry> managedAssetRegistry
        ) {
            this(
                    canonicalProjection, readCatalog, applicabilityImporter,
                    applicabilityFindingExporter, cvssV31Importer, cvssV31EvidenceReader,
                    cisaKevImporter, cisaKevEvidenceReader, epssImporter, epssEvidenceReader,
                    assetContextImporter, assetContextEvidenceReader,
                    networkReachabilityImporter, networkReachabilityEvidenceReader,
                    businessImpactImporter, businessImpactEvidenceReader, decisionRuntime,
                    managedAssetRegistry, Optional.empty()
            );
        }

        /** Backward-compatible constructor through the complete V17 Decision runtime layer. */
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
                Optional<EpssEvidenceReader> epssEvidenceReader,
                Optional<AssetContextImporter> assetContextImporter,
                Optional<AssetContextEvidenceReader> assetContextEvidenceReader,
                Optional<NetworkReachabilityImporter> networkReachabilityImporter,
                Optional<NetworkReachabilityEvidenceReader> networkReachabilityEvidenceReader,
                Optional<BusinessImpactImporter> businessImpactImporter,
                Optional<BusinessImpactEvidenceReader> businessImpactEvidenceReader,
                Optional<DecisionRuntime> decisionRuntime
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
                    assetContextImporter,
                    assetContextEvidenceReader,
                    networkReachabilityImporter,
                    networkReachabilityEvidenceReader,
                    businessImpactImporter,
                    businessImpactEvidenceReader,
                    decisionRuntime,
                    Optional.empty()
            );
        }

        /** Backward-compatible constructor through the Business Impact V15 runtime layer. */
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
                Optional<EpssEvidenceReader> epssEvidenceReader,
                Optional<AssetContextImporter> assetContextImporter,
                Optional<AssetContextEvidenceReader> assetContextEvidenceReader,
                Optional<NetworkReachabilityImporter> networkReachabilityImporter,
                Optional<NetworkReachabilityEvidenceReader> networkReachabilityEvidenceReader,
                Optional<BusinessImpactImporter> businessImpactImporter,
                Optional<BusinessImpactEvidenceReader> businessImpactEvidenceReader
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
                    assetContextImporter,
                    assetContextEvidenceReader,
                    networkReachabilityImporter,
                    networkReachabilityEvidenceReader,
                    businessImpactImporter,
                    businessImpactEvidenceReader,
                    Optional.empty()
            );
        }

        public RuntimeComponents(CanonicalProjection canonicalProjection, DomainCatalog readCatalog) {
            this(canonicalProjection, readCatalog,
                    Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty(),
                    Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty(),
                    Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty());
        }

        public RuntimeComponents(
                CanonicalProjection canonicalProjection,
                DomainCatalog readCatalog,
                Optional<ApplicabilityImporter> applicabilityImporter,
                Optional<ApplicabilityFindingExporter> applicabilityFindingExporter
        ) {
            this(canonicalProjection, readCatalog, applicabilityImporter, applicabilityFindingExporter,
                    Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty(),
                    Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty(),
                    Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty());
        }

        public RuntimeComponents(
                CanonicalProjection canonicalProjection,
                DomainCatalog readCatalog,
                Optional<ApplicabilityImporter> applicabilityImporter,
                Optional<ApplicabilityFindingExporter> applicabilityFindingExporter,
                Optional<CvssV31Importer> cvssV31Importer,
                Optional<CvssV31EvidenceReader> cvssV31EvidenceReader
        ) {
            this(canonicalProjection, readCatalog, applicabilityImporter, applicabilityFindingExporter,
                    cvssV31Importer, cvssV31EvidenceReader,
                    Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty(),
                    Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty());
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
            this(canonicalProjection, readCatalog, applicabilityImporter, applicabilityFindingExporter,
                    cvssV31Importer, cvssV31EvidenceReader, cisaKevImporter, cisaKevEvidenceReader,
                    Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty(),
                    Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty());
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
            this(canonicalProjection, readCatalog, applicabilityImporter, applicabilityFindingExporter,
                    cvssV31Importer, cvssV31EvidenceReader, cisaKevImporter, cisaKevEvidenceReader,
                    epssImporter, epssEvidenceReader,
                    Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty());
        }

        /** Backward-compatible constructor through the Asset Context V13 runtime capability layer. */
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
                Optional<EpssEvidenceReader> epssEvidenceReader,
                Optional<AssetContextImporter> assetContextImporter,
                Optional<AssetContextEvidenceReader> assetContextEvidenceReader
        ) {
            this(canonicalProjection, readCatalog, applicabilityImporter, applicabilityFindingExporter,
                    cvssV31Importer, cvssV31EvidenceReader, cisaKevImporter, cisaKevEvidenceReader,
                    epssImporter, epssEvidenceReader, assetContextImporter, assetContextEvidenceReader,
                    Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty());
        }

        /** Backward-compatible constructor through the Network Reachability V14 runtime capability layer. */
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
                Optional<EpssEvidenceReader> epssEvidenceReader,
                Optional<AssetContextImporter> assetContextImporter,
                Optional<AssetContextEvidenceReader> assetContextEvidenceReader,
                Optional<NetworkReachabilityImporter> networkReachabilityImporter,
                Optional<NetworkReachabilityEvidenceReader> networkReachabilityEvidenceReader
        ) {
            this(canonicalProjection, readCatalog, applicabilityImporter, applicabilityFindingExporter,
                    cvssV31Importer, cvssV31EvidenceReader, cisaKevImporter, cisaKevEvidenceReader,
                    epssImporter, epssEvidenceReader, assetContextImporter, assetContextEvidenceReader,
                    networkReachabilityImporter, networkReachabilityEvidenceReader,
                    Optional.empty(), Optional.empty());
        }
    }

    public record FindingContextAssociationRuntime(
            FindingReachabilityScopeLinkRegistry reachabilityLinks,
            FindingBusinessServiceLinkRegistry businessServiceLinks
    ) {
        public FindingContextAssociationRuntime {
            reachabilityLinks = Objects.requireNonNull(reachabilityLinks, "reachabilityLinks");
            businessServiceLinks = Objects.requireNonNull(businessServiceLinks, "businessServiceLinks");
        }
    }

    /** Complete Decision Input runtime capability. Exposed only when PostgreSQL schema V17+ exists. */
    public record DecisionRuntime(
            DecisionMethodologyPolicyStore methodologyPolicies,
            DecisionInputSnapshotStore snapshots,
            DecisionInputSnapshotMaterializer materializer,
            Optional<DecisionInputEvidenceResolver> evidenceResolver
    ) {
        public DecisionRuntime {
            methodologyPolicies = Objects.requireNonNull(methodologyPolicies, "methodologyPolicies");
            snapshots = Objects.requireNonNull(snapshots, "snapshots");
            materializer = Objects.requireNonNull(materializer, "materializer");
            evidenceResolver = Objects.requireNonNull(evidenceResolver, "evidenceResolver");
        }

        /** Backward-compatible constructor through snapshot materialization runtime. */
        public DecisionRuntime(
                DecisionMethodologyPolicyStore methodologyPolicies,
                DecisionInputSnapshotStore snapshots,
                DecisionInputSnapshotMaterializer materializer
        ) {
            this(methodologyPolicies, snapshots, materializer, Optional.empty());
        }
    }
}

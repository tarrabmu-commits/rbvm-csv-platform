package io.rbvm.csv;

import com.sun.net.httpserver.HttpServer;

import io.rbvm.context.FindingBusinessServiceLinkRegistry;
import io.rbvm.context.FindingReachabilityScopeLinkRegistry;
import io.rbvm.postgres.ActiveRiskMethodExecutionRuntimeFactory;
import io.rbvm.postgres.CanonicalImportFindingExporter;
import io.rbvm.postgres.CanonicalImportFindingRuntimeFactory;
import io.rbvm.postgres.CanonicalMvpPriorityRuntimeFactory;
import io.rbvm.postgres.CanonicalMvpPriorityStore;
import io.rbvm.postgres.CanonicalProjectionFactory;
import io.rbvm.postgres.CanonicalProjectionFactory.RuntimeComponents;
import io.rbvm.postgres.CisaKevImporter;
import io.rbvm.postgres.CsvFirstLocalIntelligenceRuntimeFactory;
import io.rbvm.postgres.DerivedRiskResultRuntimeFactory;
import io.rbvm.postgres.EpssImporter;
import io.rbvm.postgres.FormulaResultRuntimeFactory;
import io.rbvm.postgres.PostgresPublicIntelligenceSyncJobStore;
import io.rbvm.postgres.PublicIntelligenceAutomationController;
import io.rbvm.postgres.PublicIntelligenceAutomationRuntimeFactory;
import io.rbvm.postgres.PublicIntelligenceOrchestrationRuntimeFactory;
import io.rbvm.postgres.PublicIntelligenceStatusReader;
import io.rbvm.postgres.PublicIntelligenceSyncCoordinator;
import io.rbvm.postgres.PublicIntelligenceSyncRuntimeFactory;
import io.rbvm.postgres.PublicIntelligenceSyncTrigger;
import io.rbvm.postgres.RiskMethodSelectionPolicyRuntimeFactory;
import io.rbvm.security.ApiKeyAuthenticator;
import io.rbvm.security.RequestRateLimiter;

import java.lang.reflect.Field;
import java.nio.file.Path;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CountDownLatch;

/**
 * Product launcher that enables the CSV-first upload transport alongside the
 * existing CsvPlatformServer without changing the established route adapter.
 */
public final class RbvmPlatformMain {
    private static final long DEFAULT_MAXIMUM_UPLOAD_BYTES = 100L * 1024L * 1024L;

    private RbvmPlatformMain() {
    }

    public static void main(String[] args) throws Exception {
        Map<String, String> environment = System.getenv();
        String host = environment(environment, "RBVM_HOST", "127.0.0.1");
        int port = Math.toIntExact(parseLong(
                environment(environment, "RBVM_PORT", "8080"),
                "RBVM_PORT", 1, 65_535));
        Path dataDirectory = Path.of(environment(environment, "RBVM_DATA_DIR", "data"));
        long maximumUploadBytes = parseLong(
                environment(environment, "RBVM_MAX_UPLOAD_BYTES", Long.toString(DEFAULT_MAXIMUM_UPLOAD_BYTES)),
                "RBVM_MAX_UPLOAD_BYTES", 1, Long.MAX_VALUE);

        RuntimeComponents runtime = CanonicalProjectionFactory.runtimeFromEnvironment(environment);
        Optional<CanonicalProjectionFactory.FindingContextAssociationRuntime> associationRuntime =
                CanonicalProjectionFactory.findingContextAssociationRuntimeFromEnvironment(environment);
        Optional<CanonicalImportFindingExporter> canonicalImportFindings =
                CanonicalImportFindingRuntimeFactory.fromEnvironment(environment);
        Optional<CanonicalMvpPriorityStore> canonicalMvpPriority =
                CanonicalMvpPriorityRuntimeFactory.fromEnvironment(environment);
        Optional<FormulaResultRuntimeFactory.Runtime> formulaResultRuntime =
                FormulaResultRuntimeFactory.fromEnvironment(environment);
        Optional<DerivedRiskResultRuntimeFactory.Runtime> derivedRiskResultRuntime =
                DerivedRiskResultRuntimeFactory.fromEnvironment(environment);
        Optional<RiskMethodSelectionPolicyRuntimeFactory.Runtime> riskMethodSelectionPolicyRuntime =
                RiskMethodSelectionPolicyRuntimeFactory.fromEnvironment(environment);
        Optional<ActiveRiskMethodExecutionRuntimeFactory.Runtime> activeRiskMethodExecutionRuntime =
                ActiveRiskMethodExecutionRuntimeFactory.fromEnvironment(environment);
        Optional<PostgresPublicIntelligenceSyncJobStore> publicIntelligenceStatusRuntime =
                PublicIntelligenceSyncRuntimeFactory.fromEnvironment(environment);
        Optional<CsvFirstLocalIntelligenceSnapshotExporter> csvFirstLocalIntelligence =
                CsvFirstLocalIntelligenceRuntimeFactory.fromEnvironment(environment);
        Optional<PublicIntelligenceSyncCoordinator> publicIntelligenceOrchestration =
                PublicIntelligenceOrchestrationRuntimeFactory.fromEnvironment(
                        environment, dataDirectory);
        Optional<PublicIntelligenceAutomationController> publicIntelligenceAutomation =
                PublicIntelligenceAutomationRuntimeFactory.fromEnvironment(
                        environment, publicIntelligenceOrchestration);
        ApiKeyAuthenticator authenticator = ApiKeyAuthenticator.fromEnvironment(environment);
        RequestRateLimiter rateLimiter = RequestRateLimiter.fromEnvironment(environment);
        CanonicalProjection canonicalProjection = runtime.canonicalProjection();

        CsvPlatformServer application = new CsvPlatformServer(
                host,
                port,
                dataDirectory,
                maximumUploadBytes,
                canonicalProjection,
                runtime.readCatalog(),
                runtime.applicabilityImporter(),
                runtime.applicabilityFindingExporter(),
                runtime.cvssV31Importer(),
                runtime.cvssV31EvidenceReader(),
                runtime.cisaKevImporter(),
                runtime.cisaKevEvidenceReader(),
                runtime.epssImporter(),
                runtime.epssEvidenceReader(),
                runtime.assetContextImporter(),
                runtime.assetContextEvidenceReader(),
                runtime.networkReachabilityImporter(),
                runtime.networkReachabilityEvidenceReader(),
                runtime.businessImpactImporter(),
                runtime.businessImpactEvidenceReader(),
                runtime.managedAssetRegistry(),
                runtime.scannerManagedAssetLinkRegistry(),
                authenticator,
                rateLimiter
        );

        registerProductExtensions(
                application,
                dataDirectory,
                maximumUploadBytes,
                canonicalImportFindings,
                canonicalMvpPriority,
                runtime.epssImporter(),
                runtime.cisaKevImporter(),
                csvFirstLocalIntelligence,
                publicIntelligenceStatusRuntime,
                publicIntelligenceOrchestration,
                authenticator
        );

        associationRuntime.ifPresent(context -> application.enableFindingContextAssociationApi(
                context.reachabilityLinks(),
                context.businessServiceLinks()
        ));
        formulaResultRuntime.ifPresent(context -> application.enableFormulaResultApi(
                new FormulaResultApi(context.results(), context.replayVerifier())
        ));
        derivedRiskResultRuntime.ifPresent(context -> application.enableDerivedRiskResultApi(
                new DerivedRiskResultApi(
                        context.results(), context.replayVerifier(), context.materializer()
                )
        ));
        riskMethodSelectionPolicyRuntime.ifPresent(context ->
                application.enableRiskMethodSelectionPolicyApi(
                        new RiskMethodSelectionPolicyApi(context.policies())
                )
        );
        activeRiskMethodExecutionRuntime.ifPresent(context ->
                application.enableActiveRiskMethodExecutionApi(
                        new ActiveRiskMethodExecutionApi(context.bindings(), context.materializer())
                )
        );

        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            publicIntelligenceAutomation.ifPresent(PublicIntelligenceAutomationController::close);
            publicIntelligenceOrchestration.ifPresent(PublicIntelligenceSyncCoordinator::close);
            application.close();
        }, "rbvm-shutdown"));
        application.start();
        publicIntelligenceAutomation.ifPresent(PublicIntelligenceAutomationController::start);
        System.out.println("RBVM CSV Platform is running at " + application.baseUri());
        System.out.println("CSV-first enrichment API: "
                + application.baseUri().resolve("/api/v1/csv-first-enrichments"));
        System.out.println("CSV-first async enrichment jobs API: "
                + application.baseUri().resolve("/api/v1/csv-first-enrichment-jobs"));
        System.out.println("CSV-first customer asset bundle API: "
                + application.baseUri().resolve("/api/v1/csv-first-customer-assets/{runId}"));
        System.out.println("CSV-first local public intelligence: "
                + (csvFirstLocalIntelligence.isPresent() ? "CONFIGURED" : "UNAVAILABLE"));
        System.out.println("CSV-first MVP priority API: "
                + application.baseUri().resolve("/api/v1/csv-first-priorities/{runId}/{analysisId}"));
        System.out.println("CSV-first risk method catalog API: "
                + application.baseUri().resolve(CsvFirstRiskHttpHandler.METHODS_ROOT));
        System.out.println("CSV-first risk readiness API: "
                + application.baseUri().resolve("/api/v1/csv-first-risk-readiness/{runId}/{analysisId}"));
        System.out.println("CSV-first risk execution API: "
                + application.baseUri().resolve(
                        "/api/v1/csv-first-risks/{runId}/{analysisId}/{methodId}"));
        System.out.println("CSV-first risk benchmark API: "
                + application.baseUri().resolve(
                        "/api/v1/csv-first-risk-benchmarks/{runId}/{analysisId}"));
        System.out.println("Canonical MVP priority API: "
                + application.baseUri().resolve("/api/v1/canonical-mvp-priorities/{importId}/{runId}/{analysisId}"));
        System.out.println("CSV-first source API: "
                + application.baseUri().resolve("/api/v1/csv-first-sources/{runId}"));
        System.out.println("CSV-first canonical public evidence API: "
                + application.baseUri().resolve("/api/v1/csv-first-canonical-evidence/{runId}"));
        System.out.println("Canonical import Finding manifest API: "
                + application.baseUri().resolve("/api/v1/canonical-imports/{importId}/findings.csv"));
        System.out.println("Public intelligence status API: "
                + application.baseUri().resolve("/api/v1/intelligence/status"));
        System.out.println("Public intelligence sync API: "
                + application.baseUri().resolve("/api/v1/intelligence/sync/{provider}"));
        System.out.println("Public intelligence automation: "
                + (publicIntelligenceAutomation.isPresent() ? "CONFIGURED" : "DISABLED"));
        System.out.println("Managed Assets operator UI: " + application.baseUri().resolve("/assets"));
        System.out.println("Data directory: " + dataDirectory.toAbsolutePath().normalize());
        System.out.println("Canonical projection: " + canonicalProjection.health().get("backend"));
        System.out.println("API authentication: " + (authenticator.enabled() ? "API_KEY" : "DISABLED"));
        new CountDownLatch(1).await();
    }

    private static void registerProductExtensions(
            CsvPlatformServer application,
            Path dataDirectory,
            long maximumUploadBytes,
            Optional<CanonicalImportFindingExporter> canonicalImportFindings,
            Optional<CanonicalMvpPriorityStore> canonicalMvpPriority,
            Optional<EpssImporter> epssImporter,
            Optional<CisaKevImporter> cisaKevImporter,
            Optional<CsvFirstLocalIntelligenceSnapshotExporter> csvFirstLocalIntelligence,
            Optional<? extends PublicIntelligenceStatusReader> publicIntelligenceStatus,
            Optional<? extends PublicIntelligenceSyncTrigger> publicIntelligenceSync,
            ApiKeyAuthenticator authenticator
    ) throws ReflectiveOperationException {
        // Transitional registration seam: CsvPlatformServer predates extension
        // contexts and keeps its HttpServer private. Keep the reflection isolated
        // here so the established adapter does not need a broad rewrite for these
        // narrow CSV-first and exact import-scoped transports.
        Field serverField = CsvPlatformServer.class.getDeclaredField("server");
        serverField.setAccessible(true);
        HttpServer server = (HttpServer) serverField.get(application);
        server.createContext(
                "/api/v1/csv-first-enrichments",
                new CsvFirstLocalEnrichmentHttpHandler(
                        dataDirectory, maximumUploadBytes, csvFirstLocalIntelligence, authenticator)
        );
        server.createContext(
                "/api/v1/csv-first-enrichment-jobs",
                new CsvFirstLocalEnrichmentJobHttpHandler(
                        dataDirectory, maximumUploadBytes, csvFirstLocalIntelligence, authenticator)
        );
        server.createContext(
                CsvFirstCustomerAssetBundleHttpHandler.ROOT,
                new CsvFirstCustomerAssetBundleHttpHandler(
                        dataDirectory, maximumUploadBytes, authenticator)
        );
        server.createContext(
                "/api/v1/csv-first-priorities",
                new CsvFirstMvpPriorityHttpHandler(dataDirectory, authenticator)
        );
        CsvFirstRiskHttpHandler csvFirstRisk = new CsvFirstRiskHttpHandler(
                dataDirectory, authenticator);
        server.createContext(CsvFirstRiskHttpHandler.METHODS_ROOT, csvFirstRisk);
        server.createContext(CsvFirstRiskHttpHandler.READINESS_ROOT, csvFirstRisk);
        server.createContext(CsvFirstRiskHttpHandler.RISKS_ROOT, csvFirstRisk);
        server.createContext(
                CsvFirstRiskBenchmarkHttpHandler.ROOT,
                new CsvFirstRiskBenchmarkHttpHandler(dataDirectory, authenticator)
        );
        server.createContext(
                "/api/v1/canonical-mvp-priorities/findings",
                new CanonicalMvpPriorityReadHttpHandler(canonicalMvpPriority, authenticator)
        );
        server.createContext(
                "/api/v1/canonical-mvp-priorities",
                new CanonicalMvpPriorityHttpHandler(dataDirectory, canonicalMvpPriority, authenticator)
        );
        server.createContext(
                "/api/v1/csv-first-sources",
                new CsvFirstSourceHttpHandler(dataDirectory, authenticator)
        );
        server.createContext(
                "/api/v1/csv-first-canonical-evidence",
                new CsvFirstCanonicalEvidenceHttpHandler(
                        dataDirectory, epssImporter, cisaKevImporter, authenticator)
        );
        server.createContext(
                "/api/v1/canonical-imports",
                new CanonicalImportFindingHttpHandler(canonicalImportFindings, authenticator)
        );
        server.createContext(
                PublicIntelligenceStatusHttpHandler.ROOT,
                new PublicIntelligenceStatusHttpHandler(publicIntelligenceStatus, authenticator)
        );
        server.createContext(
                PublicIntelligenceSyncHttpHandler.ROOT,
                new PublicIntelligenceSyncHttpHandler(publicIntelligenceSync, authenticator)
        );
    }

    private static String environment(Map<String, String> environment, String name, String fallback) {
        String value = environment.get(name);
        return value == null || value.isBlank() ? fallback : value.trim();
    }

    private static long parseLong(String value, String name, long minimum, long maximum) {
        try {
            long parsed = Long.parseLong(value);
            if (parsed < minimum || parsed > maximum) {
                throw new IllegalArgumentException(
                        name + " must be between " + minimum + " and " + maximum);
            }
            return parsed;
        } catch (NumberFormatException exception) {
            throw new IllegalArgumentException(name + " must be an integer", exception);
        }
    }
}

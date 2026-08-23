package io.rbvm.csv;

import com.sun.net.httpserver.HttpServer;

import io.rbvm.context.FindingBusinessServiceLinkRegistry;
import io.rbvm.context.FindingReachabilityScopeLinkRegistry;
import io.rbvm.postgres.ActiveRiskMethodExecutionRuntimeFactory;
import io.rbvm.postgres.CanonicalImportFindingExporter;
import io.rbvm.postgres.CanonicalImportFindingRuntimeFactory;
import io.rbvm.postgres.CanonicalProjectionFactory;
import io.rbvm.postgres.CanonicalProjectionFactory.RuntimeComponents;
import io.rbvm.postgres.DerivedRiskResultRuntimeFactory;
import io.rbvm.postgres.FormulaResultRuntimeFactory;
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
        Optional<FormulaResultRuntimeFactory.Runtime> formulaResultRuntime =
                FormulaResultRuntimeFactory.fromEnvironment(environment);
        Optional<DerivedRiskResultRuntimeFactory.Runtime> derivedRiskResultRuntime =
                DerivedRiskResultRuntimeFactory.fromEnvironment(environment);
        Optional<RiskMethodSelectionPolicyRuntimeFactory.Runtime> riskMethodSelectionPolicyRuntime =
                RiskMethodSelectionPolicyRuntimeFactory.fromEnvironment(environment);
        Optional<ActiveRiskMethodExecutionRuntimeFactory.Runtime> activeRiskMethodExecutionRuntime =
                ActiveRiskMethodExecutionRuntimeFactory.fromEnvironment(environment);
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
                        context.results(),
                        context.replayVerifier(),
                        context.materializer()
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

        Runtime.getRuntime().addShutdownHook(new Thread(application::close, "rbvm-shutdown"));
        application.start();
        System.out.println("RBVM CSV Platform is running at " + application.baseUri());
        System.out.println("CSV-first enrichment API: "
                + application.baseUri().resolve("/api/v1/csv-first-enrichments"));
        System.out.println("CSV-first source API: "
                + application.baseUri().resolve("/api/v1/csv-first-sources/{runId}"));
        System.out.println("Canonical import Finding manifest API: "
                + application.baseUri().resolve("/api/v1/canonical-imports/{importId}/findings.csv"));
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
            ApiKeyAuthenticator authenticator
    ) throws ReflectiveOperationException {
        // Transitional registration seam: CsvPlatformServer predates extension
        // contexts and keeps its HttpServer private. Keep the reflection isolated
        // here so the established adapter does not need a broad rewrite for these
        // narrow CSV-first and exact import-scoped read transports.
        Field serverField = CsvPlatformServer.class.getDeclaredField("server");
        serverField.setAccessible(true);
        HttpServer server = (HttpServer) serverField.get(application);
        server.createContext(
                "/api/v1/csv-first-enrichments",
                new CsvFirstEnrichmentHttpHandler(dataDirectory, maximumUploadBytes, authenticator)
        );
        server.createContext(
                "/api/v1/csv-first-sources",
                new CsvFirstSourceHttpHandler(dataDirectory, authenticator)
        );
        server.createContext(
                "/api/v1/canonical-imports",
                new CanonicalImportFindingHttpHandler(canonicalImportFindings, authenticator)
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

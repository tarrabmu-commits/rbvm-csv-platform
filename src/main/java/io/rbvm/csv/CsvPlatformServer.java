package io.rbvm.csv;

import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import io.rbvm.asset.ManagedAssetRegistry;
import io.rbvm.asset.ScannerManagedAssetLinkRegistry;
import io.rbvm.context.FindingBusinessServiceLinkRegistry;
import io.rbvm.context.FindingReachabilityScopeLinkRegistry;
import io.rbvm.domain.CaseActionCommand;
import io.rbvm.domain.CaseActionType;
import io.rbvm.domain.CaseNotFoundException;
import io.rbvm.domain.CaseQuery;
import io.rbvm.domain.CaseStatus;
import io.rbvm.domain.DomainCatalog;
import io.rbvm.domain.CaseWorkflowConflictException;
import io.rbvm.domain.InvalidCaseActionException;
import io.rbvm.domain.StaleCaseCursorException;
import io.rbvm.domain.VulnerabilityPriorityTier;
import io.rbvm.postgres.ApplicabilityFindingExporter;
import io.rbvm.postgres.ApplicabilityImportResult;
import io.rbvm.postgres.ApplicabilityImporter;
import io.rbvm.postgres.AssetContextEvidenceReader;
import io.rbvm.postgres.AssetContextImportResult;
import io.rbvm.postgres.AssetContextImporter;
import io.rbvm.postgres.BusinessImpactEvidenceReader;
import io.rbvm.postgres.BusinessImpactImportResult;
import io.rbvm.postgres.BusinessImpactImporter;
import io.rbvm.postgres.CanonicalProjectionFactory;
import io.rbvm.postgres.CanonicalProjectionFactory.RuntimeComponents;
import io.rbvm.postgres.CisaKevEvidenceReader;
import io.rbvm.postgres.CisaKevImportResult;
import io.rbvm.postgres.CisaKevImporter;
import io.rbvm.postgres.CvssV31EvidenceReader;
import io.rbvm.postgres.CvssV31ImportResult;
import io.rbvm.postgres.CvssV31Importer;
import io.rbvm.postgres.DerivedRiskResultRuntimeFactory;
import io.rbvm.postgres.EpssEvidenceReader;
import io.rbvm.postgres.EpssImportResult;
import io.rbvm.postgres.EpssImporter;
import io.rbvm.postgres.FormulaResultRuntimeFactory;
import io.rbvm.postgres.NetworkReachabilityEvidenceReader;
import io.rbvm.postgres.NetworkReachabilityImportResult;
import io.rbvm.postgres.NetworkReachabilityImporter;
import io.rbvm.security.ApiKeyAuthenticator;
import io.rbvm.security.ApiRole;
import io.rbvm.security.AuthPrincipal;
import io.rbvm.security.RequestRateLimiter;
import io.rbvm.security.RequestRateLimiter.Decision;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicLong;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Dependency-free HTTP adapter and local browser entry point. */
public final class CsvPlatformServer implements AutoCloseable {
    private static final Pattern IMPORT_PATH = Pattern.compile(
            "^/api/v1/csv-imports/([0-9a-fA-F-]{36})(/confirm)?$");
    private static final Pattern CASE_PATH = Pattern.compile(
            "^/api/v1/cases/([a-f0-9]{64})(/actions)?$");
    private static final Pattern CVE_PREFIX = Pattern.compile("^CVE-[0-9A-Z-]+$");
    private static final Pattern SOURCE_PROFILE_KEY = Pattern.compile("^[A-Za-z0-9._:-]+$");
    private static final long DEFAULT_MAXIMUM_UPLOAD_BYTES = 100L * 1024L * 1024L;
    private static final int MAXIMUM_ACTION_BODY_BYTES = 16 * 1024;

    private final HttpServer server;
    private final ExecutorService executor;
    private final CsvImportService imports;
    private final byte[] webUi;
    private final byte[] cvssUi;
    private final byte[] kevUi;
    private final byte[] epssUi;
    private final byte[] assetContextUi;
    private final byte[] networkReachabilityUi;
    private final byte[] businessImpactUi;
    private final byte[] managedAssetsUi;
    private final byte[] scannerManagedAssetLinksUi;
    private final byte[] frontendCss;
    private final byte[] frontendJs;
    private final ApiKeyAuthenticator authenticator;
    private final RequestRateLimiter rateLimiter;
    private final long maximumUploadBytes;
    private final Optional<ApplicabilityImporter> applicabilityImporter;
    private final Optional<ApplicabilityFindingExporter> applicabilityFindingExporter;
    private final Optional<CvssV31Importer> cvssV31Importer;
    private final Optional<CvssV31EvidenceReader> cvssV31EvidenceReader;
    private final Optional<CisaKevImporter> cisaKevImporter;
    private final Optional<CisaKevEvidenceReader> cisaKevEvidenceReader;
    private final Optional<EpssImporter> epssImporter;
    private final Optional<EpssEvidenceReader> epssEvidenceReader;
    private final Optional<AssetContextImporter> assetContextImporter;
    private final Optional<AssetContextEvidenceReader> assetContextEvidenceReader;
    private final Optional<NetworkReachabilityImporter> networkReachabilityImporter;
    private final Optional<NetworkReachabilityEvidenceReader> networkReachabilityEvidenceReader;
    private final Optional<BusinessImpactImporter> businessImpactImporter;
    private final Optional<BusinessImpactEvidenceReader> businessImpactEvidenceReader;
    private final Optional<ManagedAssetHttpRouter> managedAssetRouter;
    private Optional<ScannerManagedAssetLinkHttpRouter> scannerManagedAssetLinkRouter;
    private Optional<FindingContextAssociationHttpRouter> findingContextAssociationRouter = Optional.empty();
    private Optional<FormulaResultHttpRouter> formulaResultRouter = Optional.empty();
    private Optional<DerivedRiskResultHttpRouter> derivedRiskResultRouter = Optional.empty();
    private final Instant startedAt = Instant.now();
    private final AtomicLong requestsTotal = new AtomicLong();
    private final AtomicLong problemsTotal = new AtomicLong();
    private final AtomicLong authenticationFailuresTotal = new AtomicLong();
    private final AtomicLong forbiddenTotal = new AtomicLong();
    private final AtomicLong rateLimitedTotal = new AtomicLong();

    public CsvPlatformServer(String host, int port, Path dataDirectory, long maximumUploadBytes)
            throws IOException {
        this(
                host,
                port,
                dataDirectory,
                maximumUploadBytes,
                new NoopCanonicalProjection()
        );
    }

    public CsvPlatformServer(
            String host,
            int port,
            Path dataDirectory,
            long maximumUploadBytes,
            CanonicalProjection canonicalProjection
    ) throws IOException {
        if (port < 0 || port > 65_535) {
            throw new IllegalArgumentException("port must be between 0 and 65535");
        }
        this.imports = new CsvImportService(
                dataDirectory,
                maximumUploadBytes,
                canonicalProjection
        );
        this.authenticator = ApiKeyAuthenticator.disabled();
        this.rateLimiter = RequestRateLimiter.disabled();
        this.maximumUploadBytes = maximumUploadBytes;
        this.applicabilityImporter = Optional.empty();
        this.applicabilityFindingExporter = Optional.empty();
        this.cvssV31Importer = Optional.empty();
        this.cvssV31EvidenceReader = Optional.empty();
        this.cisaKevImporter = Optional.empty();
        this.cisaKevEvidenceReader = Optional.empty();
        this.epssImporter = Optional.empty();
        this.epssEvidenceReader = Optional.empty();
        this.assetContextImporter = Optional.empty();
        this.assetContextEvidenceReader = Optional.empty();
        this.networkReachabilityImporter = Optional.empty();
        this.networkReachabilityEvidenceReader = Optional.empty();
        this.businessImpactImporter = Optional.empty();
        this.businessImpactEvidenceReader = Optional.empty();
        this.managedAssetRouter = Optional.empty();
        this.scannerManagedAssetLinkRouter = Optional.empty();
        this.webUi = loadResource("/web/index.html");
        this.cvssUi = loadResource("/web/cvss-v31.html");
        this.kevUi = loadResource("/web/cisa-kev.html");
        this.epssUi = loadResource("/web/epss.html");
        this.assetContextUi = loadResource("/web/asset-context.html");
        this.networkReachabilityUi = loadResource("/web/network-reachability.html");
        this.businessImpactUi = loadResource("/web/business-impact.html");
        this.managedAssetsUi = loadResource("/web/assets.html");
        this.scannerManagedAssetLinksUi = loadResource("/web/asset-links.html");
        this.frontendCss = loadResource("/web/rbvm-ui.css");
        this.frontendJs = loadResource("/web/rbvm-ui.js");
        this.server = HttpServer.create(new InetSocketAddress(host, port), 32);
        int workers = Math.max(4, Math.min(16, Runtime.getRuntime().availableProcessors()));
        this.executor = Executors.newFixedThreadPool(workers);
        this.server.setExecutor(executor);
        this.server.createContext("/", this::route);
    }

    public CsvPlatformServer(
            String host,
            int port,
            Path dataDirectory,
            long maximumUploadBytes,
            CanonicalProjection canonicalProjection,
            DomainCatalog readCatalog
    ) throws IOException {
        this(host, port, dataDirectory, maximumUploadBytes, canonicalProjection, readCatalog,
                ApiKeyAuthenticator.disabled(), RequestRateLimiter.disabled());
    }

    public CsvPlatformServer(
            String host,
            int port,
            Path dataDirectory,
            long maximumUploadBytes,
            CanonicalProjection canonicalProjection,
            DomainCatalog readCatalog,
            ApiKeyAuthenticator authenticator
    ) throws IOException {
        this(host, port, dataDirectory, maximumUploadBytes, canonicalProjection, readCatalog,
                authenticator, RequestRateLimiter.disabled());
    }

    public CsvPlatformServer(
            String host,
            int port,
            Path dataDirectory,
            long maximumUploadBytes,
            CanonicalProjection canonicalProjection,
            DomainCatalog readCatalog,
            ApiKeyAuthenticator authenticator,
            RequestRateLimiter rateLimiter
    ) throws IOException {
        this(
                host,
                port,
                dataDirectory,
                maximumUploadBytes,
                canonicalProjection,
                readCatalog,
                Optional.empty(),
                Optional.empty(),
                Optional.empty(),
                Optional.empty(),
                authenticator,
                rateLimiter
        );
    }

    public CsvPlatformServer(
            String host,
            int port,
            Path dataDirectory,
            long maximumUploadBytes,
            CanonicalProjection canonicalProjection,
            DomainCatalog readCatalog,
            Optional<ApplicabilityImporter> applicabilityImporter,
            Optional<ApplicabilityFindingExporter> applicabilityFindingExporter,
            ApiKeyAuthenticator authenticator,
            RequestRateLimiter rateLimiter
    ) throws IOException {
        this(
                host,
                port,
                dataDirectory,
                maximumUploadBytes,
                canonicalProjection,
                readCatalog,
                applicabilityImporter,
                applicabilityFindingExporter,
                Optional.empty(),
                Optional.empty(),
                authenticator,
                rateLimiter
        );
    }

    public CsvPlatformServer(
            String host,
            int port,
            Path dataDirectory,
            long maximumUploadBytes,
            CanonicalProjection canonicalProjection,
            DomainCatalog readCatalog,
            Optional<ApplicabilityImporter> applicabilityImporter,
            Optional<ApplicabilityFindingExporter> applicabilityFindingExporter,
            Optional<CvssV31Importer> cvssV31Importer,
            Optional<CvssV31EvidenceReader> cvssV31EvidenceReader,
            ApiKeyAuthenticator authenticator,
            RequestRateLimiter rateLimiter
    ) throws IOException {
        this(
                host,
                port,
                dataDirectory,
                maximumUploadBytes,
                canonicalProjection,
                readCatalog,
                applicabilityImporter,
                applicabilityFindingExporter,
                cvssV31Importer,
                cvssV31EvidenceReader,
                Optional.empty(),
                Optional.empty(),
                authenticator,
                rateLimiter
        );
    }

    /** Backward-compatible runtime constructor through the CISA KEV V11 capability layer. */
    public CsvPlatformServer(
            String host,
            int port,
            Path dataDirectory,
            long maximumUploadBytes,
            CanonicalProjection canonicalProjection,
            DomainCatalog readCatalog,
            Optional<ApplicabilityImporter> applicabilityImporter,
            Optional<ApplicabilityFindingExporter> applicabilityFindingExporter,
            Optional<CvssV31Importer> cvssV31Importer,
            Optional<CvssV31EvidenceReader> cvssV31EvidenceReader,
            Optional<CisaKevImporter> cisaKevImporter,
            Optional<CisaKevEvidenceReader> cisaKevEvidenceReader,
            ApiKeyAuthenticator authenticator,
            RequestRateLimiter rateLimiter
    ) throws IOException {
        this(
                host,
                port,
                dataDirectory,
                maximumUploadBytes,
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
                authenticator,
                rateLimiter
        );
    }

    /** Backward-compatible runtime constructor through the EPSS V12 capability layer. */
    public CsvPlatformServer(
            String host,
            int port,
            Path dataDirectory,
            long maximumUploadBytes,
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
            ApiKeyAuthenticator authenticator,
            RequestRateLimiter rateLimiter
    ) throws IOException {
        this(
                host,
                port,
                dataDirectory,
                maximumUploadBytes,
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
                Optional.empty(),
                authenticator,
                rateLimiter
        );
    }

    /** Backward-compatible runtime constructor through the Asset Context V13 capability layer. */
    public CsvPlatformServer(
            String host,
            int port,
            Path dataDirectory,
            long maximumUploadBytes,
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
            ApiKeyAuthenticator authenticator,
            RequestRateLimiter rateLimiter
    ) throws IOException {
        this(
                host,
                port,
                dataDirectory,
                maximumUploadBytes,
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
                Optional.empty(),
                Optional.empty(),
                authenticator,
                rateLimiter
        );
    }

    /** Backward-compatible runtime constructor through the Network Reachability V14 capability layer. */
    public CsvPlatformServer(
            String host,
            int port,
            Path dataDirectory,
            long maximumUploadBytes,
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
            ApiKeyAuthenticator authenticator,
            RequestRateLimiter rateLimiter
    ) throws IOException {
        this(
                host, port, dataDirectory, maximumUploadBytes, canonicalProjection, readCatalog,
                applicabilityImporter, applicabilityFindingExporter,
                cvssV31Importer, cvssV31EvidenceReader,
                cisaKevImporter, cisaKevEvidenceReader,
                epssImporter, epssEvidenceReader,
                assetContextImporter, assetContextEvidenceReader,
                networkReachabilityImporter, networkReachabilityEvidenceReader,
                Optional.empty(), Optional.empty(), authenticator, rateLimiter
        );
    }

    public CsvPlatformServer(
            String host,
            int port,
            Path dataDirectory,
            long maximumUploadBytes,
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
            ApiKeyAuthenticator authenticator,
            RequestRateLimiter rateLimiter
    ) throws IOException {
        this(
                host,
                port,
                dataDirectory,
                maximumUploadBytes,
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
                Optional.empty(),
                authenticator,
                rateLimiter
        );
    }

    /** Runtime constructor through the V18 customer-managed asset registry capability. */
    public CsvPlatformServer(
            String host,
            int port,
            Path dataDirectory,
            long maximumUploadBytes,
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
            Optional<ManagedAssetRegistry> managedAssetRegistry,
            ApiKeyAuthenticator authenticator,
            RequestRateLimiter rateLimiter
    ) throws IOException {
        if (port < 0 || port > 65_535) {
            throw new IllegalArgumentException("port must be between 0 and 65535");
        }
        DomainCatalog mutationCatalog = "POSTGRESQL".equals(readCatalog.backend())
                ? new io.rbvm.domain.InMemoryDomainCatalog()
                : readCatalog;
        this.imports = new CsvImportService(
                dataDirectory,
                maximumUploadBytes,
                java.time.Clock.systemUTC(),
                mutationCatalog,
                readCatalog,
                canonicalProjection
        );
        this.authenticator = Objects.requireNonNull(authenticator, "authenticator");
        this.rateLimiter = Objects.requireNonNull(rateLimiter, "rateLimiter");
        this.maximumUploadBytes = maximumUploadBytes;
        this.applicabilityImporter = Objects.requireNonNull(
                applicabilityImporter,
                "applicabilityImporter"
        );
        this.applicabilityFindingExporter = Objects.requireNonNull(
                applicabilityFindingExporter,
                "applicabilityFindingExporter"
        );
        this.cvssV31Importer = Objects.requireNonNull(cvssV31Importer, "cvssV31Importer");
        this.cvssV31EvidenceReader = Objects.requireNonNull(
                cvssV31EvidenceReader,
                "cvssV31EvidenceReader"
        );
        this.cisaKevImporter = Objects.requireNonNull(cisaKevImporter, "cisaKevImporter");
        this.cisaKevEvidenceReader = Objects.requireNonNull(
                cisaKevEvidenceReader,
                "cisaKevEvidenceReader"
        );
        this.epssImporter = Objects.requireNonNull(epssImporter, "epssImporter");
        this.epssEvidenceReader = Objects.requireNonNull(epssEvidenceReader, "epssEvidenceReader");
        this.assetContextImporter = Objects.requireNonNull(
                assetContextImporter,
                "assetContextImporter"
        );
        this.assetContextEvidenceReader = Objects.requireNonNull(
                assetContextEvidenceReader,
                "assetContextEvidenceReader"
        );
        this.networkReachabilityImporter = Objects.requireNonNull(
                networkReachabilityImporter,
                "networkReachabilityImporter"
        );
        this.networkReachabilityEvidenceReader = Objects.requireNonNull(
                networkReachabilityEvidenceReader,
                "networkReachabilityEvidenceReader"
        );
        this.businessImpactImporter = Objects.requireNonNull(
                businessImpactImporter,
                "businessImpactImporter"
        );
        this.businessImpactEvidenceReader = Objects.requireNonNull(
                businessImpactEvidenceReader,
                "businessImpactEvidenceReader"
        );
        this.managedAssetRouter = Objects.requireNonNull(
                managedAssetRegistry,
                "managedAssetRegistry"
        ).map(ManagedAssetApi::new).map(ManagedAssetHttpRouter::new);
        this.scannerManagedAssetLinkRouter = Optional.empty();
        this.webUi = loadResource("/web/index.html");
        this.cvssUi = loadResource("/web/cvss-v31.html");
        this.kevUi = loadResource("/web/cisa-kev.html");
        this.epssUi = loadResource("/web/epss.html");
        this.assetContextUi = loadResource("/web/asset-context.html");
        this.networkReachabilityUi = loadResource("/web/network-reachability.html");
        this.businessImpactUi = loadResource("/web/business-impact.html");
        this.managedAssetsUi = loadResource("/web/assets.html");
        this.scannerManagedAssetLinksUi = loadResource("/web/asset-links.html");
        this.frontendCss = loadResource("/web/rbvm-ui.css");
        this.frontendJs = loadResource("/web/rbvm-ui.js");
        this.server = HttpServer.create(new InetSocketAddress(host, port), 32);
        int workers = Math.max(4, Math.min(16, Runtime.getRuntime().availableProcessors()));
        this.executor = Executors.newFixedThreadPool(workers);
        this.server.setExecutor(executor);
        this.server.createContext("/", this::route);
    }

    /** Runtime constructor through the V23 scanner-managed-asset link API capability. */
    public CsvPlatformServer(
            String host,
            int port,
            Path dataDirectory,
            long maximumUploadBytes,
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
            Optional<ManagedAssetRegistry> managedAssetRegistry,
            Optional<ScannerManagedAssetLinkRegistry> scannerManagedAssetLinkRegistry,
            ApiKeyAuthenticator authenticator,
            RequestRateLimiter rateLimiter
    ) throws IOException {
        this(
                host,
                port,
                dataDirectory,
                maximumUploadBytes,
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
                managedAssetRegistry,
                authenticator,
                rateLimiter
        );
        this.scannerManagedAssetLinkRouter = Objects.requireNonNull(
                scannerManagedAssetLinkRegistry,
                "scannerManagedAssetLinkRegistry"
        ).map(ScannerManagedAssetLinkApi::new).map(ScannerManagedAssetLinkHttpRouter::new);
    }

    /** Enable the V21 explicit Finding-context association API before the server is started. */
    public void enableFindingContextAssociationApi(
            FindingReachabilityScopeLinkRegistry reachabilityLinks,
            FindingBusinessServiceLinkRegistry businessServiceLinks
    ) {
        if (findingContextAssociationRouter.isPresent()) {
            throw new IllegalStateException("Finding-context association API is already enabled");
        }
        findingContextAssociationRouter = Optional.of(new FindingContextAssociationHttpRouter(
                new FindingReachabilityScopeLinkApi(
                        Objects.requireNonNull(reachabilityLinks, "reachabilityLinks")
                ),
                new FindingBusinessServiceLinkApi(
                        Objects.requireNonNull(businessServiceLinks, "businessServiceLinks")
                )
        ));
    }

    /** Enable the replay-verified V23 Formula Result read API before the server is started. */
    public void enableFormulaResultApi(FormulaResultApi api) {
        if (formulaResultRouter.isPresent()) {
            throw new IllegalStateException("Formula Result API is already enabled");
        }
        formulaResultRouter = Optional.of(new FormulaResultHttpRouter(
                Objects.requireNonNull(api, "api")
        ));
    }

    /** Enable the replay-verified V24 derived risk result API before the server is started. */
    public void enableDerivedRiskResultApi(DerivedRiskResultApi api) {
        if (derivedRiskResultRouter.isPresent()) {
            throw new IllegalStateException("Derived Risk Result API is already enabled");
        }
        derivedRiskResultRouter = Optional.of(new DerivedRiskResultHttpRouter(
                Objects.requireNonNull(api, "api")
        ));
    }

    public void start() {
        server.start();
    }

    public int port() {
        return server.getAddress().getPort();
    }

    public URI baseUri() {
        String host = server.getAddress().getHostString();
        return URI.create("http://" + host + ':' + port() + '/');
    }

    @Override
    public void close() {
        server.stop(0);
        executor.shutdownNow();
        imports.close();
    }

    private void route(HttpExchange exchange) throws IOException {
        requestsTotal.incrementAndGet();
        String correlationId = UUID.randomUUID().toString();
        try {
            addCommonHeaders(exchange.getResponseHeaders(), correlationId);
            String path = exchange.getRequestURI().getPath();
            String method = exchange.getRequestMethod().toUpperCase(Locale.ROOT);

            if ("/ui/rbvm-ui.css".equals(path)) {
                requireMethod(exchange, method, "GET");
                sendBytes(exchange, 200, "text/css; charset=utf-8", frontendCss);
                return;
            }
            if ("/ui/rbvm-ui.js".equals(path)) {
                requireMethod(exchange, method, "GET");
                sendBytes(exchange, 200, "text/javascript; charset=utf-8", frontendJs);
                return;
            }
            if ("/".equals(path)) {
                requireMethod(exchange, method, "GET");
                sendBytes(exchange, 200, "text/html; charset=utf-8", webUi);
                return;
            }
            if ("/cvss".equals(path) || "/cvss/".equals(path)) {
                requireMethod(exchange, method, "GET");
                sendBytes(exchange, 200, "text/html; charset=utf-8", cvssUi);
                return;
            }
            if ("/kev".equals(path) || "/kev/".equals(path)) {
                requireMethod(exchange, method, "GET");
                sendBytes(exchange, 200, "text/html; charset=utf-8", kevUi);
                return;
            }
            if ("/epss".equals(path) || "/epss/".equals(path)) {
                requireMethod(exchange, method, "GET");
                sendBytes(exchange, 200, "text/html; charset=utf-8", epssUi);
                return;
            }
            if ("/asset-context".equals(path) || "/asset-context/".equals(path)) {
                requireMethod(exchange, method, "GET");
                sendBytes(exchange, 200, "text/html; charset=utf-8", assetContextUi);
                return;
            }
            if ("/reachability".equals(path) || "/reachability/".equals(path)) {
                requireMethod(exchange, method, "GET");
                sendBytes(exchange, 200, "text/html; charset=utf-8", networkReachabilityUi);
                return;
            }
            if ("/business-impact".equals(path) || "/business-impact/".equals(path)) {
                requireMethod(exchange, method, "GET");
                sendBytes(exchange, 200, "text/html; charset=utf-8", businessImpactUi);
                return;
            }
            if ("/assets".equals(path) || "/assets/".equals(path)) {
                requireMethod(exchange, method, "GET");
                sendBytes(exchange, 200, "text/html; charset=utf-8", managedAssetsUi);
                return;
            }
            if ("/asset-links".equals(path) || "/asset-links/".equals(path)) {
                requireMethod(exchange, method, "GET");
                sendBytes(exchange, 200, "text/html; charset=utf-8", scannerManagedAssetLinksUi);
                return;
            }
            if ("/api/v1/health".equals(path)) {
                requireMethod(exchange, method, "GET");
                authorize(exchange, ApiRole.VIEWER);
                sendJson(exchange, 200, healthView());
                return;
            }
            if ("/api/v1/live".equals(path)) {
                requireMethod(exchange, method, "GET");
                sendJson(exchange, 200, Map.of("status", "UP", "startedAt", startedAt.toString()));
                return;
            }
            if ("/api/v1/ready".equals(path)) {
                requireMethod(exchange, method, "GET");
                Map<String, Object> readiness = imports.health();
                int status = "UP".equals(readiness.get("status")) ? 200 : 503;
                sendJson(exchange, status, Map.of(
                        "status", readiness.get("status"),
                        "checkedAt", Instant.now().toString()
                ));
                return;
            }
            if ("/api/v1/metrics".equals(path)) {
                requireMethod(exchange, method, "GET");
                authorize(exchange, ApiRole.VIEWER);
                sendMetrics(exchange);
                return;
            }
            if ("/api/v1/catalog/summary".equals(path)) {
                requireMethod(exchange, method, "GET");
                authorize(exchange, ApiRole.VIEWER);
                sendJson(exchange, 200, imports.catalogSummary());
                return;
            }
            if (ManagedAssetHttpRouter.inNamespace(path)) {
                if (!ManagedAssetHttpRouter.handles(path)) {
                    throw new HttpProblem(
                            404,
                            "NOT_FOUND",
                            "The requested managed asset route does not exist"
                    );
                }
                ApiRole requiredRole = ManagedAssetHttpRouter.requiredRole(exchange, method);
                AuthPrincipal principal = authorize(exchange, requiredRole);
                ManagedAssetHttpRouter managedAssets = managedAssetRouter.orElseThrow(() ->
                        new HttpProblem(
                                503,
                                "MANAGED_ASSET_PERSISTENCE_UNAVAILABLE",
                                "Managed asset API requires PostgreSQL schema version 18 or newer"
                        ));
                managedAssets.routeAuthorized(exchange, method, principal);
                return;
            }
            if (ScannerManagedAssetLinkHttpRouter.inNamespace(path)) {
                if (!ScannerManagedAssetLinkHttpRouter.handles(path)) {
                    throw new HttpProblem(
                            404,
                            "NOT_FOUND",
                            "The requested scanner-managed-asset link route does not exist"
                    );
                }
                ApiRole requiredRole = ScannerManagedAssetLinkHttpRouter.requiredRole(exchange, method);
                AuthPrincipal principal = authorize(exchange, requiredRole);
                ScannerManagedAssetLinkHttpRouter links = scannerManagedAssetLinkRouter.orElseThrow(() ->
                        new HttpProblem(
                                503,
                                "SCANNER_MANAGED_ASSET_LINK_PERSISTENCE_UNAVAILABLE",
                                "Scanner-managed-asset link API requires PostgreSQL schema version 19 or newer"
                        ));
                links.routeAuthorized(exchange, method, principal);
                return;
            }
            if (FindingContextAssociationHttpRouter.inNamespace(path)) {
                if (!FindingContextAssociationHttpRouter.handles(path)) {
                    throw new HttpProblem(
                            404,
                            "NOT_FOUND",
                            "The requested Finding-context association route does not exist"
                    );
                }
                ApiRole requiredRole = FindingContextAssociationHttpRouter.requiredRole(exchange, method);
                AuthPrincipal principal = authorize(exchange, requiredRole);
                FindingContextAssociationHttpRouter associations =
                        findingContextAssociationRouter.orElseThrow(() -> new HttpProblem(
                                503,
                                "FINDING_CONTEXT_ASSOCIATION_PERSISTENCE_UNAVAILABLE",
                                "Finding-context association API requires PostgreSQL schema version 21 or newer"
                        ));
                associations.routeAuthorized(exchange, method, principal);
                return;
            }
            if (FormulaResultHttpRouter.inNamespace(path)) {
                if (!FormulaResultHttpRouter.handles(path)) {
                    throw new HttpProblem(
                            404,
                            "NOT_FOUND",
                            "The requested Formula result route does not exist"
                    );
                }
                ApiRole requiredRole = FormulaResultHttpRouter.requiredRole(exchange, method);
                AuthPrincipal principal = authorize(exchange, requiredRole);
                FormulaResultHttpRouter formulaResults = formulaResultRouter.orElseThrow(() ->
                        new HttpProblem(
                                503,
                                "FORMULA_RESULT_PERSISTENCE_UNAVAILABLE",
                                "Formula Result API requires PostgreSQL schema version 23 or newer"
                        ));
                formulaResults.routeAuthorized(exchange, method, principal);
                return;
            }
            if (DerivedRiskResultHttpRouter.inNamespace(path)) {
                if (!DerivedRiskResultHttpRouter.handles(path)) {
                    throw new HttpProblem(
                            404,
                            "NOT_FOUND",
                            "The requested derived risk result route does not exist"
                    );
                }
                ApiRole requiredRole = DerivedRiskResultHttpRouter.requiredRole(exchange, method);
                AuthPrincipal principal = authorize(exchange, requiredRole);
                DerivedRiskResultHttpRouter derivedRiskResults = derivedRiskResultRouter.orElseThrow(() ->
                        new HttpProblem(
                                503,
                                "DERIVED_RISK_RESULT_PERSISTENCE_UNAVAILABLE",
                                "Derived Risk Result API requires PostgreSQL schema version 24 or newer"
                        ));
                derivedRiskResults.routeAuthorized(exchange, method, principal);
                return;
            }
            if ("/api/v1/cases".equals(path)) {
                requireMethod(exchange, method, "GET");
                authorize(exchange, ApiRole.VIEWER);
                sendJson(exchange, 200, imports.queryCases(parseCaseQuery(exchange.getRequestURI())));
                return;
            }
            if ("/api/v1/applicability-findings.csv".equals(path)) {
                requireMethod(exchange, method, "GET");
                authorize(exchange, ApiRole.VIEWER);
                exportApplicabilityFindings(exchange);
                return;
            }
            if ("/api/v1/applicability-imports".equals(path)) {
                requireMethod(exchange, method, "POST");
                authorize(exchange, ApiRole.OPERATOR);
                createApplicabilityImport(exchange);
                return;
            }
            if ("/api/v1/cvss-v31-evidence".equals(path)) {
                requireMethod(exchange, method, "GET");
                authorize(exchange, ApiRole.VIEWER);
                readCvssV31Evidence(exchange);
                return;
            }
            if ("/api/v1/cvss-v31-imports".equals(path)) {
                requireMethod(exchange, method, "POST");
                authorize(exchange, ApiRole.OPERATOR);
                createCvssV31Import(exchange);
                return;
            }
            if ("/api/v1/cisa-kev-evidence".equals(path)) {
                requireMethod(exchange, method, "GET");
                authorize(exchange, ApiRole.VIEWER);
                readCisaKevEvidence(exchange);
                return;
            }
            if ("/api/v1/cisa-kev-imports".equals(path)) {
                requireMethod(exchange, method, "POST");
                authorize(exchange, ApiRole.OPERATOR);
                createCisaKevImport(exchange);
                return;
            }
            if ("/api/v1/epss-evidence".equals(path)) {
                requireMethod(exchange, method, "GET");
                authorize(exchange, ApiRole.VIEWER);
                readEpssEvidence(exchange);
                return;
            }
            if ("/api/v1/epss-imports".equals(path)) {
                requireMethod(exchange, method, "POST");
                authorize(exchange, ApiRole.OPERATOR);
                createEpssImport(exchange);
                return;
            }
            if ("/api/v1/asset-context-evidence".equals(path)) {
                requireMethod(exchange, method, "GET");
                authorize(exchange, ApiRole.VIEWER);
                readAssetContextEvidence(exchange);
                return;
            }
            if ("/api/v1/asset-context-imports".equals(path)) {
                requireMethod(exchange, method, "POST");
                authorize(exchange, ApiRole.OPERATOR);
                createAssetContextImport(exchange);
                return;
            }
            if ("/api/v1/network-reachability-evidence".equals(path)) {
                requireMethod(exchange, method, "GET");
                authorize(exchange, ApiRole.VIEWER);
                readNetworkReachabilityEvidence(exchange);
                return;
            }
            if ("/api/v1/network-reachability-imports".equals(path)) {
                requireMethod(exchange, method, "POST");
                authorize(exchange, ApiRole.OPERATOR);
                createNetworkReachabilityImport(exchange);
                return;
            }
            if ("/api/v1/business-impact-evidence".equals(path)) {
                requireMethod(exchange, method, "GET");
                authorize(exchange, ApiRole.VIEWER);
                readBusinessImpactEvidence(exchange);
                return;
            }
            if ("/api/v1/business-impact-imports".equals(path)) {
                requireMethod(exchange, method, "POST");
                authorize(exchange, ApiRole.OPERATOR);
                createBusinessImpactImport(exchange);
                return;
            }
            if ("/api/v1/csv-imports".equals(path)) {
                requireMethod(exchange, method, "POST");
                authorize(exchange, ApiRole.OPERATOR);
                createImport(exchange);
                return;
            }

            Matcher matcher = IMPORT_PATH.matcher(path);
            if (matcher.matches()) {
                UUID importId;
                try {
                    importId = UUID.fromString(matcher.group(1));
                } catch (IllegalArgumentException exception) {
                    throw new HttpProblem(400, "INVALID_IMPORT_ID", "Invalid import identifier");
                }
                if (matcher.group(2) == null) {
                    requireMethod(exchange, method, "GET");
                    authorize(exchange, ApiRole.VIEWER);
                    getImport(exchange, importId);
                } else {
                    requireMethod(exchange, method, "POST");
                    authorize(exchange, ApiRole.OPERATOR);
                    confirmImport(exchange, importId);
                }
                return;
            }

            Matcher caseMatcher = CASE_PATH.matcher(path);
            if (caseMatcher.matches()) {
                String caseId = caseMatcher.group(1);
                if (caseMatcher.group(2) == null) {
                    requireMethod(exchange, method, "GET");
                    authorize(exchange, ApiRole.VIEWER);
                    getCase(exchange, caseId);
                } else {
                    requireMethod(exchange, method, "POST");
                    AuthPrincipal principal = authorize(exchange, ApiRole.OPERATOR);
                    actOnCase(exchange, caseId, principal);
                }
                return;
            }

            throw new HttpProblem(404, "NOT_FOUND", "The requested route does not exist");
        } catch (DerivedRiskResultApi.ApiProblem problem) {
            problemsTotal.incrementAndGet();
            sendProblem(exchange, problem.status(), problem.code(), problem.getMessage(), correlationId);
        } catch (FormulaResultApi.ApiProblem problem) {
            problemsTotal.incrementAndGet();
            sendProblem(exchange, problem.status(), problem.code(), problem.getMessage(), correlationId);
        } catch (ManagedAssetApi.ApiProblem problem) {
            problemsTotal.incrementAndGet();
            sendProblem(exchange, problem.status(), problem.code(), problem.getMessage(), correlationId);
        } catch (HttpProblem problem) {
            problemsTotal.incrementAndGet();
            sendProblem(exchange, problem.status(), problem.code(), problem.getMessage(), correlationId);
        } catch (CsvImportService.UploadTooLargeException exception) {
            problemsTotal.incrementAndGet();
            sendProblem(exchange, 413, "UPLOAD_TOO_LARGE", exception.getMessage(), correlationId);
        } catch (CsvImportService.IdempotencyConflictException exception) {
            problemsTotal.incrementAndGet();
            sendProblem(exchange, 409, "IDEMPOTENCY_CONFLICT", exception.getMessage(), correlationId);
        } catch (CsvImportService.InvalidImportStateException exception) {
            problemsTotal.incrementAndGet();
            sendProblem(exchange, 409, "INVALID_IMPORT_STATE", exception.getMessage(), correlationId);
        } catch (CsvImportService.ImportNotFoundException exception) {
            problemsTotal.incrementAndGet();
            sendProblem(exchange, 404, "IMPORT_NOT_FOUND", exception.getMessage(), correlationId);
        } catch (CsvImportService.InvalidRequestException exception) {
            problemsTotal.incrementAndGet();
            sendProblem(exchange, 400, "INVALID_REQUEST", exception.getMessage(), correlationId);
        } catch (CaseNotFoundException exception) {
            problemsTotal.incrementAndGet();
            sendProblem(exchange, 404, "CASE_NOT_FOUND", exception.getMessage(), correlationId);
        } catch (InvalidCaseActionException exception) {
            problemsTotal.incrementAndGet();
            sendProblem(exchange, 400, "INVALID_CASE_REQUEST", exception.getMessage(), correlationId);
        } catch (StaleCaseCursorException exception) {
            problemsTotal.incrementAndGet();
            sendProblem(exchange, 409, "STALE_CASE_CURSOR", exception.getMessage(), correlationId);
        } catch (CaseWorkflowConflictException exception) {
            problemsTotal.incrementAndGet();
            sendProblem(exchange, 409, "CASE_WORKFLOW_CONFLICT", exception.getMessage(), correlationId);
        } catch (CsvContractException exception) {
            problemsTotal.incrementAndGet();
            sendProblem(exchange, 422, "CSV_CONTRACT_REJECTED", exception.getMessage(), correlationId);
        } catch (Exception exception) {
            problemsTotal.incrementAndGet();
            exception.printStackTrace(System.err);
            sendProblem(exchange, 500, "INTERNAL_ERROR", "The request could not be completed", correlationId);
        } finally {
            exchange.close();
        }
    }

    private Map<String, Object> healthView() {
        Map<String, Object> health = new LinkedHashMap<>(imports.health());
        health.put("applicability", Map.of(
                "importEnabled", applicabilityImporter.isPresent(),
                "findingReferenceExportEnabled", applicabilityFindingExporter.isPresent()
        ));
        health.put("cvssV31", Map.of(
                "importEnabled", cvssV31Importer.isPresent(),
                "evidenceReadEnabled", cvssV31EvidenceReader.isPresent()
        ));
        health.put("cisaKev", Map.of(
                "importEnabled", cisaKevImporter.isPresent(),
                "evidenceReadEnabled", cisaKevEvidenceReader.isPresent()
        ));
        health.put("epss", Map.of(
                "importEnabled", epssImporter.isPresent(),
                "evidenceReadEnabled", epssEvidenceReader.isPresent()
        ));
        health.put("assetContext", Map.of(
                "importEnabled", assetContextImporter.isPresent(),
                "evidenceReadEnabled", assetContextEvidenceReader.isPresent()
        ));
        health.put("networkReachability", Map.of(
                "importEnabled", networkReachabilityImporter.isPresent(),
                "evidenceReadEnabled", networkReachabilityEvidenceReader.isPresent()
        ));
        health.put("businessImpact", Map.of(
                "importEnabled", businessImpactImporter.isPresent(),
                "evidenceReadEnabled", businessImpactEvidenceReader.isPresent()
        ));
        health.put("managedAssets", Map.of(
                "readEnabled", managedAssetRouter.isPresent(),
                "writeEnabled", managedAssetRouter.isPresent(),
                "historyReadEnabled", managedAssetRouter.isPresent()
        ));
        health.put("scannerManagedAssetLinks", Map.of(
                "readEnabled", scannerManagedAssetLinkRouter.isPresent(),
                "writeEnabled", scannerManagedAssetLinkRouter.isPresent(),
                "historyReadEnabled", scannerManagedAssetLinkRouter.isPresent()
        ));
        health.put("findingContextAssociations", Map.of(
                "readEnabled", findingContextAssociationRouter.isPresent(),
                "writeEnabled", findingContextAssociationRouter.isPresent(),
                "historyReadEnabled", findingContextAssociationRouter.isPresent()
        ));
        health.put("formulaResults", Map.of(
                "readEnabled", formulaResultRouter.isPresent(),
                "replayVerified", formulaResultRouter.isPresent()
        ));
        health.put("derivedRiskResults", Map.of(
                "catalogEnabled", derivedRiskResultRouter.isPresent(),
                "readEnabled", derivedRiskResultRouter.isPresent(),
                "materializationEnabled", derivedRiskResultRouter.isPresent(),
                "replayVerified", derivedRiskResultRouter.isPresent()
        ));
        return health;
    }

    private void exportApplicabilityFindings(HttpExchange exchange) throws IOException {
        ApplicabilityFindingExporter exporter = applicabilityFindingExporter.orElseThrow(() ->
                new HttpProblem(
                        503,
                        "APPLICABILITY_PERSISTENCE_UNAVAILABLE",
                        "Applicability finding references require PostgreSQL schema version 9 or newer"
                ));
        byte[] csv = exporter.exportCsv();
        exchange.getResponseHeaders().set(
                "Content-Disposition",
                "attachment; filename=\"rbvm-applicability-findings.csv\""
        );
        sendBytes(exchange, 200, "text/csv; charset=utf-8", csv);
    }

    private void createApplicabilityImport(HttpExchange exchange) throws IOException {
        ApplicabilityImporter importer = applicabilityImporter.orElseThrow(() ->
                new HttpProblem(
                        503,
                        "APPLICABILITY_PERSISTENCE_UNAVAILABLE",
                        "Applicability import requires PostgreSQL schema version 9 or newer"
                ));
        String contentType = exchange.getRequestHeaders().getFirst("Content-Type");
        if (!isCsvContentType(contentType)) {
            throw new HttpProblem(
                    415,
                    "UNSUPPORTED_MEDIA_TYPE",
                    "Content-Type must be text/csv, application/csv, or application/octet-stream"
            );
        }
        long contentLength = parseContentLength(exchange.getRequestHeaders().getFirst("Content-Length"));
        if (contentLength > maximumUploadBytes) {
            throw new HttpProblem(
                    413,
                    "UPLOAD_TOO_LARGE",
                    "Applicability CSV exceeds the configured upload limit"
            );
        }

        Path staged = Files.createTempFile("rbvm-applicability-upload-", ".csv");
        try {
            try (InputStream body = exchange.getRequestBody();
                 OutputStream output = Files.newOutputStream(staged)) {
                copyBounded(body, output, maximumUploadBytes, "Applicability CSV");
            }
            ApplicabilityImportResult result = importer.importFile(staged);
            sendJson(exchange, 200, result.toMap());
        } finally {
            Files.deleteIfExists(staged);
        }
    }

    private void readCvssV31Evidence(HttpExchange exchange) throws IOException {
        CvssV31EvidenceReader reader = cvssV31EvidenceReader.orElseThrow(() ->
                new HttpProblem(
                        503,
                        "CVSS_V31_PERSISTENCE_UNAVAILABLE",
                        "CVSS v3.1 evidence reads require PostgreSQL schema version 10 or newer"
                ));
        CvssEvidenceQuery query = parseCvssEvidenceQuery(exchange.getRequestURI());
        sendJson(exchange, 200, reader.currentEvidence(query.limit(), query.cvePrefix()));
    }

    private void createCvssV31Import(HttpExchange exchange) throws IOException {
        CvssV31Importer importer = cvssV31Importer.orElseThrow(() ->
                new HttpProblem(
                        503,
                        "CVSS_V31_PERSISTENCE_UNAVAILABLE",
                        "CVSS v3.1 import requires PostgreSQL schema version 10 or newer"
                ));
        String contentType = exchange.getRequestHeaders().getFirst("Content-Type");
        if (!isCsvContentType(contentType)) {
            throw new HttpProblem(
                    415,
                    "UNSUPPORTED_MEDIA_TYPE",
                    "Content-Type must be text/csv, application/csv, or application/octet-stream"
            );
        }
        long contentLength = parseContentLength(exchange.getRequestHeaders().getFirst("Content-Length"));
        if (contentLength > maximumUploadBytes) {
            throw new HttpProblem(
                    413,
                    "UPLOAD_TOO_LARGE",
                    "CVSS v3.1 CSV exceeds the configured upload limit"
            );
        }

        Path staged = Files.createTempFile("rbvm-cvss-v31-upload-", ".csv");
        try {
            try (InputStream body = exchange.getRequestBody();
                 OutputStream output = Files.newOutputStream(staged)) {
                copyBounded(body, output, maximumUploadBytes, "CVSS v3.1 CSV");
            }
            CvssV31ImportResult result = importer.importFile(staged);
            sendJson(exchange, 200, result.toMap());
        } finally {
            Files.deleteIfExists(staged);
        }
    }

    private void readCisaKevEvidence(HttpExchange exchange) throws IOException {
        CisaKevEvidenceReader reader = cisaKevEvidenceReader.orElseThrow(() ->
                new HttpProblem(
                        503,
                        "CISA_KEV_PERSISTENCE_UNAVAILABLE",
                        "CISA KEV evidence reads require PostgreSQL schema version 11 or newer"
                ));
        CisaKevEvidenceQuery query = parseCisaKevEvidenceQuery(exchange.getRequestURI());
        sendJson(exchange, 200, reader.currentEvidence(query.limit(), query.cvePrefix()));
    }

    private void createCisaKevImport(HttpExchange exchange) throws IOException {
        CisaKevImporter importer = cisaKevImporter.orElseThrow(() ->
                new HttpProblem(
                        503,
                        "CISA_KEV_PERSISTENCE_UNAVAILABLE",
                        "CISA KEV import requires PostgreSQL schema version 11 or newer"
                ));
        String contentType = exchange.getRequestHeaders().getFirst("Content-Type");
        if (!isCsvContentType(contentType)) {
            throw new HttpProblem(
                    415,
                    "UNSUPPORTED_MEDIA_TYPE",
                    "Content-Type must be text/csv, application/csv, or application/octet-stream"
            );
        }
        long contentLength = parseContentLength(exchange.getRequestHeaders().getFirst("Content-Length"));
        if (contentLength > maximumUploadBytes) {
            throw new HttpProblem(
                    413,
                    "UPLOAD_TOO_LARGE",
                    "CISA KEV CSV exceeds the configured upload limit"
            );
        }

        Path staged = Files.createTempFile("rbvm-cisa-kev-upload-", ".csv");
        try {
            try (InputStream body = exchange.getRequestBody();
                 OutputStream output = Files.newOutputStream(staged)) {
                copyBounded(body, output, maximumUploadBytes, "CISA KEV CSV");
            }
            CisaKevImportResult result = importer.importFile(staged);
            sendJson(exchange, 200, result.toMap());
        } finally {
            Files.deleteIfExists(staged);
        }
    }

    private void readEpssEvidence(HttpExchange exchange) throws IOException {
        EpssEvidenceReader reader = epssEvidenceReader.orElseThrow(() ->
                new HttpProblem(
                        503,
                        "EPSS_PERSISTENCE_UNAVAILABLE",
                        "EPSS evidence reads require PostgreSQL schema version 12 or newer"
                ));
        EpssEvidenceQuery query = parseEpssEvidenceQuery(exchange.getRequestURI());
        sendJson(exchange, 200, reader.currentEvidence(query.limit(), query.cvePrefix()));
    }

    private void createEpssImport(HttpExchange exchange) throws IOException {
        EpssImporter importer = epssImporter.orElseThrow(() ->
                new HttpProblem(
                        503,
                        "EPSS_PERSISTENCE_UNAVAILABLE",
                        "EPSS import requires PostgreSQL schema version 12 or newer"
                ));
        String contentType = exchange.getRequestHeaders().getFirst("Content-Type");
        if (!isCsvContentType(contentType)) {
            throw new HttpProblem(
                    415,
                    "UNSUPPORTED_MEDIA_TYPE",
                    "Content-Type must be text/csv, application/csv, or application/octet-stream"
            );
        }
        long contentLength = parseContentLength(exchange.getRequestHeaders().getFirst("Content-Length"));
        if (contentLength > maximumUploadBytes) {
            throw new HttpProblem(
                    413,
                    "UPLOAD_TOO_LARGE",
                    "EPSS CSV exceeds the configured upload limit"
            );
        }

        Path staged = Files.createTempFile("rbvm-epss-upload-", ".csv");
        try {
            try (InputStream body = exchange.getRequestBody();
                 OutputStream output = Files.newOutputStream(staged)) {
                copyBounded(body, output, maximumUploadBytes, "EPSS CSV");
            }
            EpssImportResult result = importer.importFile(staged);
            sendJson(exchange, 200, result.toMap());
        } finally {
            Files.deleteIfExists(staged);
        }
    }

    private void readAssetContextEvidence(HttpExchange exchange) throws IOException {
        AssetContextEvidenceReader reader = assetContextEvidenceReader.orElseThrow(() ->
                new HttpProblem(
                        503,
                        "ASSET_CONTEXT_PERSISTENCE_UNAVAILABLE",
                        "Asset context evidence reads require PostgreSQL schema version 13 or newer"
                ));
        AssetContextEvidenceQuery query = parseAssetContextEvidenceQuery(exchange.getRequestURI());
        sendJson(exchange, 200, reader.currentEvidence(
                query.limit(),
                query.assetPrefix(),
                query.sourceProfileKey(),
                query.contextSource()
        ));
    }

    private void createAssetContextImport(HttpExchange exchange) throws IOException {
        AssetContextImporter importer = assetContextImporter.orElseThrow(() ->
                new HttpProblem(
                        503,
                        "ASSET_CONTEXT_PERSISTENCE_UNAVAILABLE",
                        "Asset context import requires PostgreSQL schema version 13 or newer"
                ));
        String contentType = exchange.getRequestHeaders().getFirst("Content-Type");
        if (!isCsvContentType(contentType)) {
            throw new HttpProblem(
                    415,
                    "UNSUPPORTED_MEDIA_TYPE",
                    "Content-Type must be text/csv, application/csv, or application/octet-stream"
            );
        }
        long contentLength = parseContentLength(exchange.getRequestHeaders().getFirst("Content-Length"));
        if (contentLength > maximumUploadBytes) {
            throw new HttpProblem(
                    413,
                    "UPLOAD_TOO_LARGE",
                    "Asset context CSV exceeds the configured upload limit"
            );
        }

        Path staged = Files.createTempFile("rbvm-asset-context-upload-", ".csv");
        try {
            try (InputStream body = exchange.getRequestBody();
                 OutputStream output = Files.newOutputStream(staged)) {
                copyBounded(body, output, maximumUploadBytes, "Asset context CSV");
            }
            AssetContextImportResult result = importer.importFile(staged);
            sendJson(exchange, 200, result.toMap());
        } finally {
            Files.deleteIfExists(staged);
        }
    }

    private void readNetworkReachabilityEvidence(HttpExchange exchange) throws IOException {
        NetworkReachabilityEvidenceReader reader = networkReachabilityEvidenceReader.orElseThrow(() ->
                new HttpProblem(
                        503,
                        "NETWORK_REACHABILITY_PERSISTENCE_UNAVAILABLE",
                        "Network reachability evidence reads require PostgreSQL schema version 14 or newer"
                ));
        NetworkReachabilityEvidenceQuery query = parseNetworkReachabilityEvidenceQuery(
                exchange.getRequestURI());
        sendJson(exchange, 200, reader.currentEvidence(
                query.limit(),
                query.assetPrefix(),
                query.sourceProfileKey(),
                query.evidenceSource(),
                query.originScope(),
                query.reachabilityStatus()
        ));
    }

    private void createNetworkReachabilityImport(HttpExchange exchange) throws IOException {
        NetworkReachabilityImporter importer = networkReachabilityImporter.orElseThrow(() ->
                new HttpProblem(
                        503,
                        "NETWORK_REACHABILITY_PERSISTENCE_UNAVAILABLE",
                        "Network reachability import requires PostgreSQL schema version 14 or newer"
                ));
        String contentType = exchange.getRequestHeaders().getFirst("Content-Type");
        if (!isCsvContentType(contentType)) {
            throw new HttpProblem(
                    415,
                    "UNSUPPORTED_MEDIA_TYPE",
                    "Content-Type must be text/csv, application/csv, or application/octet-stream"
            );
        }
        long contentLength = parseContentLength(exchange.getRequestHeaders().getFirst("Content-Length"));
        if (contentLength > maximumUploadBytes) {
            throw new HttpProblem(
                    413,
                    "UPLOAD_TOO_LARGE",
                    "Network reachability CSV exceeds the configured upload limit"
            );
        }
        Path staged = Files.createTempFile("rbvm-network-reachability-upload-", ".csv");
        try {
            try (InputStream body = exchange.getRequestBody();
                 OutputStream output = Files.newOutputStream(staged)) {
                copyBounded(body, output, maximumUploadBytes, "Network reachability CSV");
            }
            NetworkReachabilityImportResult result = importer.importFile(staged);
            sendJson(exchange, 200, result.toMap());
        } finally {
            Files.deleteIfExists(staged);
        }
    }

    private void readBusinessImpactEvidence(HttpExchange exchange) throws IOException {
        BusinessImpactEvidenceReader reader = businessImpactEvidenceReader.orElseThrow(() ->
                new HttpProblem(
                        503,
                        "BUSINESS_IMPACT_PERSISTENCE_UNAVAILABLE",
                        "Business Impact evidence reads require PostgreSQL schema version 15 or newer"
                ));
        BusinessImpactEvidenceQuery query = parseBusinessImpactEvidenceQuery(exchange.getRequestURI());
        sendJson(exchange, 200, reader.currentEvidence(
                query.limit(),
                query.assetPrefix(),
                query.sourceProfileKey(),
                query.businessService(),
                query.impactSource(),
                query.impactDimension(),
                query.impactLevel()
        ));
    }

    private void createBusinessImpactImport(HttpExchange exchange) throws IOException {
        BusinessImpactImporter importer = businessImpactImporter.orElseThrow(() ->
                new HttpProblem(
                        503,
                        "BUSINESS_IMPACT_PERSISTENCE_UNAVAILABLE",
                        "Business Impact import requires PostgreSQL schema version 15 or newer"
                ));
        String contentType = exchange.getRequestHeaders().getFirst("Content-Type");
        if (!isCsvContentType(contentType)) {
            throw new HttpProblem(
                    415,
                    "UNSUPPORTED_MEDIA_TYPE",
                    "Content-Type must be text/csv, application/csv, or application/octet-stream"
            );
        }
        long contentLength = parseContentLength(exchange.getRequestHeaders().getFirst("Content-Length"));
        if (contentLength > maximumUploadBytes) {
            throw new HttpProblem(
                    413,
                    "UPLOAD_TOO_LARGE",
                    "Business Impact CSV exceeds the configured upload limit"
            );
        }
        Path staged = Files.createTempFile("rbvm-business-impact-upload-", ".csv");
        try {
            try (InputStream body = exchange.getRequestBody();
                 OutputStream output = Files.newOutputStream(staged)) {
                copyBounded(body, output, maximumUploadBytes, "Business Impact CSV");
            }
            BusinessImpactImportResult result = importer.importFile(staged);
            sendJson(exchange, 200, result.toMap());
        } finally {
            Files.deleteIfExists(staged);
        }
    }

    private static void copyBounded(
            InputStream input,
            OutputStream output,
            long maximumBytes,
            String evidenceName
    ) throws IOException {
        byte[] buffer = new byte[8192];
        long total = 0;
        int read;
        while ((read = input.read(buffer)) >= 0) {
            if (read == 0) {
                continue;
            }
            total += read;
            if (total > maximumBytes) {
                throw new HttpProblem(
                        413,
                        "UPLOAD_TOO_LARGE",
                        evidenceName + " exceeds the configured upload limit"
                );
            }
            output.write(buffer, 0, read);
        }
    }

    private void createImport(HttpExchange exchange) throws IOException {
        String contentType = exchange.getRequestHeaders().getFirst("Content-Type");
        if (!isCsvContentType(contentType)) {
            throw new HttpProblem(
                    415,
                    "UNSUPPORTED_MEDIA_TYPE",
                    "Content-Type must be text/csv, application/csv, or application/octet-stream"
            );
        }
        String sourceProfile = exchange.getRequestHeaders().getFirst("X-Source-Profile-Id");
        String contractId = exchange.getRequestHeaders().getFirst("X-CSV-Contract");
        String idempotencyKey = exchange.getRequestHeaders().getFirst("Idempotency-Key");
        long contentLength = parseContentLength(exchange.getRequestHeaders().getFirst("Content-Length"));

        CsvImportService.CreateResult result;
        try (InputStream body = exchange.getRequestBody()) {
            result = imports.create(body, contentLength, sourceProfile, idempotencyKey, contractId);
        }
        if (result.replayed()) {
            exchange.getResponseHeaders().set("Idempotency-Replayed", "true");
            if (result.replayReason() != null) {
                exchange.getResponseHeaders().set("RBVM-Replay-Reason", result.replayReason());
            }
        } else {
            exchange.getResponseHeaders().set(
                    "Location",
                    "/api/v1/csv-imports/" + result.importView().get("importId")
            );
        }
        sendJson(exchange, result.replayed() ? 200 : 201, result.importView());
    }

    private void getImport(HttpExchange exchange, UUID importId) throws IOException {
        Map<String, Object> view = imports.find(importId)
                .orElseThrow(() -> new CsvImportService.ImportNotFoundException(importId));
        sendJson(exchange, 200, view);
    }

    private void confirmImport(HttpExchange exchange, UUID importId) throws IOException {
        validateIdempotencyHeader(exchange.getRequestHeaders().getFirst("Idempotency-Key"));
        CsvImportService.ConfirmResult result = imports.confirm(importId);
        if (result.replayed()) {
            exchange.getResponseHeaders().set("Idempotency-Replayed", "true");
        }
        sendJson(exchange, 200, result.importView());
    }

    private void getCase(HttpExchange exchange, String caseId) throws IOException {
        Map<String, Object> view = imports.caseDetail(caseId)
                .orElseThrow(() -> new CaseNotFoundException(caseId));
        sendJson(exchange, 200, view);
    }

    private void actOnCase(HttpExchange exchange, String caseId, AuthPrincipal principal)
            throws IOException {
        String contentType = exchange.getRequestHeaders().getFirst("Content-Type");
        if (contentType == null || !contentType.split(";", 2)[0].trim()
                .equalsIgnoreCase("application/x-www-form-urlencoded")) {
            throw new HttpProblem(
                    415,
                    "UNSUPPORTED_MEDIA_TYPE",
                    "Case actions require application/x-www-form-urlencoded"
            );
        }
        String idempotencyKey = exchange.getRequestHeaders().getFirst("Idempotency-Key");
        validateIdempotencyHeader(idempotencyKey);
        Map<String, String> form;
        try (InputStream body = exchange.getRequestBody()) {
            form = readForm(body);
        }
        rejectUnknownFields(form, Set.of("action", "reason", "expiresAt", "evidenceReference"));

        CaseActionType action;
        try {
            action = CaseActionType.valueOf(requiredForm(form, "action").toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException exception) {
            throw new InvalidCaseActionException("action is not recognized");
        }
        Instant expiresAt = parseOptionalInstant(form.get("expiresAt"));
        CaseActionCommand command = new CaseActionCommand(
                action,
                form.get("reason"),
                expiresAt,
                form.get("evidenceReference")
        );
        CsvImportService.CaseActionResult result = imports.actOnCase(
                caseId,
                command,
                idempotencyKey,
                principal.actorId(),
                principal.assurance()
        );
        if (result.replayed()) {
            exchange.getResponseHeaders().set("Idempotency-Replayed", "true");
        }
        sendJson(exchange, 200, result.toMap());
    }

    private static void validateIdempotencyHeader(String key) {
        if (key == null || key.isBlank() || key.trim().length() < 8 || key.trim().length() > 128) {
            throw new CsvImportService.InvalidRequestException(
                    "Idempotency-Key must contain between 8 and 128 characters");
        }
    }

    private static boolean isCsvContentType(String value) {
        if (value == null) {
            return false;
        }
        String mediaType = value.split(";", 2)[0].trim().toLowerCase(Locale.ROOT);
        return mediaType.equals("text/csv")
                || mediaType.equals("application/csv")
                || mediaType.equals("application/octet-stream");
    }

    private static long parseContentLength(String value) {
        if (value == null || value.isBlank()) {
            return -1;
        }
        try {
            long length = Long.parseLong(value);
            if (length < 0) {
                throw new NumberFormatException("negative");
            }
            return length;
        } catch (NumberFormatException exception) {
            throw new HttpProblem(400, "INVALID_CONTENT_LENGTH", "Content-Length is invalid");
        }
    }

    private static CaseQuery parseCaseQuery(URI uri) {
        Map<String, String> query = parseParameters(uri.getRawQuery());
        rejectUnknownFields(query, Set.of(
                "limit", "cursor", "severity", "status", "cve", "asset",
                "priority", "knownExploited"));
        int limit = 20;
        if (query.containsKey("limit")) {
            try {
                limit = Integer.parseInt(query.get("limit"));
                if (limit < 0 || limit > 100) {
                    throw new NumberFormatException("out of range");
                }
            } catch (NumberFormatException exception) {
                throw new InvalidCaseActionException("limit must be between 0 and 100");
            }
        }
        return new CaseQuery(
                limit,
                query.get("cursor"),
                parseEnumSet(query.get("severity"), CsvSeverity.class, "severity"),
                parseEnumSet(query.get("status"), CaseStatus.class, "status"),
                query.get("cve"),
                query.get("asset"),
                parseEnumSet(query.get("priority"), VulnerabilityPriorityTier.class, "priority"),
                parseOptionalBoolean(query.get("knownExploited"), "knownExploited")
        );
    }

    private static CvssEvidenceQuery parseCvssEvidenceQuery(URI uri) {
        Map<String, String> query = parseEvidenceQuery(uri);
        return new CvssEvidenceQuery(queryLimit(query), queryCve(query));
    }

    private static CisaKevEvidenceQuery parseCisaKevEvidenceQuery(URI uri) {
        Map<String, String> query = parseEvidenceQuery(uri);
        return new CisaKevEvidenceQuery(queryLimit(query), queryCve(query));
    }

    private static EpssEvidenceQuery parseEpssEvidenceQuery(URI uri) {
        Map<String, String> query = parseEvidenceQuery(uri);
        return new EpssEvidenceQuery(queryLimit(query), queryCve(query));
    }

    private static AssetContextEvidenceQuery parseAssetContextEvidenceQuery(URI uri) {
        Map<String, String> query = parseParameters(uri.getRawQuery());
        rejectUnknownFields(query, Set.of("limit", "asset", "sourceProfile", "contextSource"));
        return new AssetContextEvidenceQuery(
                queryLimit(query),
                queryOptional(query, "asset", 160),
                querySourceProfile(query),
                queryOptional(query, "contextSource", 256)
        );
    }

    private static NetworkReachabilityEvidenceQuery parseNetworkReachabilityEvidenceQuery(URI uri) {
        Map<String, String> query = parseParameters(uri.getRawQuery());
        rejectUnknownFields(query, Set.of(
                "limit", "asset", "sourceProfile", "evidenceSource",
                "originScope", "reachabilityStatus"));
        return new NetworkReachabilityEvidenceQuery(
                queryLimit(query),
                queryOptional(query, "asset", 160),
                querySourceProfile(query),
                queryOptional(query, "evidenceSource", 256),
                queryEnum(query, "originScope", Set.of(
                        "INTERNET", "EXTERNAL_PARTNER", "INTERNAL_ENTERPRISE",
                        "LOCAL_SEGMENT", "OTHER", "UNKNOWN")),
                queryEnum(query, "reachabilityStatus", Set.of(
                        "REACHABLE", "NOT_REACHABLE", "UNKNOWN"))
        );
    }

    private static BusinessImpactEvidenceQuery parseBusinessImpactEvidenceQuery(URI uri) {
        Map<String, String> query = parseParameters(uri.getRawQuery());
        rejectUnknownFields(query, Set.of(
                "limit", "asset", "sourceProfile", "businessService", "impactSource",
                "impactDimension", "impactLevel"));
        return new BusinessImpactEvidenceQuery(
                queryLimit(query),
                queryOptional(query, "asset", 160),
                querySourceProfile(query),
                queryOptional(query, "businessService", 256),
                queryOptional(query, "impactSource", 256),
                queryEnum(query, "impactDimension", Set.of(
                        "AVAILABILITY", "INTEGRITY", "CONFIDENTIALITY", "SAFETY", "FINANCIAL",
                        "REGULATORY", "OPERATIONAL", "REPUTATIONAL", "MISSION", "OTHER", "UNKNOWN")),
                queryEnum(query, "impactLevel", Set.of(
                        "SEVERE", "HIGH", "MODERATE", "LOW", "NEGLIGIBLE", "UNKNOWN"))
        );
    }

    private static Map<String, String> parseEvidenceQuery(URI uri) {
        Map<String, String> query = parseParameters(uri.getRawQuery());
        rejectUnknownFields(query, Set.of("limit", "cve"));
        return query;
    }

    private static int queryLimit(Map<String, String> query) {
        int limit = 100;
        if (query.containsKey("limit")) {
            try {
                limit = Integer.parseInt(query.get("limit"));
                if (limit < 1 || limit > 500) {
                    throw new NumberFormatException("out of range");
                }
            } catch (NumberFormatException exception) {
                throw new InvalidCaseActionException("limit must be between 1 and 500");
            }
        }
        return limit;
    }

    private static String queryCve(Map<String, String> query) {
        String cve = query.get("cve");
        if (cve != null && !cve.isBlank()) {
            cve = cve.trim().toUpperCase(Locale.ROOT);
            if (cve.length() > 32 || !CVE_PREFIX.matcher(cve).matches()) {
                throw new InvalidCaseActionException("cve must be a CVE identifier or CVE prefix");
            }
            return cve;
        }
        return null;
    }

    private static String queryEnum(
            Map<String, String> query,
            String field,
            Set<String> allowed
    ) {
        String value = queryOptional(query, field, 64);
        if (value == null) {
            return null;
        }
        value = value.toUpperCase(Locale.ROOT);
        if (!allowed.contains(value)) {
            throw new InvalidCaseActionException(field + " contains an unsupported value");
        }
        return value;
    }

    private static String querySourceProfile(Map<String, String> query) {
        String value = queryOptional(query, "sourceProfile", 128);
        if (value != null && !SOURCE_PROFILE_KEY.matcher(value).matches()) {
            throw new InvalidCaseActionException("sourceProfile contains unsupported characters");
        }
        return value;
    }

    private static String queryOptional(
            Map<String, String> query,
            String field,
            int maximumLength
    ) {
        String value = query.get(field);
        if (value == null || value.isBlank()) {
            return null;
        }
        value = value.trim();
        if (value.length() > maximumLength || value.indexOf('\u0000') >= 0) {
            throw new InvalidCaseActionException(field + " is invalid or too long");
        }
        return value;
    }

    private static Boolean parseOptionalBoolean(String value, String field) {
        if (value == null || value.isBlank()) return null;
        if (value.equalsIgnoreCase("true")) return true;
        if (value.equalsIgnoreCase("false")) return false;
        throw new InvalidCaseActionException(field + " must be true or false");
    }

    private static Map<String, String> readForm(InputStream input) throws IOException {
        byte[] bytes = input.readNBytes(MAXIMUM_ACTION_BODY_BYTES + 1);
        if (bytes.length > MAXIMUM_ACTION_BODY_BYTES) {
            throw new HttpProblem(413, "ACTION_BODY_TOO_LARGE", "Case action body exceeds 16 KiB");
        }
        return parseParameters(new String(bytes, StandardCharsets.UTF_8));
    }

    private static Map<String, String> parseParameters(String encoded) {
        Map<String, String> output = new LinkedHashMap<>();
        if (encoded == null || encoded.isBlank()) {
            return output;
        }
        for (String parameter : encoded.split("&")) {
            String[] pair = parameter.split("=", 2);
            String name;
            String value;
            try {
                name = URLDecoder.decode(pair[0], StandardCharsets.UTF_8);
                value = URLDecoder.decode(pair.length == 2 ? pair[1] : "", StandardCharsets.UTF_8);
            } catch (IllegalArgumentException exception) {
                throw new InvalidCaseActionException("Request parameters contain invalid encoding");
            }
            if (name.isBlank()) {
                throw new InvalidCaseActionException("Request parameter name cannot be empty");
            }
            if (output.putIfAbsent(name, value) != null) {
                throw new InvalidCaseActionException("Duplicate request parameter: " + name);
            }
        }
        return output;
    }

    private static <E extends Enum<E>> Set<E> parseEnumSet(
            String value,
            Class<E> type,
            String field
    ) {
        if (value == null || value.isBlank()) {
            return Set.of();
        }
        Set<E> output = EnumSet.noneOf(type);
        for (String token : value.split(",")) {
            try {
                output.add(Enum.valueOf(type, token.trim().toUpperCase(Locale.ROOT)));
            } catch (IllegalArgumentException exception) {
                throw new InvalidCaseActionException(field + " contains an unknown value: " + token);
            }
        }
        return output;
    }

    private static void rejectUnknownFields(Map<String, String> values, Set<String> allowed) {
        Set<String> unknown = new HashSet<>(values.keySet());
        unknown.removeAll(allowed);
        if (!unknown.isEmpty()) {
            throw new InvalidCaseActionException("Unknown request fields: " + unknown);
        }
    }

    private static String requiredForm(Map<String, String> form, String field) {
        String value = form.get(field);
        if (value == null || value.isBlank()) {
            throw new InvalidCaseActionException(field + " is required");
        }
        return value.trim();
    }

    private static Instant parseOptionalInstant(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        try {
            return Instant.parse(value.trim());
        } catch (DateTimeParseException exception) {
            throw new InvalidCaseActionException("expiresAt must be ISO-8601 with timezone");
        }
    }

    private static void requireMethod(HttpExchange exchange, String actual, String expected) {
        if (!expected.equals(actual)) {
            exchange.getResponseHeaders().set("Allow", expected);
            throw new HttpProblem(405, "METHOD_NOT_ALLOWED", "Use " + expected + " for this route");
        }
    }

    private AuthPrincipal authorize(HttpExchange exchange, ApiRole required) {
        java.util.List<String> authorization = exchange.getRequestHeaders().get("Authorization");
        String authorizationHeader = authorization == null || authorization.size() != 1
                ? null
                : authorization.get(0);
        AuthPrincipal principal = authenticator.authenticate(authorizationHeader)
                .orElseThrow(() -> {
                    Decision decision = rateLimiter.checkAuthenticationFailure(
                            exchange.getRemoteAddress().getAddress().getHostAddress());
                    if (!decision.permitted()) {
                        rejectRateLimit(exchange, decision);
                    }
                    authenticationFailuresTotal.incrementAndGet();
                    exchange.getResponseHeaders().set(
                            "WWW-Authenticate", "Bearer realm=\"rbvm-api\"");
                    return new HttpProblem(401, "AUTHENTICATION_REQUIRED",
                            "A valid bearer API key is required");
                });
        Decision decision = rateLimiter.checkActor(principal.actorId());
        if (!decision.permitted()) {
            rejectRateLimit(exchange, decision);
        }
        if (!principal.role().permits(required)) {
            forbiddenTotal.incrementAndGet();
            throw new HttpProblem(403, "INSUFFICIENT_ROLE",
                    "The authenticated identity is not permitted to perform this operation");
        }
        return principal;
    }

    private void rejectRateLimit(HttpExchange exchange, Decision decision) {
        rateLimitedTotal.incrementAndGet();
        exchange.getResponseHeaders().set(
                "Retry-After", Integer.toString(decision.retryAfterSeconds()));
        throw new HttpProblem(429, "RATE_LIMIT_EXCEEDED",
                "Request rate limit exceeded; retry after the indicated interval");
    }

    private static void sendProblem(
            HttpExchange exchange,
            int status,
            String code,
            String detail,
            String correlationId
    ) throws IOException {
        Map<String, Object> problem = new LinkedHashMap<>();
        problem.put("type", "urn:rbvm:problem:" + code.toLowerCase(Locale.ROOT));
        problem.put("title", code.replace('_', ' '));
        problem.put("status", status);
        problem.put("detail", detail);
        problem.put("correlationId", correlationId);
        sendBytes(
                exchange,
                status,
                "application/problem+json; charset=utf-8",
                JsonOutput.pretty(problem).getBytes(StandardCharsets.UTF_8)
        );
    }

    private static void sendJson(HttpExchange exchange, int status, Map<String, Object> value)
            throws IOException {
        sendBytes(
                exchange,
                status,
                "application/json; charset=utf-8",
                JsonOutput.pretty(value).getBytes(StandardCharsets.UTF_8)
        );
    }

    private void sendMetrics(HttpExchange exchange) throws IOException {
        Map<String, Object> health = imports.health();
        long uptime = Math.max(0, java.time.Duration.between(startedAt, Instant.now()).toSeconds());
        String metrics = "# TYPE rbvm_up gauge\n"
                + "rbvm_up " + ("UP".equals(health.get("status")) ? 1 : 0) + "\n"
                + "# TYPE rbvm_http_requests_total counter\n"
                + "rbvm_http_requests_total " + requestsTotal.get() + "\n"
                + "# TYPE rbvm_http_problems_total counter\n"
                + "rbvm_http_problems_total " + problemsTotal.get() + "\n"
                + "# TYPE rbvm_authentication_failures_total counter\n"
                + "rbvm_authentication_failures_total " + authenticationFailuresTotal.get() + "\n"
                + "# TYPE rbvm_authorization_forbidden_total counter\n"
                + "rbvm_authorization_forbidden_total " + forbiddenTotal.get() + "\n"
                + "# TYPE rbvm_rate_limited_total counter\n"
                + "rbvm_rate_limited_total " + rateLimitedTotal.get() + "\n"
                + "# TYPE rbvm_applicability_import_enabled gauge\n"
                + "rbvm_applicability_import_enabled " + (applicabilityImporter.isPresent() ? 1 : 0) + "\n"
                + "# TYPE rbvm_cvss_v31_import_enabled gauge\n"
                + "rbvm_cvss_v31_import_enabled " + (cvssV31Importer.isPresent() ? 1 : 0) + "\n"
                + "# TYPE rbvm_cvss_v31_evidence_read_enabled gauge\n"
                + "rbvm_cvss_v31_evidence_read_enabled " + (cvssV31EvidenceReader.isPresent() ? 1 : 0) + "\n"
                + "# TYPE rbvm_cisa_kev_import_enabled gauge\n"
                + "rbvm_cisa_kev_import_enabled " + (cisaKevImporter.isPresent() ? 1 : 0) + "\n"
                + "# TYPE rbvm_cisa_kev_evidence_read_enabled gauge\n"
                + "rbvm_cisa_kev_evidence_read_enabled " + (cisaKevEvidenceReader.isPresent() ? 1 : 0) + "\n"
                + "# TYPE rbvm_epss_import_enabled gauge\n"
                + "rbvm_epss_import_enabled " + (epssImporter.isPresent() ? 1 : 0) + "\n"
                + "# TYPE rbvm_epss_evidence_read_enabled gauge\n"
                + "rbvm_epss_evidence_read_enabled " + (epssEvidenceReader.isPresent() ? 1 : 0) + "\n"
                + "# TYPE rbvm_asset_context_import_enabled gauge\n"
                + "rbvm_asset_context_import_enabled " + (assetContextImporter.isPresent() ? 1 : 0) + "\n"
                + "# TYPE rbvm_asset_context_evidence_read_enabled gauge\n"
                + "rbvm_asset_context_evidence_read_enabled " + (assetContextEvidenceReader.isPresent() ? 1 : 0) + "\n"
                + "# TYPE rbvm_network_reachability_import_enabled gauge\n"
                + "rbvm_network_reachability_import_enabled " + (networkReachabilityImporter.isPresent() ? 1 : 0) + "\n"
                + "# TYPE rbvm_network_reachability_evidence_read_enabled gauge\n"
                + "rbvm_network_reachability_evidence_read_enabled " + (networkReachabilityEvidenceReader.isPresent() ? 1 : 0) + "\n"
                + "# TYPE rbvm_business_impact_import_enabled gauge\n"
                + "rbvm_business_impact_import_enabled " + (businessImpactImporter.isPresent() ? 1 : 0) + "\n"
                + "# TYPE rbvm_business_impact_evidence_read_enabled gauge\n"
                + "rbvm_business_impact_evidence_read_enabled " + (businessImpactEvidenceReader.isPresent() ? 1 : 0) + "\n"
                + "# TYPE rbvm_managed_asset_api_enabled gauge\n"
                + "rbvm_managed_asset_api_enabled " + (managedAssetRouter.isPresent() ? 1 : 0) + "\n"
                + "# TYPE rbvm_scanner_managed_asset_link_api_enabled gauge\n"
                + "rbvm_scanner_managed_asset_link_api_enabled "
                + (scannerManagedAssetLinkRouter.isPresent() ? 1 : 0) + "\n"
                + "# TYPE rbvm_finding_context_association_api_enabled gauge\n"
                + "rbvm_finding_context_association_api_enabled "
                + (findingContextAssociationRouter.isPresent() ? 1 : 0) + "\n"
                + "# TYPE rbvm_formula_result_api_enabled gauge\n"
                + "rbvm_formula_result_api_enabled "
                + (formulaResultRouter.isPresent() ? 1 : 0) + "\n"
                + "# TYPE rbvm_derived_risk_result_api_enabled gauge\n"
                + "rbvm_derived_risk_result_api_enabled "
                + (derivedRiskResultRouter.isPresent() ? 1 : 0) + "\n"
                + "# TYPE rbvm_process_uptime_seconds gauge\n"
                + "rbvm_process_uptime_seconds " + uptime + "\n"
                + "# TYPE rbvm_imports_stored gauge\n"
                + "rbvm_imports_stored " + health.get("storedImports") + "\n"
                + "# TYPE rbvm_cases gauge\n"
                + "rbvm_cases " + health.get("cases") + "\n";
        sendBytes(exchange, 200, "text/plain; version=0.0.4; charset=utf-8",
                metrics.getBytes(StandardCharsets.UTF_8));
    }

    private static void sendBytes(HttpExchange exchange, int status, String contentType, byte[] body)
            throws IOException {
        exchange.getResponseHeaders().set("Content-Type", contentType);
        exchange.sendResponseHeaders(status, body.length);
        exchange.getResponseBody().write(body);
    }

    private static void addCommonHeaders(Headers headers, String correlationId) {
        headers.set("Cache-Control", "no-store");
        headers.set("X-Content-Type-Options", "nosniff");
        headers.set("X-Frame-Options", "DENY");
        headers.set("Referrer-Policy", "no-referrer");
        headers.set("Content-Security-Policy",
                "default-src 'self'; style-src 'self' 'unsafe-inline'; "
                        + "script-src 'self' 'unsafe-inline'; connect-src 'self'; "
                        + "img-src 'self' data:; object-src 'none'; base-uri 'none'; "
                        + "frame-ancestors 'none'; form-action 'self'");
        headers.set("X-Correlation-Id", correlationId);
    }

    private static byte[] loadResource(String name) throws IOException {
        try (InputStream input = CsvPlatformServer.class.getResourceAsStream(name)) {
            if (input == null) {
                throw new IOException("Required server resource is missing: " + name);
            }
            return input.readAllBytes();
        }
    }

    public static void main(String[] args) throws Exception {
        ServerConfiguration configuration = ServerConfiguration.fromEnvironment();
        RuntimeComponents runtime = CanonicalProjectionFactory.runtimeFromEnvironment(System.getenv());
        Optional<CanonicalProjectionFactory.FindingContextAssociationRuntime> associationRuntime =
                CanonicalProjectionFactory.findingContextAssociationRuntimeFromEnvironment(System.getenv());
        Optional<FormulaResultRuntimeFactory.Runtime> formulaResultRuntime =
                FormulaResultRuntimeFactory.fromEnvironment(System.getenv());
        Optional<DerivedRiskResultRuntimeFactory.Runtime> derivedRiskResultRuntime =
                DerivedRiskResultRuntimeFactory.fromEnvironment(System.getenv());
        ApiKeyAuthenticator authenticator = ApiKeyAuthenticator.fromEnvironment(System.getenv());
        RequestRateLimiter rateLimiter = RequestRateLimiter.fromEnvironment(System.getenv());
        CanonicalProjection canonicalProjection = runtime.canonicalProjection();
        CsvPlatformServer application = new CsvPlatformServer(
                configuration.host(),
                configuration.port(),
                configuration.dataDirectory(),
                configuration.maximumUploadBytes(),
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
        Runtime.getRuntime().addShutdownHook(new Thread(application::close, "rbvm-shutdown"));
        application.start();
        System.out.println("RBVM CSV Platform is running at " + application.baseUri());
        System.out.println("CVSS v3.1 operator UI: " + application.baseUri().resolve("/cvss"));
        System.out.println("CISA KEV operator UI: " + application.baseUri().resolve("/kev"));
        System.out.println("EPSS operator UI: " + application.baseUri().resolve("/epss"));
        System.out.println("Asset Context operator UI: " + application.baseUri().resolve("/asset-context"));
        System.out.println("Network Reachability operator UI: " + application.baseUri().resolve("/reachability"));
        System.out.println("Business Impact operator UI: " + application.baseUri().resolve("/business-impact"));
        System.out.println("Managed Assets operator UI: " + application.baseUri().resolve("/assets"));
        System.out.println("Scanner↔Managed Asset Link operator UI: " + application.baseUri().resolve("/asset-links"));
        System.out.println("Data directory: " + configuration.dataDirectory().toAbsolutePath().normalize());
        System.out.println("Canonical projection: "
                + canonicalProjection.health().get("backend"));
        System.out.println("Applicability persistence: "
                + (runtime.applicabilityImporter().isPresent() ? "ENABLED" : "DISABLED"));
        System.out.println("CVSS v3.1 persistence: "
                + (runtime.cvssV31Importer().isPresent() ? "ENABLED" : "DISABLED"));
        System.out.println("CISA KEV persistence: "
                + (runtime.cisaKevImporter().isPresent() ? "ENABLED" : "DISABLED"));
        System.out.println("EPSS persistence: "
                + (runtime.epssImporter().isPresent() ? "ENABLED" : "DISABLED"));
        System.out.println("Asset Context persistence: "
                + (runtime.assetContextImporter().isPresent() ? "ENABLED" : "DISABLED"));
        System.out.println("Network Reachability persistence: "
                + (runtime.networkReachabilityImporter().isPresent() ? "ENABLED" : "DISABLED"));
        System.out.println("Business Impact persistence: "
                + (runtime.businessImpactImporter().isPresent() ? "ENABLED" : "DISABLED"));
        System.out.println("Managed Asset API: "
                + (runtime.managedAssetRegistry().isPresent() ? "ENABLED" : "DISABLED"));
        System.out.println("Scanner↔Managed Asset Link API: "
                + (runtime.scannerManagedAssetLinkRegistry().isPresent() ? "ENABLED" : "DISABLED"));
        System.out.println("Finding Context Association API: "
                + (associationRuntime.isPresent() ? "ENABLED" : "DISABLED"));
        System.out.println("Formula Result API: "
                + (formulaResultRuntime.isPresent() ? "ENABLED" : "DISABLED"));
        System.out.println("Derived Risk Result API: "
                + (derivedRiskResultRuntime.isPresent() ? "ENABLED" : "DISABLED"));
        System.out.println("API authentication: "
                + (authenticator.enabled() ? "API_KEY" : "DISABLED"));
        new CountDownLatch(1).await();
    }

    private record CvssEvidenceQuery(int limit, String cvePrefix) {
    }

    private record CisaKevEvidenceQuery(int limit, String cvePrefix) {
    }

    private record EpssEvidenceQuery(int limit, String cvePrefix) {
    }

    private record AssetContextEvidenceQuery(
            int limit,
            String assetPrefix,
            String sourceProfileKey,
            String contextSource
    ) {
    }

    private record NetworkReachabilityEvidenceQuery(
            int limit,
            String assetPrefix,
            String sourceProfileKey,
            String evidenceSource,
            String originScope,
            String reachabilityStatus
    ) {
    }

    private record BusinessImpactEvidenceQuery(
            int limit,
            String assetPrefix,
            String sourceProfileKey,
            String businessService,
            String impactSource,
            String impactDimension,
            String impactLevel
    ) {
    }

    private record ServerConfiguration(
            String host,
            int port,
            Path dataDirectory,
            long maximumUploadBytes
    ) {
        private static ServerConfiguration fromEnvironment() {
            String host = environment("RBVM_HOST", "127.0.0.1");
            int port = parseInteger(environment("RBVM_PORT", "8080"), "RBVM_PORT", 1, 65_535);
            Path data = Path.of(environment("RBVM_DATA_DIR", "data"));
            long max = parseLong(
                    environment("RBVM_MAX_UPLOAD_BYTES", Long.toString(DEFAULT_MAXIMUM_UPLOAD_BYTES)),
                    "RBVM_MAX_UPLOAD_BYTES",
                    1,
                    Long.MAX_VALUE
            );
            return new ServerConfiguration(host, port, data, max);
        }

        private static String environment(String name, String fallback) {
            String value = System.getenv(name);
            return value == null || value.isBlank() ? fallback : value.trim();
        }

        private static int parseInteger(String value, String name, int minimum, int maximum) {
            long parsed = parseLong(value, name, minimum, maximum);
            return Math.toIntExact(parsed);
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

    private static final class HttpProblem extends RuntimeException {
        private static final long serialVersionUID = 1L;
        private final int status;
        private final String code;

        private HttpProblem(int status, String code, String message) {
            super(Objects.requireNonNull(message, "message"));
            this.status = status;
            this.code = Objects.requireNonNull(code, "code");
        }

        private int status() {
            return status;
        }

        private String code() {
            return code;
        }
    }
}

package io.rbvm.postgres;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Duration;
import java.time.Instant;
import java.time.Year;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Runs the hardened standard-library Python source adapters packaged inside the RBVM artifact.
 *
 * <p>No shell is involved. Script paths and provider URLs are fixed by the application, provider
 * names/feed identities are allowlisted, process output is bounded, and every invocation has a
 * hard timeout. The Python tools are implementation helpers; V30/V31 remain the persistence and
 * lifecycle authorities.</p>
 */
public final class SubprocessPublicIntelligenceSourcePipeline
        implements PublicIntelligenceSourcePipeline {
    private static final String FETCHER_RESOURCE =
            "/intelligence-tools/scripts/fetch-local-public-intelligence-source.py";
    private static final String BRIDGE_RESOURCE =
            "/intelligence-tools/scripts/build-public-intelligence-bundle-from-acquisition.py";
    private static final String BUILDER_RESOURCE =
            "/intelligence-tools/scripts/build-public-intelligence-sync-bundle.py";
    private static final Pattern NVD_FEED = Pattern.compile("^(modified|20[0-9]{2})$");
    private static final Pattern ACQUISITION_SUMMARY = Pattern.compile(
            "public_intelligence_source=VALID\\s+provider=([A-Z_]+)\\s+"
                    + "version=([^\\s]+)\\s+sha256=([a-f0-9]{64})\\s+output=([^\\r\\n]+)"
    );
    private static final int MAX_TOOL_OUTPUT_BYTES = 128 * 1024;
    private static final long DEFAULT_TIMEOUT_SECONDS = 1_800L;
    private static final String NVD_BASE = "https://nvd.nist.gov/feeds/json/cve/2.0";
    private static final String FIRST_EPSS =
            "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz";
    private static final String CISA_KEV =
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
    private static final String CVE_ARCHIVE =
            "https://github.com/CVEProject/cvelistV5/archive/%s.zip";

    private final String pythonExecutable;
    private final Duration timeout;

    public SubprocessPublicIntelligenceSourcePipeline(Map<String, String> environment) {
        Objects.requireNonNull(environment, "environment");
        this.pythonExecutable = textOrDefault(
                environment.get("RBVM_INTELLIGENCE_PYTHON"), "python3");
        this.timeout = Duration.ofSeconds(parseLong(
                environment.get("RBVM_INTELLIGENCE_TOOL_TIMEOUT_SECONDS"),
                DEFAULT_TIMEOUT_SECONDS,
                30L,
                7_200L,
                "RBVM_INTELLIGENCE_TOOL_TIMEOUT_SECONDS"));
    }

    @Override
    public AcquiredSource acquire(
            PostgresPublicIntelligenceStore.Provider provider,
            String nvdFeed,
            Path workDirectory,
            Instant observedAt
    ) throws IOException, InterruptedException {
        Objects.requireNonNull(provider, "provider");
        Objects.requireNonNull(workDirectory, "workDirectory");
        Objects.requireNonNull(observedAt, "observedAt");
        requireSafeWorkDirectory(workDirectory);
        Path toolsRoot = extractTools(workDirectory.resolve("tools"));
        Path acquisition = workDirectory.resolve("acquisition");
        if (Files.exists(acquisition, LinkOption.NOFOLLOW_LINKS)) {
            throw new IOException("public-intelligence acquisition directory already exists");
        }

        String feed = canonicalNvdFeed(provider, nvdFeed);
        List<String> command = new ArrayList<>();
        command.add(pythonExecutable);
        command.add(toolsRoot.resolve("scripts/fetch-local-public-intelligence-source.py").toString());
        command.add(provider.name());
        command.add(acquisition.toString());
        command.add("--observed-at");
        command.add(observedAt.toString());
        if (provider == PostgresPublicIntelligenceStore.Provider.NVD) {
            command.add("--nvd-feed");
            command.add(feed);
        }

        String output = execute(command, workDirectory);
        Matcher matcher = ACQUISITION_SUMMARY.matcher(output);
        if (!matcher.find()) {
            throw new IOException("public-intelligence acquisition helper returned no validated summary");
        }
        if (!provider.name().equals(matcher.group(1))) {
            throw new IOException("public-intelligence acquisition helper returned a different provider");
        }
        String version = matcher.group(2);
        String sha256 = matcher.group(3);
        Path reported = Path.of(matcher.group(4).trim()).toAbsolutePath().normalize();
        if (!reported.equals(acquisition.toAbsolutePath().normalize())) {
            throw new IOException("public-intelligence acquisition helper returned an unexpected output path");
        }
        requireSafeAcquisition(acquisition);
        return new AcquiredSource(
                provider,
                feed,
                sourceUri(provider, feed, version),
                version,
                sha256,
                acquisition);
    }

    @Override
    public Path buildBundle(
            AcquiredSource source,
            Set<String> previousCurrentCves,
            Path workDirectory
    ) throws IOException, InterruptedException {
        Objects.requireNonNull(source, "source");
        Objects.requireNonNull(previousCurrentCves, "previousCurrentCves");
        Objects.requireNonNull(workDirectory, "workDirectory");
        requireSafeWorkDirectory(workDirectory);
        if (source.provider() == PostgresPublicIntelligenceStore.Provider.NVD
                && !previousCurrentCves.isEmpty()) {
            throw new IOException("NVD partial/year feeds must never infer tombstones from absence");
        }
        requireSafeAcquisition(source.acquisitionDirectory());
        Path toolsRoot = workDirectory.resolve("tools");
        requireSafeTools(toolsRoot);
        Path bundle = workDirectory.resolve("bundle");
        if (Files.exists(bundle, LinkOption.NOFOLLOW_LINKS)) {
            throw new IOException("public-intelligence bundle directory already exists");
        }

        List<String> command = new ArrayList<>();
        command.add(pythonExecutable);
        command.add(toolsRoot.resolve(
                "scripts/build-public-intelligence-bundle-from-acquisition.py").toString());
        command.add(source.acquisitionDirectory().toString());
        command.add(bundle.toString());

        if (!previousCurrentCves.isEmpty()) {
            Path previous = workDirectory.resolve("previous-cves.txt");
            if (Files.exists(previous, LinkOption.NOFOLLOW_LINKS)) {
                throw new IOException("previous-cves working file already exists");
            }
            List<String> sorted = previousCurrentCves.stream().sorted().toList();
            Files.write(
                    previous,
                    sorted.stream().map(value -> value + "\n").toList(),
                    StandardCharsets.UTF_8,
                    StandardOpenOption.CREATE_NEW,
                    StandardOpenOption.WRITE);
            setOwnerOnly(previous, false);
            command.add("--previous-cves");
            command.add(previous.toString());
        }

        execute(command, workDirectory);
        if (!Files.isDirectory(bundle, LinkOption.NOFOLLOW_LINKS) || Files.isSymbolicLink(bundle)) {
            throw new IOException("public-intelligence bundle helper did not publish a safe directory");
        }
        return bundle;
    }

    private Path extractTools(Path toolsRoot) throws IOException {
        if (Files.exists(toolsRoot, LinkOption.NOFOLLOW_LINKS)) {
            throw new IOException("public-intelligence tools directory already exists");
        }
        Path scripts = toolsRoot.resolve("scripts");
        Files.createDirectories(scripts);
        setOwnerOnly(toolsRoot, true);
        setOwnerOnly(scripts, true);
        extract(FETCHER_RESOURCE, scripts.resolve("fetch-local-public-intelligence-source.py"));
        extract(BRIDGE_RESOURCE, scripts.resolve("build-public-intelligence-bundle-from-acquisition.py"));
        extract(BUILDER_RESOURCE, scripts.resolve("build-public-intelligence-sync-bundle.py"));
        return toolsRoot;
    }

    private void extract(String resource, Path target) throws IOException {
        try (InputStream input = SubprocessPublicIntelligenceSourcePipeline.class
                .getResourceAsStream(resource)) {
            if (input == null) throw new IOException("missing packaged intelligence tool: " + resource);
            Files.copy(input, target);
        }
        if (Files.isSymbolicLink(target) || !Files.isRegularFile(target, LinkOption.NOFOLLOW_LINKS)) {
            throw new IOException("packaged intelligence tool extraction is not a regular file");
        }
        setOwnerOnly(target, false);
    }

    private String execute(List<String> command, Path directory)
            throws IOException, InterruptedException {
        ProcessBuilder builder = new ProcessBuilder(List.copyOf(command));
        builder.directory(directory.toFile());
        builder.redirectErrorStream(true);
        Process process = builder.start();
        ExecutorService reader = Executors.newSingleThreadExecutor(runnable -> {
            Thread thread = new Thread(runnable, "rbvm-intelligence-tool-output");
            thread.setDaemon(true);
            return thread;
        });
        Future<String> output = reader.submit(() -> readBounded(process.getInputStream()));
        try {
            if (!process.waitFor(timeout.toMillis(), TimeUnit.MILLISECONDS)) {
                process.destroyForcibly();
                throw new IOException("public-intelligence helper timed out");
            }
            String text;
            try {
                text = output.get(5, TimeUnit.SECONDS);
            } catch (java.util.concurrent.TimeoutException exception) {
                throw new IOException("public-intelligence helper output did not terminate", exception);
            } catch (ExecutionException exception) {
                Throwable cause = exception.getCause();
                if (cause instanceof IOException ioException) throw ioException;
                throw new IOException("public-intelligence helper output read failed", cause);
            }
            if (process.exitValue() != 0) {
                throw new IOException(
                        "public-intelligence helper failed: " + safeToolOutput(text));
            }
            return text;
        } finally {
            output.cancel(true);
            reader.shutdownNow();
            if (process.isAlive()) process.destroyForcibly();
        }
    }

    private static String readBounded(InputStream input) throws IOException {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        byte[] buffer = new byte[8 * 1024];
        int read;
        while ((read = input.read(buffer)) >= 0) {
            if (read == 0) continue;
            if (output.size() + read > MAX_TOOL_OUTPUT_BYTES) {
                throw new IOException("public-intelligence helper output exceeded configured maximum");
            }
            output.write(buffer, 0, read);
        }
        return output.toString(StandardCharsets.UTF_8);
    }

    private static String safeToolOutput(String output) {
        String normalized = output == null ? "" : output
                .replace('\r', ' ')
                .replace('\n', ' ')
                .replaceAll("\\s+", " ")
                .trim();
        if (normalized.isEmpty()) return "no diagnostic output";
        return normalized.length() <= 512 ? normalized : normalized.substring(0, 512);
    }

    private static String canonicalNvdFeed(
            PostgresPublicIntelligenceStore.Provider provider,
            String requested
    ) {
        if (provider != PostgresPublicIntelligenceStore.Provider.NVD) {
            if (requested != null && !requested.isBlank()) {
                throw new IllegalArgumentException("nvdFeed is valid only for provider NVD");
            }
            return null;
        }
        String feed = requested == null || requested.isBlank() ? "modified" : requested.trim();
        if (!NVD_FEED.matcher(feed).matches()) {
            throw new IllegalArgumentException("NVD feed must be modified or a four-digit year");
        }
        if (!"modified".equals(feed)) {
            int year = Integer.parseInt(feed);
            if (year < 2002 || year > Year.now(java.time.ZoneOffset.UTC).getValue()) {
                throw new IllegalArgumentException("NVD year feed is outside the supported range");
            }
        }
        return feed;
    }

    private static String sourceUri(
            PostgresPublicIntelligenceStore.Provider provider,
            String nvdFeed,
            String version
    ) throws IOException {
        return switch (provider) {
            case NVD -> NVD_BASE + "/nvdcve-2.0-" + nvdFeed + ".json.gz";
            case FIRST_EPSS -> FIRST_EPSS;
            case CISA_KEV -> CISA_KEV;
            case CVE_PROGRAM -> {
                if (!version.matches("^[a-f0-9]{40}$")) {
                    throw new IOException("CVE Program acquisition version is not a commit SHA");
                }
                yield String.format(Locale.ROOT, CVE_ARCHIVE, version);
            }
        };
    }

    private static void requireSafeWorkDirectory(Path path) throws IOException {
        if (!Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS) || Files.isSymbolicLink(path)) {
            throw new IOException("public-intelligence work directory must be a non-symlink directory");
        }
    }

    private static void requireSafeAcquisition(Path path) throws IOException {
        if (!Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS) || Files.isSymbolicLink(path)) {
            throw new IOException("public-intelligence acquisition must be a non-symlink directory");
        }
        Path descriptor = path.resolve("acquisition.json");
        if (!Files.isRegularFile(descriptor, LinkOption.NOFOLLOW_LINKS)
                || Files.isSymbolicLink(descriptor)) {
            throw new IOException("public-intelligence acquisition descriptor is missing or unsafe");
        }
    }

    private static void requireSafeTools(Path toolsRoot) throws IOException {
        requireSafeWorkDirectory(toolsRoot);
        Path scripts = toolsRoot.resolve("scripts");
        requireSafeWorkDirectory(scripts);
        for (String name : List.of(
                "fetch-local-public-intelligence-source.py",
                "build-public-intelligence-bundle-from-acquisition.py",
                "build-public-intelligence-sync-bundle.py")) {
            Path tool = scripts.resolve(name);
            if (Files.isSymbolicLink(tool)
                    || !Files.isRegularFile(tool, LinkOption.NOFOLLOW_LINKS)) {
                throw new IOException("public-intelligence packaged tool is missing or unsafe: " + name);
            }
        }
    }

    private static void setOwnerOnly(Path path, boolean directory) {
        try {
            Files.setPosixFilePermissions(
                    path,
                    PosixFilePermissions.fromString(directory ? "rwx------" : "rw-------"));
        } catch (IOException | UnsupportedOperationException ignored) {
            // POSIX permissions are a hardening layer; non-POSIX filesystems use platform defaults.
        }
    }

    private static String textOrDefault(String value, String fallback) {
        return value == null || value.isBlank() ? fallback : value.trim();
    }

    private static long parseLong(
            String value,
            long fallback,
            long minimum,
            long maximum,
            String field
    ) {
        if (value == null || value.isBlank()) return fallback;
        try {
            long parsed = Long.parseLong(value.trim());
            if (parsed < minimum || parsed > maximum) {
                throw new IllegalArgumentException(field + " is outside the supported range");
            }
            return parsed;
        } catch (NumberFormatException exception) {
            throw new IllegalArgumentException(field + " must be an integer", exception);
        }
    }
}

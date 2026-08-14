package io.rbvm.security;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.regex.Pattern;
import java.util.Set;

/** File-backed bearer-token authentication that retains only SHA-256 token digests. */
public final class ApiKeyAuthenticator {
    private static final Pattern DIGEST = Pattern.compile("^[a-f0-9]{64}$");
    private static final Pattern ACTOR = Pattern.compile("^[A-Za-z0-9][A-Za-z0-9._@:-]{0,199}$");
    private static final AuthPrincipal LOCAL = new AuthPrincipal(
            "local-operator", ApiRole.ADMIN, "UNAUTHENTICATED_LOCAL");

    private final boolean enabled;
    private final List<KeyEntry> entries;
    private final Clock clock;

    private ApiKeyAuthenticator(boolean enabled, List<KeyEntry> entries, Clock clock) {
        this.enabled = enabled;
        this.entries = List.copyOf(entries);
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    public static ApiKeyAuthenticator disabled() {
        return new ApiKeyAuthenticator(false, List.of(), Clock.systemUTC());
    }

    public static ApiKeyAuthenticator fromEnvironment(Map<String, String> environment)
            throws IOException {
        Objects.requireNonNull(environment, "environment");
        String mode = environment.getOrDefault("RBVM_AUTH_MODE", "DISABLED").trim()
                .toUpperCase(Locale.ROOT);
        if (mode.equals("DISABLED")) {
            return disabled();
        }
        if (!mode.equals("API_KEY")) {
            throw new IllegalArgumentException("RBVM_AUTH_MODE must be DISABLED or API_KEY");
        }
        String file = environment.get("RBVM_API_KEYS_FILE");
        if (file == null || file.isBlank()) {
            throw new IllegalArgumentException("RBVM_API_KEYS_FILE is required in API_KEY mode");
        }
        return fromFile(Path.of(file.trim()), Clock.systemUTC());
    }

    public static ApiKeyAuthenticator fromFile(Path path) throws IOException {
        return fromFile(path, Clock.systemUTC());
    }

    public static ApiKeyAuthenticator fromFile(Path path, Clock clock) throws IOException {
        Objects.requireNonNull(path, "path");
        Objects.requireNonNull(clock, "clock");
        requirePrivateFile(path);
        List<KeyEntry> parsed = new ArrayList<>();
        Set<String> digests = new HashSet<>();
        int lineNumber = 0;
        for (String line : Files.readAllLines(path, StandardCharsets.UTF_8)) {
            lineNumber++;
            String value = line.trim();
            if (value.isEmpty() || value.startsWith("#")) {
                continue;
            }
            String[] assignment = value.split("=", 2);
            if (assignment.length != 2) {
                throw invalid(path, lineNumber);
            }
            String digest = assignment[0].trim().toLowerCase(Locale.ROOT);
            String[] identity = assignment[1].trim().split("\\|", -1);
            if (!DIGEST.matcher(digest).matches() || (identity.length != 2 && identity.length != 3)
                    || !ACTOR.matcher(identity[0].trim()).matches()) {
                throw invalid(path, lineNumber);
            }
            if (!digests.add(digest)) {
                throw new IOException("Duplicate API key digest at " + path + ':' + lineNumber);
            }
            ApiRole role;
            try {
                role = ApiRole.valueOf(identity[1].trim().toUpperCase(Locale.ROOT));
            } catch (IllegalArgumentException exception) {
                throw invalid(path, lineNumber);
            }
            Instant expiresAt = null;
            if (identity.length == 3 && !identity[2].isBlank()) {
                try {
                    expiresAt = Instant.parse(identity[2].trim());
                } catch (DateTimeParseException exception) {
                    throw invalid(path, lineNumber);
                }
            }
            parsed.add(new KeyEntry(
                    HexFormat.of().parseHex(digest),
                    new AuthPrincipal(identity[0].trim(), role, "API_KEY_SHA256"),
                    expiresAt
            ));
        }
        if (parsed.isEmpty()) {
            throw new IOException("API key registry contains no active keys: " + path);
        }
        if (parsed.stream().noneMatch(entry -> entry.activeAt(clock.instant()))) {
            throw new IOException("API key registry contains no unexpired keys: " + path);
        }
        return new ApiKeyAuthenticator(true, parsed, clock);
    }

    public boolean enabled() {
        return enabled;
    }

    public Optional<AuthPrincipal> authenticate(String authorizationHeader) {
        if (!enabled) {
            return Optional.of(LOCAL);
        }
        if (authorizationHeader == null
                || !authorizationHeader.regionMatches(true, 0, "Bearer ", 0, "Bearer ".length())) {
            return Optional.empty();
        }
        String token = authorizationHeader.substring("Bearer ".length()).trim();
        if (token.length() < 32 || token.length() > 512) {
            return Optional.empty();
        }
        byte[] supplied = sha256(token);
        AuthPrincipal match = null;
        for (KeyEntry entry : entries) {
            if (MessageDigest.isEqual(entry.digest(), supplied) && entry.activeAt(clock.instant())) {
                match = entry.principal();
            }
        }
        return Optional.ofNullable(match);
    }

    private static byte[] sha256(String token) {
        try {
            return MessageDigest.getInstance("SHA-256")
                    .digest(token.getBytes(StandardCharsets.UTF_8));
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is unavailable", exception);
        }
    }

    private static IOException invalid(Path path, int lineNumber) {
        return new IOException("Invalid API key registry entry at " + path + ':' + lineNumber);
    }

    private static void requirePrivateFile(Path path) throws IOException {
        if (!Files.isRegularFile(path)) {
            throw new IOException("API key registry is not a regular file: " + path);
        }
        try {
            Set<PosixFilePermission> permissions = Files.getPosixFilePermissions(path);
            if (permissions.contains(PosixFilePermission.GROUP_READ)
                    || permissions.contains(PosixFilePermission.GROUP_WRITE)
                    || permissions.contains(PosixFilePermission.GROUP_EXECUTE)
                    || permissions.contains(PosixFilePermission.OTHERS_READ)
                    || permissions.contains(PosixFilePermission.OTHERS_WRITE)
                    || permissions.contains(PosixFilePermission.OTHERS_EXECUTE)) {
                throw new IOException(
                        "API key registry must not grant group or other permissions: " + path);
            }
        } catch (UnsupportedOperationException exception) {
            // Non-POSIX filesystems use their platform ACLs; readable content is still validated.
        }
    }

    private record KeyEntry(byte[] digest, AuthPrincipal principal, Instant expiresAt) {
        private KeyEntry {
            digest = digest.clone();
        }

        @Override
        public byte[] digest() {
            return digest.clone();
        }

        private boolean activeAt(Instant instant) {
            return expiresAt == null || instant.isBefore(expiresAt);
        }
    }
}

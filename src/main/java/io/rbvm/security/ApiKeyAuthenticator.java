package io.rbvm.security;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.regex.Pattern;

/** File-backed bearer-token authentication that retains only SHA-256 token digests. */
public final class ApiKeyAuthenticator {
    private static final Pattern DIGEST = Pattern.compile("^[a-f0-9]{64}$");
    private static final Pattern ACTOR = Pattern.compile("^[A-Za-z0-9][A-Za-z0-9._@:-]{0,199}$");
    private static final AuthPrincipal LOCAL = new AuthPrincipal(
            "local-operator", ApiRole.ADMIN, "UNAUTHENTICATED_LOCAL");

    private final boolean enabled;
    private final List<KeyEntry> entries;

    private ApiKeyAuthenticator(boolean enabled, List<KeyEntry> entries) {
        this.enabled = enabled;
        this.entries = List.copyOf(entries);
    }

    public static ApiKeyAuthenticator disabled() {
        return new ApiKeyAuthenticator(false, List.of());
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
        return fromFile(Path.of(file.trim()));
    }

    public static ApiKeyAuthenticator fromFile(Path path) throws IOException {
        Objects.requireNonNull(path, "path");
        List<KeyEntry> parsed = new ArrayList<>();
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
            String[] identity = assignment[1].trim().split("\\|", 2);
            if (!DIGEST.matcher(digest).matches() || identity.length != 2
                    || !ACTOR.matcher(identity[0].trim()).matches()) {
                throw invalid(path, lineNumber);
            }
            ApiRole role;
            try {
                role = ApiRole.valueOf(identity[1].trim().toUpperCase(Locale.ROOT));
            } catch (IllegalArgumentException exception) {
                throw invalid(path, lineNumber);
            }
            parsed.add(new KeyEntry(
                    HexFormat.of().parseHex(digest),
                    new AuthPrincipal(identity[0].trim(), role, "API_KEY_SHA256")
            ));
        }
        if (parsed.isEmpty()) {
            throw new IOException("API key registry contains no active keys: " + path);
        }
        return new ApiKeyAuthenticator(true, parsed);
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
            if (MessageDigest.isEqual(entry.digest(), supplied)) {
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

    private record KeyEntry(byte[] digest, AuthPrincipal principal) {
        private KeyEntry {
            digest = digest.clone();
        }

        @Override
        public byte[] digest() {
            return digest.clone();
        }
    }
}

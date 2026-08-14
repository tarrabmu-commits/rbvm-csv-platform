package io.rbvm.security;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.HexFormat;
import java.util.Set;

public final class ApiSecuritySelfTest {
    private static final Instant NOW = Instant.parse("2026-08-14T10:00:30Z");
    private static final Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);

    private ApiSecuritySelfTest() {
    }

    public static void main(String[] args) throws Exception {
        acceptsUnexpiredAndRejectsExpiredKeys();
        rejectsDuplicateDigestsAndAllExpiredRegistries();
        rejectsRegistryReadableByOtherUsers();
        limitsActorsAndAuthenticationFailuresIndependently();
        System.out.println("ApiSecuritySelfTest: PASS");
    }

    private static void acceptsUnexpiredAndRejectsExpiredKeys() throws Exception {
        Path registry = Files.createTempFile("rbvm-keys-", ".conf");
        String active = "active-token-abcdefghijklmnopqrstuvwxyz-123456";
        String expired = "expired-token-abcdefghijklmnopqrstuvwxyz-1234";
        try {
            Files.writeString(registry,
                    digest(active) + "=active-operator|OPERATOR|2026-08-15T10:00:30Z\n"
                            + digest(expired) + "=expired-viewer|VIEWER|2026-08-13T10:00:30Z\n",
                    StandardCharsets.UTF_8);
            ApiKeyAuthenticator authenticator = ApiKeyAuthenticator.fromFile(registry, CLOCK);
            AuthPrincipal principal = authenticator.authenticate("bearer " + active).orElseThrow();
            assert principal.actorId().equals("active-operator");
            assert principal.role() == ApiRole.OPERATOR;
            assert authenticator.authenticate("Bearer " + expired).isEmpty();
        } finally {
            Files.deleteIfExists(registry);
        }
    }

    private static void rejectsDuplicateDigestsAndAllExpiredRegistries() throws Exception {
        Path registry = Files.createTempFile("rbvm-invalid-keys-", ".conf");
        String token = "duplicate-token-abcdefghijklmnopqrstuvwxyz-123";
        try {
            String digest = digest(token);
            Files.writeString(registry,
                    digest + "=one|VIEWER\n" + digest + "=two|ADMIN\n",
                    StandardCharsets.UTF_8);
            assertLoadFails(registry, "Duplicate API key digest");

            Files.writeString(registry,
                    digest + "=expired|VIEWER|2026-08-13T10:00:30Z\n",
                    StandardCharsets.UTF_8);
            assertLoadFails(registry, "no unexpired keys");
        } finally {
            Files.deleteIfExists(registry);
        }
    }

    private static void limitsActorsAndAuthenticationFailuresIndependently() {
        RequestRateLimiter limiter = RequestRateLimiter.configured(2, 1, CLOCK);
        assert limiter.checkActor("operator").permitted();
        assert limiter.checkActor("operator").permitted();
        RequestRateLimiter.Decision actorRejected = limiter.checkActor("operator");
        assert !actorRejected.permitted();
        assert actorRejected.retryAfterSeconds() == 30;
        assert limiter.checkActor("other-operator").permitted();

        assert limiter.checkAuthenticationFailure("127.0.0.1").permitted();
        RequestRateLimiter.Decision failureRejected =
                limiter.checkAuthenticationFailure("127.0.0.1");
        assert !failureRejected.permitted();
        assert failureRejected.retryAfterSeconds() == 30;
    }

    private static void rejectsRegistryReadableByOtherUsers() throws Exception {
        Path registry = Files.createTempFile("rbvm-public-keys-", ".conf");
        try {
            Files.writeString(registry,
                    digest("private-token-abcdefghijklmnopqrstuvwxyz-12345")
                            + "=operator|OPERATOR\n",
                    StandardCharsets.UTF_8);
            try {
                Files.setPosixFilePermissions(registry, Set.of(
                        PosixFilePermission.OWNER_READ,
                        PosixFilePermission.OWNER_WRITE,
                        PosixFilePermission.GROUP_READ
                ));
            } catch (UnsupportedOperationException exception) {
                return;
            }
            assertLoadFails(registry, "must not grant group or other permissions");
        } finally {
            Files.deleteIfExists(registry);
        }
    }

    private static void assertLoadFails(Path registry, String expected) throws Exception {
        try {
            ApiKeyAuthenticator.fromFile(registry, CLOCK);
            throw new AssertionError("registry should have failed: " + registry);
        } catch (IOException exception) {
            assert exception.getMessage().contains(expected) : exception.getMessage();
        }
    }

    private static String digest(String token) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                .digest(token.getBytes(StandardCharsets.UTF_8)));
    }
}

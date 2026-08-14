package io.rbvm.security;

import java.time.Clock;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/** Bounded fixed-window rate limits for authenticated actors and failed-auth sources. */
public final class RequestRateLimiter {
    private static final int DEFAULT_ACTOR_REQUESTS_PER_MINUTE = 600;
    private static final int DEFAULT_AUTH_FAILURES_PER_MINUTE = 60;
    private static final int MAXIMUM_TRACKED_IDENTITIES = 10_000;
    private static final long WINDOW_SECONDS = 60;

    private final int actorLimit;
    private final int authFailureLimit;
    private final Clock clock;
    private final ConcurrentHashMap<String, Window> windows = new ConcurrentHashMap<>();
    private final AtomicLong lastPurgeWindow = new AtomicLong(Long.MIN_VALUE);

    private RequestRateLimiter(int actorLimit, int authFailureLimit, Clock clock) {
        this.actorLimit = actorLimit;
        this.authFailureLimit = authFailureLimit;
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    public static RequestRateLimiter disabled() {
        return new RequestRateLimiter(0, 0, Clock.systemUTC());
    }

    public static RequestRateLimiter fromEnvironment(Map<String, String> environment) {
        Objects.requireNonNull(environment, "environment");
        return new RequestRateLimiter(
                parseLimit(environment, "RBVM_RATE_LIMIT_PER_MINUTE",
                        DEFAULT_ACTOR_REQUESTS_PER_MINUTE),
                parseLimit(environment, "RBVM_AUTH_FAILURE_LIMIT_PER_MINUTE",
                        DEFAULT_AUTH_FAILURES_PER_MINUTE),
                Clock.systemUTC()
        );
    }

    public static RequestRateLimiter configured(
            int actorLimit,
            int authFailureLimit,
            Clock clock
    ) {
        if (actorLimit < 0 || authFailureLimit < 0) {
            throw new IllegalArgumentException("rate limits cannot be negative");
        }
        return new RequestRateLimiter(actorLimit, authFailureLimit, clock);
    }

    public Decision checkActor(String actorId) {
        return check("actor:" + actorId, actorLimit);
    }

    public Decision checkAuthenticationFailure(String source) {
        return check("auth-failure:" + source, authFailureLimit);
    }

    private Decision check(String identity, int limit) {
        if (limit == 0) {
            return Decision.allowed();
        }
        long epochSecond = clock.instant().getEpochSecond();
        long windowNumber = Math.floorDiv(epochSecond, WINDOW_SECONDS);
        purgeExpired(windowNumber);
        if (!windows.containsKey(identity) && windows.size() >= MAXIMUM_TRACKED_IDENTITIES) {
            return Decision.rejected(retryAfter(epochSecond));
        }
        Window current = windows.compute(identity, (key, previous) -> {
            if (previous == null || previous.windowNumber() != windowNumber) {
                return new Window(windowNumber, 1);
            }
            return new Window(windowNumber, previous.count() + 1);
        });
        return current.count() <= limit
                ? Decision.allowed()
                : Decision.rejected(retryAfter(epochSecond));
    }

    private void purgeExpired(long currentWindow) {
        long prior = lastPurgeWindow.get();
        if (prior == currentWindow || !lastPurgeWindow.compareAndSet(prior, currentWindow)) {
            return;
        }
        windows.entrySet().removeIf(entry -> entry.getValue().windowNumber() < currentWindow);
    }

    private static int retryAfter(long epochSecond) {
        return Math.toIntExact(WINDOW_SECONDS - Math.floorMod(epochSecond, WINDOW_SECONDS));
    }

    private static int parseLimit(Map<String, String> environment, String name, int fallback) {
        String value = environment.get(name);
        if (value == null || value.isBlank()) {
            return fallback;
        }
        try {
            int parsed = Integer.parseInt(value.trim());
            if (parsed < 0 || parsed > 1_000_000) {
                throw new IllegalArgumentException(name + " must be between 0 and 1000000");
            }
            return parsed;
        } catch (NumberFormatException exception) {
            throw new IllegalArgumentException(name + " must be an integer", exception);
        }
    }

    public record Decision(boolean permitted, int retryAfterSeconds) {
        private static Decision allowed() {
            return new Decision(true, 0);
        }

        private static Decision rejected(int retryAfterSeconds) {
            return new Decision(false, retryAfterSeconds);
        }
    }

    private record Window(long windowNumber, int count) {
    }
}

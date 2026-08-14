package io.rbvm.security;

import java.util.Objects;

/** Identity established by the HTTP authentication boundary. */
public record AuthPrincipal(String actorId, ApiRole role, String assurance) {
    public AuthPrincipal {
        Objects.requireNonNull(actorId, "actorId");
        Objects.requireNonNull(role, "role");
        Objects.requireNonNull(assurance, "assurance");
    }
}

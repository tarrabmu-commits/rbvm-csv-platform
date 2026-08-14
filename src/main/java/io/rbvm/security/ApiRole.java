package io.rbvm.security;

/** Coarse-grained API roles ordered by increasing privilege. */
public enum ApiRole {
    VIEWER,
    OPERATOR,
    ADMIN;

    public boolean permits(ApiRole required) {
        return ordinal() >= required.ordinal();
    }
}

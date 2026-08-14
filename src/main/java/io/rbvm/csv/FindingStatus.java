package io.rbvm.csv;

import java.util.Locale;

public enum FindingStatus {
    ACTIVE,
    RESOLVED;

    public static FindingStatus parse(String value) {
        try {
            return valueOf(value.trim().toUpperCase(Locale.ROOT));
        } catch (RuntimeException exception) {
            throw new IllegalArgumentException("Finding_Status must be ACTIVE or RESOLVED");
        }
    }
}

package io.rbvm.csv;

import java.util.Locale;

public enum CsvSeverity {
    CRITICAL,
    HIGH,
    MEDIUM,
    LOW,
    UNKNOWN;

    public static ParseResult parse(String source) {
        String value = source == null ? "" : source.trim();
        if (value.isEmpty() || value.equals("-") || value.equalsIgnoreCase("unknown")) {
            return new ParseResult(UNKNOWN, true);
        }

        try {
            return new ParseResult(valueOf(value.toUpperCase(Locale.ROOT)), true);
        } catch (IllegalArgumentException ignored) {
            return new ParseResult(UNKNOWN, false);
        }
    }

    public record ParseResult(CsvSeverity value, boolean recognized) {
    }
}


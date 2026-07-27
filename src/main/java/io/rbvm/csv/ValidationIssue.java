package io.rbvm.csv;

public record ValidationIssue(
        long rowNumber,
        Level level,
        String code,
        String message
) {
    public enum Level {
        WARNING,
        ERROR
    }
}


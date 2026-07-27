package io.rbvm.postgres;

import java.io.IOException;
import java.sql.SQLException;

final class PostgresErrors {
    private PostgresErrors() {
    }

    static IOException sanitized(String operation, SQLException exception) {
        return new IOException(operation + " [SQLState=" + sqlState(exception) + "]");
    }

    static String safeMessage(SQLException exception) {
        return exception.getClass().getSimpleName() + " [SQLState=" + sqlState(exception) + "]";
    }

    private static String sqlState(SQLException exception) {
        String state = exception.getSQLState();
        return state == null || state.isBlank() ? "unavailable" : state;
    }
}

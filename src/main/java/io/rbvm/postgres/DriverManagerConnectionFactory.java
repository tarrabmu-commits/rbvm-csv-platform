package io.rbvm.postgres;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.Objects;
import java.util.Properties;

public final class DriverManagerConnectionFactory implements JdbcConnectionFactory {
    private final String jdbcUrl;
    private final Properties properties;

    public DriverManagerConnectionFactory(String jdbcUrl, String user, String password) {
        this.jdbcUrl = Objects.requireNonNull(jdbcUrl, "jdbcUrl");
        properties = new Properties();
        properties.setProperty("user", Objects.requireNonNull(user, "user"));
        properties.setProperty("password", Objects.requireNonNull(password, "password"));
        properties.setProperty("ApplicationName", "rbvm-csv-platform");
    }

    @Override
    public Connection open() throws SQLException {
        return DriverManager.getConnection(jdbcUrl, properties);
    }
}

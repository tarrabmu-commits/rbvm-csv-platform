package io.rbvm.postgres;

import java.io.IOException;
import java.sql.SQLException;
import java.time.Clock;

public final class PostgresScannerManagedAssetLinkRegistrySelfTest {
    private PostgresScannerManagedAssetLinkRegistrySelfTest() {
    }

    public static void main(String[] args) throws Exception {
        requiresSchemaMigrationV19();
        System.out.println("PostgresScannerManagedAssetLinkRegistrySelfTest: PASS");
    }

    private static void requiresSchemaMigrationV19() throws Exception {
        JdbcConnectionFactory unused = () -> {
            throw new SQLException("must not open connection in schema-version constructor");
        };
        PostgresScannerManagedAssetLinkRegistry accepted =
                new PostgresScannerManagedAssetLinkRegistry(unused, 19, Clock.systemUTC());
        assert accepted.schemaVersion() == 19;

        boolean rejected = false;
        try {
            new PostgresScannerManagedAssetLinkRegistry(unused, 18, Clock.systemUTC());
        } catch (IOException expected) {
            rejected = true;
        }
        assert rejected;
    }
}

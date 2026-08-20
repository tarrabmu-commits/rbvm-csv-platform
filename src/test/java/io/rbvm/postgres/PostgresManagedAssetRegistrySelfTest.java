package io.rbvm.postgres;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.time.Clock;

public final class PostgresManagedAssetRegistrySelfTest {
    private PostgresManagedAssetRegistrySelfTest() {
    }

    public static void main(String[] args) throws Exception {
        rejectsPreV18Schema();
        acceptsV18SchemaWithoutOpeningConnection();
        bundlesV18Migration();
        System.out.println("PostgresManagedAssetRegistrySelfTest: PASS");
    }

    private static void rejectsPreV18Schema() {
        boolean rejected = false;
        try {
            new PostgresManagedAssetRegistry(
                    () -> { throw new AssertionError("connection must not be opened"); },
                    17,
                    Clock.systemUTC()
            );
        } catch (IOException expected) {
            rejected = expected.getMessage().contains("required version 18");
        }
        assert rejected;
    }

    private static void acceptsV18SchemaWithoutOpeningConnection() throws Exception {
        PostgresManagedAssetRegistry registry = new PostgresManagedAssetRegistry(
                () -> { throw new AssertionError("connection must not be opened"); },
                18,
                Clock.systemUTC()
        );
        assert registry.schemaVersion() == 18;
    }

    private static void bundlesV18Migration() throws Exception {
        try (InputStream input = PostgresManagedAssetRegistrySelfTest.class.getResourceAsStream(
                "/db/migration/V18__managed_asset_registry.sql")) {
            assert input != null : "V18 migration must be bundled in runtime resources";
            String sql = new String(input.readAllBytes(), StandardCharsets.UTF_8);
            assert sql.contains("CREATE TABLE rbvm.managed_asset (");
            assert sql.contains("CREATE TABLE rbvm.managed_asset_revision (");
            assert sql.contains("CREATE VIEW rbvm.current_managed_asset AS");
        }
    }
}

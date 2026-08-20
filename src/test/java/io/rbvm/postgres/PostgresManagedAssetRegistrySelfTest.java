package io.rbvm.postgres;

import java.io.IOException;
import java.time.Clock;

public final class PostgresManagedAssetRegistrySelfTest {
    private PostgresManagedAssetRegistrySelfTest() {
    }

    public static void main(String[] args) throws Exception {
        rejectsPreV18Schema();
        acceptsV18SchemaWithoutOpeningConnection();
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
}

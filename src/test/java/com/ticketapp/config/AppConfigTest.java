
package com.ticketapp.config;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

public class AppConfigTest {

    @TempDir
    Path tempDir;

    // Create a valid configuration for testing.
    private Map<String, String> validConfig() {
        Map<String, String> env = new HashMap<>();

        env.put(AppConfig.ENV_DB_URL, "jdbc:h2:mem:test");
        env.put(AppConfig.ENV_DB_USER, "testuser");
        env.put(AppConfig.ENV_DB_PASSWORD, "testpassword");
        env.put(
                AppConfig.ENV_FIELD_KEY,
                Base64.getEncoder().encodeToString(new byte[32])
        );
        env.put(
                AppConfig.ENV_DATA_DIR,
                tempDir.resolve("ticket-data").toString()
        );

        return env;
    }

    // CWE-455: Reject missing configuration.
    @Test
    public void testMissingEnvironmentVariable() {
        Map<String, String> env = validConfig();
        env.remove(AppConfig.ENV_DB_PASSWORD);

        assertThrows(
                SecurityConfigException.class,
                () -> AppConfig.load(env)
        );
    }

    // CWE-455: Reject blank configuration.
    @Test
    public void testBlankEnvironmentVariable() {
        Map<String, String> env = validConfig();
        env.put(AppConfig.ENV_DB_USER, " ");

        assertThrows(
                SecurityConfigException.class,
                () -> AppConfig.load(env)
        );
    }

    // CWE-455: Reject invalid Base64 keys.
    @Test
    public void testInvalidEncryptionKeyFormat() {
        Map<String, String> env = validConfig();
        env.put(AppConfig.ENV_FIELD_KEY, "not-valid-@@@");

        assertThrows(
                SecurityConfigException.class,
                () -> AppConfig.load(env)
        );
    }

    // CWE-455: Reject incorrect AES key length.
    @Test
    public void testInvalidEncryptionKeyLength() {
        Map<String, String> env = validConfig();

        env.put(
                AppConfig.ENV_FIELD_KEY,
                Base64.getEncoder().encodeToString(new byte[16])
        );

        assertThrows(
                SecurityConfigException.class,
                () -> AppConfig.load(env)
        );
    }

    // CWE-455: Accept valid configuration.
    @Test
    public void testValidConfiguration() throws Exception {
        AppConfig config = AppConfig.load(validConfig());

        assertEquals("jdbc:h2:mem:test", config.dbUrl());
        assertEquals("testuser", config.dbUser());
        assertEquals(32, config.fieldKey().length);
    }

    // CWE-455: Create required directories.
    @Test
    public void testSecureDirectoryCreation() throws Exception {
        AppConfig config = AppConfig.load(validConfig());

        assertTrue(Files.isDirectory(config.dataDir()));
        assertTrue(Files.isDirectory(config.attachmentsDir()));
        assertTrue(Files.isDirectory(config.exportsDir()));
    }
}

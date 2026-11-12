
package com.ticketapp.config;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.FileSystems;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Duration;
import java.util.Base64;
import java.util.Map;

/**
 * Runtime configuration loaded at startup.
 *
 * CWE-798 (Caleb):
 * Credentials and encryption keys come from environment variables.
 *
 * CWE-455 (Kimlay):
 * Reject invalid configuration and stop initialization.
 */
public final class AppConfig {

    // Environment variable names
    public static final String ENV_DB_URL = "TICKETAPP_DB_URL";
    public static final String ENV_DB_USER = "TICKETAPP_DB_USER";
    public static final String ENV_DB_PASSWORD = "TICKETAPP_DB_PASSWORD";
    public static final String ENV_FIELD_KEY = "TICKETAPP_FIELD_KEY";
    public static final String ENV_DATA_DIR = "TICKETAPP_DATA_DIR";

    // Security limits
    public static final int MAX_FAILED_LOGINS = 5;
    public static final Duration LOCKOUT_BASE =
            Duration.ofMinutes(1);
    public static final Duration LOCKOUT_MAX =
            Duration.ofMinutes(15);
    public static final Duration SESSION_IDLE_TIMEOUT =
            Duration.ofMinutes(15);
    public static final int PBKDF2_ITERATIONS = 600_000;
    public static final int MAX_DESCRIPTION_LENGTH = 4_000;
    public static final int MAX_OPEN_TICKETS_PER_USER = 20;

    private final String dbUrl;
    private final String dbUser;
    private final char[] dbPassword;
    private final byte[] fieldKey;
    private final Path dataDir;

    private AppConfig(
            String dbUrl,
            String dbUser,
            char[] dbPassword,
            byte[] fieldKey,
            Path dataDir) {

        this.dbUrl = dbUrl;
        this.dbUser = dbUser;
        this.dbPassword = dbPassword.clone();
        this.fieldKey = fieldKey.clone();
        this.dataDir = dataDir;
    }

    /**
     * Load configuration from operating system environment.
     */
    public static AppConfig load()
            throws SecurityConfigException {

        return load(System.getenv());
    }

    /**
     * Validate all required settings before initialization.
     * Map parameter allows unit testing.
     */
    public static AppConfig load(Map<String, String> env)
            throws SecurityConfigException {

        if (env == null) {
            throw new SecurityConfigException(
                    "Configuration environment is missing");
        }

        // CWE-798: No hard-coded credentials.
        String dbUrl = require(env, ENV_DB_URL);
        String dbUser = require(env, ENV_DB_USER);
        String dbPassword = require(env, ENV_DB_PASSWORD);
        String encodedKey = require(env, ENV_FIELD_KEY);
        String directory = require(env, ENV_DATA_DIR);

        // CWE-455: Reject invalid encryption keys.
        byte[] fieldKey;

        try {
            fieldKey = Base64.getDecoder().decode(encodedKey);
        } catch (IllegalArgumentException e) {
            throw new SecurityConfigException(
                    "Invalid encryption key format", e);
        }

        if (fieldKey.length != 32) {
            throw new SecurityConfigException(
                    "Encryption key must be 32 bytes for AES-256");
        }

        // Validate data directory.
        Path dataDir;

        try {
            dataDir = Path.of(directory)
                    .toAbsolutePath()
                    .normalize();
        } catch (RuntimeException e) {
            throw new SecurityConfigException(
                    "Invalid data directory path", e);
        }

        // Create secure directories.
        try {
            createSecureDirectory(dataDir);
            createSecureDirectory(
                    dataDir.resolve("attachments"));
            createSecureDirectory(
                    dataDir.resolve("exports"));

        } catch (IOException | SecurityException e) {
            throw new SecurityConfigException(
                    "Failed to initialize secure directories", e);
        }

        return new AppConfig(
                dbUrl,
                dbUser,
                dbPassword.toCharArray(),
                fieldKey,
                dataDir
        );
    }

    /**
     * Require a nonblank configuration value.
     */
    private static String require(
            Map<String, String> env,
            String name)
            throws SecurityConfigException {

        String value = env.get(name);

        if (value == null || value.isBlank()) {
            throw new SecurityConfigException(
                    "Missing required environment variable: " + name);
        }

        return value;
    }

    /**
     * Create directories and restrict access.
     */
    private static void createSecureDirectory(Path dir)
            throws IOException {

        Files.createDirectories(dir);

        if (!Files.isDirectory(dir)) {
            throw new IOException(
                    "Data path is not a directory");
        }

        // Owner-only access on POSIX systems.
        if (FileSystems.getDefault()
                .supportedFileAttributeViews()
                .contains("posix")) {

            Files.setPosixFilePermissions(
                    dir,
                    PosixFilePermissions.fromString(
                            "rwx------"));
        }
    }

    // Getters

    public String dbUrl() {
        return dbUrl;
    }

    public String dbUser() {
        return dbUser;
    }

    public char[] dbPassword() {
        return dbPassword.clone();
    }

    public byte[] fieldKey() {
        return fieldKey.clone();
    }

    public Path dataDir() {
        return dataDir;
    }

    public Path attachmentsDir() {
        return dataDir.resolve("attachments");
    }

    public Path exportsDir() {
        return dataDir.resolve("exports");
    }
}


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
 * All runtime configuration, loaded once at startup.
 *
 * CWE-798 Hard-coded Credentials (Caleb):
 * DB password and encryption key come from environment variables.
 *
 * CWE-455 Non-exit on Failed Initialization (Kimlay):
 * Reject missing or invalid security configuration.
 */
public final class AppConfig {

    // Environment variable names
    public static final String ENV_DB_URL = "TICKETAPP_DB_URL";
    public static final String ENV_DB_USER = "TICKETAPP_DB_USER";
    public static final String ENV_DB_PASSWORD = "TICKETAPP_DB_PASSWORD";
    public static final String ENV_FIELD_KEY = "TICKETAPP_FIELD_KEY";
    public static final String ENV_DATA_DIR = "TICKETAPP_DATA_DIR";

    // Security configuration constants
    public static final int MAX_FAILED_LOGINS = 5;
    public static final Duration LOCKOUT_BASE = Duration.ofMinutes(1);
    public static final Duration LOCKOUT_MAX = Duration.ofMinutes(15);
    public static final Duration SESSION_IDLE_TIMEOUT = Duration.ofMinutes(15);
    public static final int PBKDF2_ITERATIONS = 600_000;
    public static final int MAX_DESCRIPTION_LENGTH = 4_000;
    public static final int MAX_OPEN_TICKETS_PER_USER = 20;

    private final String dbUrl;
    private final String dbUser;
    private final char[] dbPassword;
    private final byte[] fieldKey;
    private final Path dataDir;

    private AppConfig(String dbUrl, String dbUser,
                      char[] dbPassword, byte[] fieldKey,
                      Path dataDir) {
        this.dbUrl = dbUrl;
        this.dbUser = dbUser;
        this.dbPassword = dbPassword;
        this.fieldKey = fieldKey;
        this.dataDir = dataDir;
    }

    /**
     * CWE-455: Load configuration at startup.
     * Stop initialization if required settings are invalid.
     */
    public static AppConfig load()
            throws SecurityConfigException {
        return load(System.getenv());
    }

    /**
     * Load and validate configuration values.
     * The Map parameter also allows unit testing.
     */
    public static AppConfig load(Map<String, String> env)
            throws SecurityConfigException {

        if (env == null) {
            throw new SecurityConfigException(
                    "Configuration environment is missing");
        }

        // Validate required environment variables
        String dbUrl = require(env, ENV_DB_URL);
        String dbUser = require(env, ENV_DB_USER);
        String dbPassword = require(env, ENV_DB_PASSWORD);
        String encodedKey = require(env, ENV_FIELD_KEY);
        String directory = require(env, ENV_DATA_DIR);

        // Validate AES-256 encryption key
        byte[] fieldKey;

        try {
            fieldKey = Base64.getDecoder().decode(encodedKey);
        } catch (IllegalArgumentException e) {
            throw new SecurityConfigException(
                    "Invalid encryption key format", e);
        }

        if (fieldKey.length != 32) {
            throw new SecurityConfigException(
                    "Encryption key must be 32 bytes");
        }

        // Validate the data directory path
        Path dataDir;

        try {
            dataDir = Path.of(directory)
                    .toAbsolutePath()
                    .normalize();
        } catch (RuntimeException e) {
            throw new SecurityConfigException(
                    "Invalid data directory", e);
        }

        // Initialize secure directories
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

        // Initialization succeeded
        return new AppConfig(
                dbUrl,
                dbUser,
                dbPassword.toCharArray(),
                fieldKey,
                dataDir
        );
    }

    /**
     * Reject missing or blank configuration values.
     */
    private static String require(
            Map<String, String> env,
            String name) throws SecurityConfigException {

        String value = env.get(name);

        if (value == null || value.isBlank()) {
            throw new SecurityConfigException(
                    "Missing required configuration: " + name);
        }

        return value;
    }

    /**
     * Create directories with owner-only permissions.
     */
    private static void createSecureDirectory(Path dir)
            throws IOException {

        Files.createDirectories(dir);

        if (!Files.isDirectory(dir)) {
            throw new IOException(
                    "Data path is not a directory");
        }

        // Apply POSIX permissions on macOS/Linux
        if (FileSystems.getDefault()
                .supportedFileAttributeViews()
                .contains("posix")) {

            Files.setPosixFilePermissions(
                    dir,
                    PosixFilePermissions.fromString(
                            "rwx------"));
        }
    }

    // Configuration getters
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

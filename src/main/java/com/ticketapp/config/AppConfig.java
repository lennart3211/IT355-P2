package com.ticketapp.config;

import java.nio.file.Path;
import java.time.Duration;

/**
 * All runtime configuration, loaded once at startup.
 *
 * CWE-798 Hard-coded Credentials (Caleb):
 *   DB password and the field-encryption key come from environment variables,
 *   never from source code or a committed config file.
 * CWE-455 Non-exit on Failed Initialization (Kimlay):
 *   load() throws SecurityConfigException if anything required is missing;
 *   Main exits instead of continuing.
 */
public final class AppConfig {

    // Env var names (values are NOT in source code)
    public static final String ENV_DB_URL = "TICKETAPP_DB_URL";
    public static final String ENV_DB_USER = "TICKETAPP_DB_USER";
    public static final String ENV_DB_PASSWORD = "TICKETAPP_DB_PASSWORD";
    public static final String ENV_FIELD_KEY = "TICKETAPP_FIELD_KEY";       // CWE-312 encryption key
    public static final String ENV_DATA_DIR = "TICKETAPP_DATA_DIR";

    // Documented limits / policy values (tune as a team)
    public static final int MAX_FAILED_LOGINS = 5;                            // CWE-307
    public static final Duration LOCKOUT_BASE = Duration.ofMinutes(1);       // CWE-645 bounded backoff
    public static final Duration LOCKOUT_MAX = Duration.ofMinutes(15);       // CWE-645 cap
    public static final Duration SESSION_IDLE_TIMEOUT = Duration.ofMinutes(15); // CWE-1463
    public static final int PBKDF2_ITERATIONS = 600_000;                      // CWE-916 (document rationale)
    public static final int MAX_DESCRIPTION_LENGTH = 4_000;                   // CWE-770
    public static final int MAX_OPEN_TICKETS_PER_USER = 20;                   // CWE-770

    private final String dbUrl;
    private final String dbUser;
    private final char[] dbPassword;
    private final byte[] fieldKey;
    private final Path dataDir;

    private AppConfig(String dbUrl, String dbUser, char[] dbPassword, byte[] fieldKey, Path dataDir) {
        this.dbUrl = dbUrl;
        this.dbUser = dbUser;
        this.dbPassword = dbPassword;
        this.fieldKey = fieldKey;
        this.dataDir = dataDir;
    }

    /** Loads and validates config from the environment. Throws on anything missing/invalid. */
    public static AppConfig load() throws SecurityConfigException {
        // TODO: read each ENV_* via System.getenv(); throw if null/blank
        // TODO: decode ENV_FIELD_KEY (e.g. Base64) and verify it is 32 bytes for AES-256
        // TODO: verify dataDir exists; create attachments/ and exports/ with owner-only perms
        for (String env : new String[]{ENV_DB_URL, ENV_DB_USER, ENV_DB_PASSWORD, ENV_FIELD_KEY, ENV_DATA_DIR}) {
            String value = System.getenv(env);
            if (value == null || value.isBlank()) {
                throw new SecurityConfigException("Missing required environment variable: " + env);
            }
        }

        return new AppConfig(
                System.getenv(ENV_DB_URL),
                System.getenv(ENV_DB_USER),
                System.getenv(ENV_DB_PASSWORD).toCharArray(),
                java.util.Base64.getDecoder().decode(System.getenv(ENV_FIELD_KEY)),
                Path.of(System.getenv(ENV_DATA_DIR))
        );
    }

    public String dbUrl() { return dbUrl; }
    public String dbUser() { return dbUser; }
    public char[] dbPassword() { return dbPassword.clone(); }
    public byte[] fieldKey() { return fieldKey.clone(); }
    public Path dataDir() { return dataDir; }
    public Path attachmentsDir() { return dataDir.resolve("attachments"); }
    public Path exportsDir() { return dataDir.resolve("exports"); }       // CWE-552 protected folder
}

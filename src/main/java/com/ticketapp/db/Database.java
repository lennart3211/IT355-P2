package com.ticketapp.db;

import com.ticketapp.config.AppConfig;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;

/**
 * Connection factory.
 *
 * CWE-798 (Caleb): credentials come from AppConfig (env vars), never literals.
 * CWE-772 Missing Release of Resource (Jocelyn): callers MUST use
 *   try-with-resources:  try (Connection c = db.connect(); PreparedStatement ps = ...) { }
 */
public class Database {

    private final AppConfig config;

    public Database(AppConfig config) {
        this.config = config;
    }

    public Connection connect() throws SQLException {
        char[] pw = config.dbPassword();
        try {
            return DriverManager.getConnection(config.dbUrl(), config.dbUser(), new String(pw));
        } finally {
            java.util.Arrays.fill(pw, '\0');
        }
    }

    /** Create tables if missing. Called once at startup; failure must abort startup (CWE-455). */
    public void initSchema() throws SQLException {
        // TODO: CREATE TABLE IF NOT EXISTS users(...), tickets(...), sessions(...), audit_log(...)
        //       tickets needs a 'version' column for optimistic locking (CWE-820/821)
        throw new UnsupportedOperationException("TODO");
    }
}

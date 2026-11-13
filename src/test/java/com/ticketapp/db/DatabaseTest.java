
package com.ticketapp.db;

import com.ticketapp.config.AppConfig;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

import java.lang.reflect.Constructor;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.ResultSet;



public class DatabaseTest {

    private Database createDatabase() throws Exception {
        Path dataDir = Files.createTempDirectory("ticketapp-test");

        Constructor<AppConfig> constructor =
                AppConfig.class.getDeclaredConstructor(
                        String.class,
                        String.class,
                        char[].class,
                        byte[].class,
                        Path.class
                );

        constructor.setAccessible(true);

        AppConfig config = constructor.newInstance(
                "jdbc:h2:mem:ticketdb;DB_CLOSE_DELAY=-1",
                "sa",
                new char[0],
                new byte[32],
                dataDir
        );

        return new Database(config);
    }

    private boolean tableExists(Connection conn, String table)
            throws Exception {

        DatabaseMetaData meta = conn.getMetaData();

        try (ResultSet rs = meta.getTables(
                null, null, table.toUpperCase(),
                new String[]{"TABLE"})) {
            return rs.next();
        }
    }

    private boolean columnExists(Connection conn,
                                 String table,
                                 String column) throws Exception {

        try (ResultSet rs = conn.getMetaData().getColumns(
                null, null,
                table.toUpperCase(),
                column.toUpperCase())) {
            return rs.next();
        }
    }

    @Test
    public void testTablesCreated() throws Exception {
        Database db = createDatabase();
        db.initSchema();

        try (Connection conn = db.connect()) {
            assertTrue(tableExists(conn, "users"));
            assertTrue(tableExists(conn, "sessions"));
            assertTrue(tableExists(conn, "tickets"));
        }
    }

    @Test
    public void testUserColumns() throws Exception {
        Database db = createDatabase();
        db.initSchema();

        try (Connection conn = db.connect()) {
            assertTrue(columnExists(conn, "users", "password_hash"));
            assertTrue(columnExists(conn, "users", "salt"));
            assertTrue(columnExists(conn, "users", "role_name"));
            assertTrue(columnExists(conn, "users", "failed_logins"));
            assertTrue(columnExists(conn, "users", "locked_until"));
            assertTrue(columnExists(conn, "users", "lockout_count"));
        }
    }

    @Test
    public void testTicketColumns() throws Exception {
        Database db = createDatabase();
        db.initSchema();

        try (Connection conn = db.connect()) {
            assertTrue(columnExists(conn, "tickets", "owner_id"));
            assertTrue(columnExists(conn, "tickets", "assignee_id"));
            assertTrue(columnExists(conn, "tickets", "status"));
            assertTrue(columnExists(conn, "tickets", "version"));
            assertTrue(columnExists(conn, "tickets", "contact_enc"));
        }
    }

    @Test
    public void testSessionColumns() throws Exception {
        Database db = createDatabase();
        db.initSchema();

        try (Connection conn = db.connect()) {
            assertTrue(columnExists(conn, "sessions", "token_hash"));
            assertTrue(columnExists(conn, "sessions", "user_id"));
            assertTrue(columnExists(conn, "sessions", "last_activity"));
        }
    }

    @Test
    public void testRepeatedInitialization() throws Exception {
        Database db = createDatabase();

        db.initSchema();
        db.initSchema();

        try (Connection conn = db.connect()) {
            assertTrue(tableExists(conn, "users"));
            assertTrue(tableExists(conn, "sessions"));
            assertTrue(tableExists(conn, "tickets"));
        }
    }
}

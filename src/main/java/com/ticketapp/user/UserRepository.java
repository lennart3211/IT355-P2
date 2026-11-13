package com.ticketapp.user;

import com.ticketapp.db.Database;
import com.ticketapp.model.Role;
import com.ticketapp.model.User;
import com.ticketapp.ticket.FieldEncryptor;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Types;
import java.time.Instant;
import java.util.Objects;
import java.util.Optional;

/**
 * DB access for users.
 * CWE-89: PreparedStatement only.  CWE-772: try-with-resources on every Connection/Statement/ResultSet.
 * CWE-312: email/phone are encrypted via FieldEncryptor before insert and decrypted after select.
 */
public class UserRepository {

    private static final String SELECT_USER = """
            SELECT id, username, password_hash, salt, iterations, role_name,
                   email_encrypted, phone_encrypted, must_change_password,
                   failed_logins, locked_until, lockout_count
            FROM users
            """;

    private final Database db;
    private final FieldEncryptor encryptor;   // may be null if email/phone are never stored

    public UserRepository(Database db) {
        this(db, null);
    }

    public UserRepository(Database db, FieldEncryptor encryptor) {
        this.db = Objects.requireNonNull(db, "db");
        this.encryptor = encryptor;
    }

    public Optional<User> findByUsername(String username) {
        if (username == null) {
            return Optional.empty();
        }
        return findOne(SELECT_USER + " WHERE username = ?", ps -> ps.setString(1, username));
    }

    public Optional<User> findById(long id) {
        return findOne(SELECT_USER + " WHERE id = ?", ps -> ps.setLong(1, id));
    }

    public User insert(User user) {
        Objects.requireNonNull(user, "user");

        String sql = """
                INSERT INTO users
                (username, password_hash, salt, iterations, role_name,
                 email_encrypted, phone_encrypted, must_change_password,
                 failed_logins, locked_until, lockout_count)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """;

        try (Connection conn = db.connect();
             PreparedStatement ps = conn.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS)) {

            ps.setString(1, user.getUsername());
            ps.setBytes(2, user.getPasswordHash());
            ps.setBytes(3, user.getSalt());
            ps.setInt(4, user.getIterations());
            ps.setString(5, user.getRole().name());
            ps.setString(6, encrypt(user.getEmail()));
            ps.setString(7, encrypt(user.getPhone()));
            ps.setBoolean(8, user.isMustChangePassword());
            ps.setInt(9, user.getFailedLogins());
            setInstant(ps, 10, user.getLockedUntil());
            ps.setInt(11, user.getLockoutCount());
            ps.executeUpdate();

            try (ResultSet keys = ps.getGeneratedKeys()) {
                if (keys.next()) {
                    user.setId(keys.getLong(1));
                }
            }
            return user;
        } catch (SQLException e) {
            throw new IllegalStateException("Could not save user", e);
        }
    }

    public void updatePassword(long userId, byte[] hash, byte[] salt, int iterations, boolean mustChange) {
        String sql = """
                UPDATE users
                SET password_hash = ?, salt = ?, iterations = ?, must_change_password = ?
                WHERE id = ?
                """;

        try (Connection conn = db.connect();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setBytes(1, hash);
            ps.setBytes(2, salt);
            ps.setInt(3, iterations);
            ps.setBoolean(4, mustChange);
            ps.setLong(5, userId);
            ps.executeUpdate();
        } catch (SQLException e) {
            throw new IllegalStateException("Could not update password", e);
        }
    }

    public void updateRole(long userId, Role role) {
        Objects.requireNonNull(role, "role");

        try (Connection conn = db.connect();
             PreparedStatement ps = conn.prepareStatement(
                     "UPDATE users SET role_name = ? WHERE id = ?")) {
            ps.setString(1, role.name());
            ps.setLong(2, userId);
            ps.executeUpdate();
        } catch (SQLException e) {
            throw new IllegalStateException("Could not update role", e);
        }
    }

    public void updateLockState(User user) {
        Objects.requireNonNull(user, "user");

        String sql = """
                UPDATE users
                SET failed_logins = ?, locked_until = ?, lockout_count = ?
                WHERE id = ?
                """;

        try (Connection conn = db.connect();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setInt(1, user.getFailedLogins());
            setInstant(ps, 2, user.getLockedUntil());
            ps.setInt(3, user.getLockoutCount());
            ps.setLong(4, user.getId());
            ps.executeUpdate();
        } catch (SQLException e) {
            throw new IllegalStateException("Could not update lock state", e);
        }
    }

    // ---- helpers ----

    @FunctionalInterface
    private interface Binder {
        void bind(PreparedStatement ps) throws SQLException;
    }

    private Optional<User> findOne(String sql, Binder binder) {
        try (Connection conn = db.connect();
             PreparedStatement ps = conn.prepareStatement(sql)) {
            binder.bind(ps);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next() ? Optional.of(map(rs)) : Optional.empty();
            }
        } catch (SQLException e) {
            throw new IllegalStateException("Could not load user", e);
        }
    }

    private User map(ResultSet rs) throws SQLException {
        User user = new User();
        user.setId(rs.getLong("id"));
        user.setUsername(rs.getString("username"));
        user.setPasswordHash(rs.getBytes("password_hash"));
        user.setSalt(rs.getBytes("salt"));
        user.setIterations(rs.getInt("iterations"));
        user.setRole(Role.valueOf(rs.getString("role_name")));
        user.setEmail(decrypt(rs.getString("email_encrypted")));
        user.setPhone(decrypt(rs.getString("phone_encrypted")));
        user.setMustChangePassword(rs.getBoolean("must_change_password"));
        user.setFailedLogins(rs.getInt("failed_logins"));

        long lockedUntil = rs.getLong("locked_until");
        user.setLockedUntil(rs.wasNull() ? null : Instant.ofEpochMilli(lockedUntil));

        user.setLockoutCount(rs.getInt("lockout_count"));
        return user;
    }

    private static void setInstant(PreparedStatement ps, int index, Instant value) throws SQLException {
        if (value == null) {
            ps.setNull(index, Types.BIGINT);
        } else {
            ps.setLong(index, value.toEpochMilli());
        }
    }

    // CWE-312: never store email/phone in plaintext.
    private String encrypt(String value) {
        if (value == null) {
            return null;
        }
        if (encryptor == null) {
            throw new IllegalStateException("FieldEncryptor required to store contact details");
        }
        return encryptor.encrypt(value);
    }

    private String decrypt(String stored) {
        if (stored == null || encryptor == null) {
            return null;
        }
        return encryptor.decrypt(stored);
    }
}
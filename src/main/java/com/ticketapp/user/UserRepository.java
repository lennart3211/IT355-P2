package com.ticketapp.user;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Instant;
import java.util.Optional;

import com.ticketapp.db.Database;
import com.ticketapp.model.Role;
import com.ticketapp.model.User;
import com.ticketapp.ticket.FieldEncryptor;

/**
 * DB access for users.
 * CWE-89: PreparedStatement only.  CWE-772: try-with-resources on every Connection/Statement/ResultSet.
 * CWE-312: email/phone are encrypted via FieldEncryptor before insert and decrypted after select.
 */
/** Persists account records using bound SQL parameters and encrypted contact fields. */
public class UserRepository {
    private static final String SELECT_USER = """
            SELECT id, username, password_hash, salt, iterations, role_name,
                   email_enc, phone_enc, must_change_password, failed_logins,
                   locked_until, lockout_count
            FROM users
            """;

    private final Database db;
    private final FieldEncryptor encryptor;

    public UserRepository(Database db, FieldEncryptor encryptor) {
        this.db = db;
        this.encryptor = encryptor;
    }

    public Optional<User> findByUsername(String username) {
        return findOne(SELECT_USER + " WHERE username = ?", username);
    }

    public Optional<User> findById(long id) {
        return findOne(SELECT_USER + " WHERE id = ?", id);
    }

    private Optional<User> findOne(String sql, Object key) {
        try (var connection = db.connect();
             var statement = connection.prepareStatement(sql)) {
            statement.setObject(1, key);
            try (var rows = statement.executeQuery()) {
                return rows.next() ? Optional.of(readUser(rows)) : Optional.empty();
            }
        } catch (SQLException e) {
            throw new IllegalStateException("Could not look up user", e);
        }
    }

    public User insert(User user) {
        String sql = """
                INSERT INTO users (username, password_hash, salt, iterations, role_name,
                                   email_enc, phone_enc, must_change_password,
                                   failed_logins, locked_until, lockout_count)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """;

        try (var connection = db.connect(); var statement = connection.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS)) {
                statement.setString(1, user.getUsername());
                statement.setBytes(2, user.getPasswordHash());
                statement.setBytes(3, user.getSalt());
                statement.setInt(4, user.getIterations());
                statement.setString(5, user.getRole().name());
                statement.setString(6, user.getEmail() == null ? null : encryptor.encrypt(user.getEmail()));
                statement.setString(7, user.getPhone() == null ? null : encryptor.encrypt(user.getPhone()));
                statement.setBoolean(8, user.isMustChangePassword());
                statement.setInt(9, user.getFailedLogins());
                statement.setObject(10, lockExpiry(user));
                statement.setInt(11, user.getLockoutCount());
                statement.executeUpdate();

            try (var keys = statement.getGeneratedKeys()) {
                if (!keys.next()) {
                    throw new IllegalStateException("User ID was not generated");
                }
                user.setId(keys.getLong(1));
                return user;
            }
        } catch (SQLException e) {
            if ("23505".equals(e.getSQLState())) {
                throw new IllegalArgumentException("Username is unavailable", e);
            }
            throw new IllegalStateException("Could not create user", e);
        }
    }

    public void updatePassword(long userId, byte[] hash, byte[] salt, int iterations, boolean mustChange) {
        String sql = """
                UPDATE users
                SET password_hash = ?, salt = ?, iterations = ?, must_change_password = ?
                WHERE id = ?
                """;
        try (var connection = db.connect();
             var statement = connection.prepareStatement(sql)) {
            statement.setBytes(1, hash);
            statement.setBytes(2, salt);
            statement.setInt(3, iterations);
            statement.setBoolean(4, mustChange);
            statement.setLong(5, userId);
            requireUpdatedUser(statement.executeUpdate());
        } catch (SQLException e) {
            throw new IllegalStateException("Could not update password", e);
        }
    }

    public void updateRole(long userId, Role role) {
        try (var connection = db.connect();
             var statement = connection.prepareStatement("UPDATE users SET role_name = ? WHERE id = ?")) {
            statement.setString(1, role.name());
            statement.setLong(2, userId);
            requireUpdatedUser(statement.executeUpdate());
        } catch (SQLException e) {
            throw new IllegalStateException("Could not update role", e);
        }
    }

    public void updateLockState(User user) {
        String sql = """
                UPDATE users SET failed_logins = ?, locked_until = ?, lockout_count = ? WHERE id = ?
                """;
        try (var connection = db.connect();
             var statement = connection.prepareStatement(sql)) {
            statement.setInt(1, user.getFailedLogins());
            statement.setObject(2, lockExpiry(user));
            statement.setInt(3, user.getLockoutCount());
            statement.setLong(4, user.getId());
            requireUpdatedUser(statement.executeUpdate());
        } catch (SQLException e) {
            throw new IllegalStateException("Could not update login lock state", e);
        }
    }

    private User readUser(ResultSet row) throws SQLException {
        User user = new User();
        user.setId(row.getLong("id"));
        user.setUsername(row.getString("username"));
        user.setPasswordHash(row.getBytes("password_hash"));
        user.setSalt(row.getBytes("salt"));
        user.setIterations(row.getInt("iterations"));
        user.setRole(Role.valueOf(row.getString("role_name")));
        String email = row.getString("email_enc");
        user.setEmail(email == null ? null : encryptor.decrypt(email));
        String phone = row.getString("phone_enc");
        user.setPhone(phone == null ? null : encryptor.decrypt(phone));
        user.setMustChangePassword(row.getBoolean("must_change_password"));
        user.setFailedLogins(row.getInt("failed_logins"));
        Long lockedUntil = row.getObject("locked_until", Long.class);
        user.setLockedUntil(lockedUntil == null ? null : Instant.ofEpochMilli(lockedUntil));
        user.setLockoutCount(row.getInt("lockout_count"));
        return user;
    }

    private static Long lockExpiry(User user) {
        Instant until = user.getLockedUntil();
        return until == null ? null : until.toEpochMilli();
    }

    private static void requireUpdatedUser(int updatedRows) {
        if (updatedRows != 1) {
            throw new IllegalStateException("User no longer exists");
        }
    }
}
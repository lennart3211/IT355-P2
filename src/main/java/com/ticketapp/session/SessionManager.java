
package com.ticketapp.session;

import com.ticketapp.config.AppConfig;
import com.ticketapp.db.Database;
import com.ticketapp.model.User;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Clock;
import java.time.Instant;
import java.util.Base64;
import java.util.Optional;

/**
 * Owner: Luke
 *
 * CWE-338 Weak PRNG: tokens are 32 bytes from SecureRandom, Base64url-encoded.
 * CWE-1463 Insufficient Session Timeout: validate() rejects sessions idle longer
 * than SESSION_IDLE_TIMEOUT and refreshes activity on every successful validation.
 * CWE-1465 Improper Invalidation after Logout: invalidate() deletes the token hash
 * from the shared sessions table, so reuse fails across application instances.
 * Only SHA-256 token hashes are persisted; the bearer token is returned once.
 */
public class SessionManager {

    private static final int TOKEN_BYTES = 32;
    private static final String INSERT_SESSION = "INSERT INTO sessions "
            + "(token_hash, user_id, username, role_name, created_at, last_activity) VALUES (?, ?, ?, ?, ?, ?)";

    private final SecureRandom random = new SecureRandom();
    private final Database db;
    private final Clock clock;

    public SessionManager(Database db, Clock clock) {
        if (db == null || clock == null) {
            throw new IllegalArgumentException("Database and clock are required");
        }
        this.db = db;
        this.clock = clock;
    }

    public Session create(User user) {
        if (user == null || user.getRole() == null || user.getUsername() == null) {
            throw new IllegalArgumentException("A valid user is required to create a session");
        }

        String token = newToken();
        Instant now = clock.instant();

        try (Connection connection = db.connect();
             PreparedStatement statement = connection.prepareStatement(INSERT_SESSION)) {

            statement.setString(1, hashToken(token));
            statement.setLong(2, user.getId());
            statement.setString(3, user.getUsername());
            statement.setString(4, user.getRole().name());
            statement.setLong(5, now.toEpochMilli());
            statement.setLong(6, now.toEpochMilli());

            statement.executeUpdate();

            return new Session(token, user.getId(), user.getUsername(),
                    user.getRole(), now);

        } catch (SQLException e) {
            throw new IllegalStateException("Unable to create session", e);
        }
    }

    /** @return the session if the token exists and is not expired; also bumps lastActivity. */
    public Optional<Session> validate(String token) {
        if (token == null || token.isBlank()) {
            return Optional.empty();
        }

        Instant now = clock.instant();
        long nowMillis = now.toEpochMilli();
        long cutoff = now.minus(AppConfig.SESSION_IDLE_TIMEOUT).toEpochMilli();
        String tokenHash = hashToken(token);

        // The conditional UPDATE makes the expiry check and activity refresh one DB operation.
        try (Connection connection = db.connect()) {

            int refreshed;

            try (PreparedStatement update = connection.prepareStatement(
                    "UPDATE sessions SET last_activity = ? WHERE token_hash = ? AND last_activity >= ?")) {

                update.setLong(1, nowMillis);
                update.setString(2, tokenHash);
                update.setLong(3, cutoff);

                refreshed = update.executeUpdate();
            }

            if (refreshed == 0) {
                // Expired sessions are removed; unknown or concurrently logged-out tokens are harmless.
                try (PreparedStatement delete = connection.prepareStatement(
                        "DELETE FROM sessions WHERE token_hash = ? AND last_activity < ?")) {

                    delete.setString(1, tokenHash);
                    delete.setLong(2, cutoff);
                    delete.executeUpdate();
                }

                return Optional.empty();
            }

            try (PreparedStatement select = connection.prepareStatement(
                    "SELECT user_id, username, role_name, created_at FROM sessions WHERE token_hash = ?")) {

                select.setString(1, tokenHash);

                try (ResultSet result = select.executeQuery()) {
                    if (!result.next()) {
                        return Optional.empty();
                    }

                    try {
                        Session session = new Session(
                                token,
                                result.getLong("user_id"),
                                result.getString("username"),
                                com.ticketapp.model.Role.valueOf(
                                        result.getString("role_name")),
                                Instant.ofEpochMilli(
                                        result.getLong("created_at"))
                        );

                        return Optional.of(session);

                    } catch (IllegalArgumentException invalidRole) {
                        invalidate(token);
                        return Optional.empty();
                    }
                }
            }

        } catch (SQLException e) {
            throw new IllegalStateException("Unable to validate session", e);
        }
    }

    public void invalidate(String token) {
        if (token == null || token.isBlank()) {
            return;
        }

        try (Connection connection = db.connect();
             PreparedStatement statement = connection.prepareStatement(
                     "DELETE FROM sessions WHERE token_hash = ?")) {

            statement.setString(1, hashToken(token));
            statement.executeUpdate();

        } catch (SQLException e) {
            throw new IllegalStateException("Unable to invalidate session", e);
        }
    }

    public void invalidateAllForUser(long userId) {
        try (Connection connection = db.connect();
             PreparedStatement statement = connection.prepareStatement(
                     "DELETE FROM sessions WHERE user_id = ?")) {

            statement.setLong(1, userId);
            statement.executeUpdate();

        } catch (SQLException e) {
            throw new IllegalStateException("Unable to invalidate user sessions", e);
        }
    }

    String newToken() {
        byte[] bytes = new byte[TOKEN_BYTES];
        random.nextBytes(bytes);

        return Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(bytes);
    }

    private static String hashToken(String token) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(token.getBytes(StandardCharsets.UTF_8));

            return java.util.HexFormat.of().formatHex(digest);

        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 is unavailable", impossible);
        }
    }
}
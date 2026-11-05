package com.ticketapp.user;

import com.ticketapp.db.Database;
import com.ticketapp.model.Role;
import com.ticketapp.model.User;

import java.util.Optional;

/**
 * DB access for users.
 * CWE-89: PreparedStatement only.  CWE-772: try-with-resources on every Connection/Statement/ResultSet.
 * CWE-312: email/phone are encrypted via FieldEncryptor before insert and decrypted after select.
 */
public class UserRepository {

    private final Database db;

    public UserRepository(Database db) {
        this.db = db;
    }

    public Optional<User> findByUsername(String username) {
        // TODO: SELECT ... FROM users WHERE username = ?
        throw new UnsupportedOperationException("TODO");
    }

    public Optional<User> findById(long id) {
        throw new UnsupportedOperationException("TODO");
    }

    public User insert(User user) {
        throw new UnsupportedOperationException("TODO");
    }

    public void updatePassword(long userId, byte[] hash, byte[] salt, int iterations, boolean mustChange) {
        throw new UnsupportedOperationException("TODO");
    }

    public void updateRole(long userId, Role role) {
        throw new UnsupportedOperationException("TODO");
    }

    public void updateLockState(User user) {
        // TODO: persist failedLogins, lockedUntil, lockoutCount
        throw new UnsupportedOperationException("TODO");
    }
}

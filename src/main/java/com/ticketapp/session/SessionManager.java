package com.ticketapp.session;

import com.ticketapp.model.User;

import java.security.SecureRandom;
import java.time.Clock;
import java.util.Optional;

/**
 * Owner: Luke
 *
 * CWE-338 Weak PRNG: tokens are 32 bytes from SecureRandom, Base64url-encoded.
 *   Never java.util.Random / Math.random / UUID-from-time.
 * CWE-1463 Insufficient Session Timeout: validate() rejects sessions idle longer
 *   than SESSION_IDLE_TIMEOUT, and is called on EVERY protected command.
 * CWE-1465 Improper Invalidation after Logout: invalidate() deletes the token
 *   from the shared store (sessions table), so reuse fails even from another process.
 */
public class SessionManager {

    private static final int TOKEN_BYTES = 32;

    private final SecureRandom random = new SecureRandom();
    private final Clock clock;

    public SessionManager(Clock clock) {
        this.clock = clock;
    }

    public Session create(User user) {
        // TODO: generate token; store (token hash, userId, role, createdAt, lastActivity) in sessions table
        //       consider storing SHA-256(token) rather than the raw token
        throw new UnsupportedOperationException("TODO");
    }

    /** @return the session if the token exists and is not expired; also bumps lastActivity. */
    public Optional<Session> validate(String token) {
        // TODO: lookup; if now - lastActivity > SESSION_IDLE_TIMEOUT -> invalidate + empty
        throw new UnsupportedOperationException("TODO");
    }

    public void invalidate(String token) {
        // TODO: DELETE FROM sessions WHERE token_hash = ?
        throw new UnsupportedOperationException("TODO");
    }

    public void invalidateAllForUser(long userId) {
        // TODO: call on password change and role change
        throw new UnsupportedOperationException("TODO");
    }

    String newToken() {
        byte[] bytes = new byte[TOKEN_BYTES];
        random.nextBytes(bytes);
        return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}

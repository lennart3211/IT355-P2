package com.ticketapp.user;

import com.ticketapp.model.User;

/**
 * Owner: Caleb
 *
 * CWE-916 Insufficient Computational Effort: PBKDF2WithHmacSHA256,
 *   unique 16-byte salt per user from SecureRandom, AppConfig.PBKDF2_ITERATIONS.
 * CWE-256 Plaintext Storage: only the derived hash + salt + iterations are stored.
 * CWE-208 (shared with Kimlay): verify() uses MessageDigest.isEqual();
 *   dummyVerify() does the same work for unknown users.
 */
public class PasswordHasher {

    public static final String ALGORITHM = "PBKDF2WithHmacSHA256";
    public static final int SALT_BYTES = 16;
    public static final int KEY_BITS = 256;

    public record HashResult(byte[] hash, byte[] salt, int iterations) { }

    public HashResult hash(char[] password) {
        // TODO: new salt via SecureRandom; SecretKeyFactory.getInstance(ALGORITHM); PBEKeySpec; clearPassword()
        throw new UnsupportedOperationException("TODO");
    }

    public boolean verify(char[] password, User user) {
        // TODO: re-derive using user's salt+iterations; MessageDigest.isEqual(derived, user.getPasswordHash())
        throw new UnsupportedOperationException("TODO");
    }

    /** Burn the same CPU as verify() so unknown usernames aren't faster (CWE-208). */
    public void dummyVerify(char[] password) {
        // TODO: derive against a fixed dummy salt, discard result
        throw new UnsupportedOperationException("TODO");
    }
}

package com.ticketapp.user;

import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Objects;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import com.ticketapp.config.AppConfig;
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
        Objects.requireNonNull(password, "password");

        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[SALT_BYTES];
        random.nextBytes(salt);

        int iterations = AppConfig.PBKDF2_ITERATIONS;
        PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, KEY_BITS);

        try {
            SecretKeyFactory skf = SecretKeyFactory.getInstance(ALGORITHM);
            byte[] hash = skf.generateSecret(spec).getEncoded();
            return new HashResult(hash, salt, iterations);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Couldn't hash password", e);
        } finally {
            spec.clearPassword();
        }
    }

    public boolean verify(char[] password, User user) {
        Objects.requireNonNull(password, "password");
        Objects.requireNonNull(user, "user");

        byte[] storedHash = user.getPasswordHash();
        byte[] salt = user.getSalt();
        int iterations = user.getIterations();

        if (storedHash == null || storedHash.length != KEY_BITS / Byte.SIZE
                || salt == null || salt.length == 0 || iterations <= 0) {
            return false;
        }

        PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, KEY_BITS);
        try {
            SecretKeyFactory skf = SecretKeyFactory.getInstance(ALGORITHM);
            byte[] derivedHash = skf.generateSecret(spec).getEncoded();
            return java.security.MessageDigest.isEqual(derivedHash, storedHash);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Couldn't verify password", e);
        } finally {
            spec.clearPassword();
        }
    }

    /** Burn the same CPU as verify() so unknown usernames aren't faster (CWE-208). */
    public void dummyVerify(char[] password) {
        Objects.requireNonNull(password, "password");
        byte[] dummySalt = new byte[SALT_BYTES];
        byte[] dummyHash = new byte[KEY_BITS / Byte.SIZE];
        PBEKeySpec spec = new PBEKeySpec(
                password, dummySalt, AppConfig.PBKDF2_ITERATIONS, KEY_BITS);
        try {
            SecretKeyFactory skf = SecretKeyFactory.getInstance(ALGORITHM);
            byte[] derivedHash = skf.generateSecret(spec).getEncoded();
            java.security.MessageDigest.isEqual(derivedHash, dummyHash);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Couldn't verify password", e);
        } finally {
            spec.clearPassword();
        }
    }
}

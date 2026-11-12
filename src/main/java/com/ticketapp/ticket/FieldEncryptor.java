package com.ticketapp.ticket;

/**
 * Owner: Jocelyn
 * CWE-312 Cleartext Storage of Sensitive Information.
 * AES-256-GCM with a random 12-byte IV per value; store Base64(iv || ciphertext || tag).
 * Key comes from AppConfig.fieldKey() (env var), never hard-coded (CWE-798).
 * Masking on display is NOT a substitute for this.
 */

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

public class FieldEncryptor {

    private static final int IV_LENGTH = 12;
    private static final int TAG_LENGTH_BITS = 128;

    private final byte[] key;
    private final SecureRandom random = new SecureRandom();

    public FieldEncryptor(byte[] key) {
        if (key == null || key.length != 32) {
            throw new IllegalArgumentException(
                "AES-256 requires a 32-byte key"
            );
        }
        this.key = key.clone();
    }

    public String encrypt(String plaintext) {
        if (plaintext == null) {
            throw new IllegalArgumentException(
                "Plaintext cannot be null"
            );
        }

        try {
            byte[] iv = new byte[IV_LENGTH];
            random.nextBytes(iv);

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");

            SecretKeySpec secretKey =
                new SecretKeySpec(key, "AES");

            GCMParameterSpec spec =
                new GCMParameterSpec(TAG_LENGTH_BITS, iv);

            cipher.init(Cipher.ENCRYPT_MODE, secretKey, spec);

            byte[] encrypted = cipher.doFinal(
                plaintext.getBytes(StandardCharsets.UTF_8)
            );

            byte[] combined = new byte[iv.length + encrypted.length];

            System.arraycopy(
                iv, 0, combined, 0, iv.length
            );

            System.arraycopy(
                encrypted, 0, combined, iv.length, encrypted.length
            );

            return Base64.getEncoder().encodeToString(combined);

        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(
                "Encryption failed", e
            );
        }
    }

    public String decrypt(String stored) {
        if (stored == null) {
            throw new IllegalArgumentException(
                "Encrypted value cannot be null"
            );
        }

        try {
            byte[] combined =
                Base64.getDecoder().decode(stored);

            if (combined.length < IV_LENGTH + 16) {
                throw new IllegalArgumentException(
                    "Invalid encrypted data"
                );
            }

            byte[] iv =
                Arrays.copyOfRange(combined, 0, IV_LENGTH);

            byte[] ciphertext =
                Arrays.copyOfRange(
                    combined, IV_LENGTH, combined.length
                );

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");

            SecretKeySpec secretKey =
                new SecretKeySpec(key, "AES");

            GCMParameterSpec spec =
                new GCMParameterSpec(TAG_LENGTH_BITS, iv);

            cipher.init(Cipher.DECRYPT_MODE, secretKey, spec);

            byte[] plaintext = cipher.doFinal(ciphertext);

            return new String(
                plaintext, StandardCharsets.UTF_8
            );

        } catch (GeneralSecurityException |
                 IllegalArgumentException e) {
            throw new IllegalArgumentException(
                "Decryption failed or data was modified", e
            );
        }
    }
}

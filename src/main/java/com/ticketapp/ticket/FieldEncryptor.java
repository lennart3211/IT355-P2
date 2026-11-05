package com.ticketapp.ticket;

/**
 * Owner: Jocelyn
 * CWE-312 Cleartext Storage of Sensitive Information.
 * AES-256-GCM with a random 12-byte IV per value; store Base64(iv || ciphertext || tag).
 * Key comes from AppConfig.fieldKey() (env var), never hard-coded (CWE-798).
 * Masking on display is NOT a substitute for this.
 */
public class FieldEncryptor {

    private final byte[] key;

    public FieldEncryptor(byte[] key) {
        this.key = key;
    }

    public String encrypt(String plaintext) {
        // TODO: Cipher.getInstance("AES/GCM/NoPadding"); new IV via SecureRandom; GCMParameterSpec(128, iv)
        throw new UnsupportedOperationException("TODO");
    }

    public String decrypt(String stored) {
        throw new UnsupportedOperationException("TODO");
    }
}

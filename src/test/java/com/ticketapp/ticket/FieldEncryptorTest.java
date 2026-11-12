
package com.ticketapp.ticket;

import org.junit.jupiter.api.Test;

import com.ticketapp.ticket.FieldEncryptor;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;

class FieldEncryptorTest {

    private FieldEncryptor createEncryptor() {
        byte[] key = new byte[32];
        Arrays.fill(key, (byte) 7);
        return new FieldEncryptor(key);
    }

    @Test
    void encryptAndDecrypt() {
        FieldEncryptor encryptor = createEncryptor();

        String original = "jocelyn@example.com";

        String encrypted = encryptor.encrypt(original);
        String decrypted = encryptor.decrypt(encrypted);

        assertNotEquals(original, encrypted);
        assertEquals(original, decrypted);
    }

    @Test
    void encryptionUsesRandomIV() {
        FieldEncryptor encryptor = createEncryptor();

        String first = encryptor.encrypt("secret");
        String second = encryptor.encrypt("secret");

        assertNotEquals(first, second);
    }

    @Test
    void modifiedCiphertextIsRejected() {
        FieldEncryptor encryptor = createEncryptor();

        byte[] encrypted = Base64.getDecoder().decode(
                encryptor.encrypt("private information")
        );

        encrypted[encrypted.length - 1] ^= 1;

        String modified = Base64.getEncoder()
                .encodeToString(encrypted);

        assertThrows(
                IllegalArgumentException.class,
                () -> encryptor.decrypt(modified)
        );
    }

    @Test
    void rejectsInvalidKeyLength() {
        assertThrows(
                IllegalArgumentException.class,
                () -> new FieldEncryptor(new byte[16])
        );
    }
}

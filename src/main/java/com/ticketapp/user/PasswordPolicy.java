package com.ticketapp.user;

/**
 * Owner: Caleb
 * CWE-521 Weak Password Requirements: enforced at registration AND password change.
 */
public class PasswordPolicy {

    public static final int MIN_LENGTH = 12;
    public static final int MAX_LENGTH = 128;   // also bounds PBKDF2 input (CWE-770-ish)
    private static final String SYMBOLS = "!@#$%^&*()-_+=[]{}|\\:;\"'<>,.?/";

    /** @return list of human-readable problems; empty list means OK. */
    private boolean hasRequiredCharacterTypes(char[] password) {
        boolean upper = false;
        boolean lower = false;
        boolean digit = false;
        boolean symbol = false;

        for (char c : password) {
            upper |= Character.isUpperCase(c);
            lower |= Character.isLowerCase(c);
            digit |= Character.isDigit(c);
            symbol |= SYMBOLS.indexOf(c) >= 0;
        }

        int types = (upper ? 1 : 0) + (lower ? 1 : 0)
                + (digit ? 1 : 0) + (symbol ? 1 : 0);
        return types >= 3;
    }
}

package com.ticketapp.user;

import java.util.ArrayList;
import java.util.List;

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

/**
 * CWE-521: Validate password requirements.
 * Returns a list of problems, or an empty list if valid.
 */
public List<String> validate(char[] password, String username) {
    List<String> problems = new ArrayList<>();

    if (password == null) {
        problems.add("Password is required");
        return problems;
    }

    if (password.length < MIN_LENGTH) {
        problems.add("Password must be at least 12 characters");
    }

    if (password.length > MAX_LENGTH) {
        problems.add("Password must be at most 128 characters");
    }

    if (!hasRequiredCharacterTypes(password)) {
        problems.add("Password must contain at least 3 character types");
    }

    if (username != null && !username.isBlank()) {
        String passwordText = new String(password).toLowerCase();
        if (passwordText.contains(username.toLowerCase())) {
            problems.add("Password must not contain username");
        }
    }

    return problems;
}

}

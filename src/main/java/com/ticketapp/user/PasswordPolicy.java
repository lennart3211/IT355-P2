package com.ticketapp.user;

import java.util.List;

/**
 * Owner: Caleb
 * CWE-521 Weak Password Requirements: enforced at registration AND password change.
 */
public class PasswordPolicy {

    public static final int MIN_LENGTH = 12;
    public static final int MAX_LENGTH = 128;   // also bounds PBKDF2 input (CWE-770-ish)

    /** @return list of human-readable problems; empty list means OK. */
    public List<String> validate(char[] password, String username) {
        // TODO: length bounds; at least 3 of {upper, lower, digit, symbol};
        //       must not contain the username; optional small common-password blocklist
        throw new UnsupportedOperationException("TODO");
    }
}

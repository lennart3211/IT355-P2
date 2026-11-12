package com.ticketapp.model;

/**
 * CWE-842 Placement of User into Incorrect Group (Luke):
 *   DEFAULT is USER. Only an ADMIN can promote someone to TECHNICIAN or ADMIN.
 */
public enum Role {
    USER(1),
    TECHNICIAN(2),
    ADMIN(3);

    public static final Role DEFAULT = USER;

    private final int level;

    Role(int level) {
        this.level = level;
    }

    public boolean atLeast(Role other) {
        return this.level >= other.level;
    }
}

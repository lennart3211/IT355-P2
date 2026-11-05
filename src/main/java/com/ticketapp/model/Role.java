package com.ticketapp.model;

/**
 * CWE-842 Placement of User into Incorrect Group (Luke):
 *   DEFAULT is USER. Only an ADMIN can promote someone to TECHNICIAN or ADMIN.
 */
public enum Role {
    USER,
    TECHNICIAN,
    ADMIN;

    public static final Role DEFAULT = USER;

    public boolean atLeast(Role other) {
        return this.ordinal() >= other.ordinal();
    }
}

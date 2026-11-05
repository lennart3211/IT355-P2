package com.ticketapp.session;

import com.ticketapp.model.Role;

import java.time.Instant;

/**
 * An authenticated session. Immutable snapshot; lastActivity is tracked in SessionManager.
 * Do not print the token in toString() or logs.
 */
public record Session(String token, long userId, String username, Role role, Instant createdAt) {
    @Override
    public String toString() {
        return "Session[user=" + username + ", role=" + role + "]";
    }
}

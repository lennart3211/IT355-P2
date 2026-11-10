
package com.ticketapp.session;

import com.ticketapp.audit.AuditLog;
import com.ticketapp.model.Role;
import com.ticketapp.model.Ticket;

/**
 * Central authorization checks. Owner: Luke
 *
 * CWE-306 Missing Authentication for Critical Function: requireValid() on every
 * protected command (re-validates against SessionManager, so CWE-1463/1465 apply).
 * CWE-749 Exposed Dangerous Method: services call requireRole() themselves before
 * delete/role-change/export; the CLI check is NOT enough.
 * CWE-639 Authorization Bypass via User-Controlled Key: requireCanView() checks
 * ticket ownership (or TECHNICIAN+) for "view-ticket 42".
 * CWE-778: denials logged as ACCESS_DENIED.
 */
public class AccessControl {

    private static final String DENIED = "Access denied";
    private static final String TICKET_NOT_FOUND = "Ticket not found";

    private final SessionManager sessions;
    private final AuditLog audit;

    public AccessControl(SessionManager sessions, AuditLog audit) {
        this.sessions = sessions;
        this.audit = audit;
    }

    public Session requireValid(Session session) {
        if (session == null || session.token() == null) {
            deny("anonymous", "Missing or invalid session");
        }

        return sessions.validate(session.token()).orElseGet(() -> {
            deny(session.username(), "Invalid or expired session");
            return null; // deny always throws
        });
    }

    public Session requireRole(Session session, Role minimum) {
        if (minimum == null) {
            throw new IllegalArgumentException("Minimum role is required");
        }

        Session valid = requireValid(session);

        if (valid.role() == null || !valid.role().atLeast(minimum)) {
            deny(valid.username(), "Insufficient role for protected operation");
        }

        return valid;
    }

    public void requireCanView(Session session, Ticket ticket) {
        Session valid = requireValid(session);

        // Keep the response identical for a nonexistent ticket and a ticket the user cannot access.
        if (ticket == null) {
            denyTicket(valid.username());
        }

        if (ticket.getOwnerId() != valid.userId()
                && !valid.role().atLeast(Role.TECHNICIAN)) {
            denyTicket(valid.username());
        }
    }

    /** Owner or technician+ may modify a ticket; callers must still enforce operation-specific rules. */
    public void requireCanModify(Session session, Ticket ticket) {
        Session valid = requireValid(session);

        if (ticket == null || (ticket.getOwnerId() != valid.userId()
                && !valid.role().atLeast(Role.TECHNICIAN))) {
            denyTicket(valid.username());
        }
    }

    /** Revoke every session after a password or role change. */
    public void invalidateAllForUser(long userId) {
        sessions.invalidateAllForUser(userId);
    }

    private void denyTicket(String actor) {
        audit.record(
                AuditLog.Event.ACCESS_DENIED,
                actor,
                "Ticket access denied"
        );

        throw new AccessDeniedException(TICKET_NOT_FOUND);
    }

    private void deny(String actor, String detail) {
        audit.record(
                AuditLog.Event.ACCESS_DENIED,
                actor,
                detail
        );

        throw new AccessDeniedException(DENIED);
    }
}
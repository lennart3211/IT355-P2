package com.ticketapp.session;

import com.ticketapp.audit.AuditLog;
import com.ticketapp.model.Role;
import com.ticketapp.model.Ticket;

/**
 * Central authorization checks. Owner: Luke
 *
 * CWE-306 Missing Authentication for Critical Function: requireValid() on every
 *   protected command (re-validates against SessionManager, so CWE-1463/1465 apply).
 * CWE-749 Exposed Dangerous Method: services call requireRole() themselves before
 *   delete/role-change/export; the CLI check is NOT enough.
 * CWE-639 Authorization Bypass via User-Controlled Key: requireCanView() checks
 *   ticket ownership (or TECHNICIAN+) for "view-ticket 42".
 * CWE-778: denials logged as ACCESS_DENIED.
 */
public class AccessControl {

    private final SessionManager sessions;
    private final AuditLog audit;

    public AccessControl(SessionManager sessions, AuditLog audit) {
        this.sessions = sessions;
        this.audit = audit;
    }

    public Session requireValid(Session session) {
        // TODO: if session == null or sessions.validate(token) empty -> throw AccessDeniedException
        throw new UnsupportedOperationException("TODO");
    }

    public Session requireRole(Session session, Role minimum) {
        // TODO: requireValid(); if !role.atLeast(minimum) -> audit + throw
        throw new UnsupportedOperationException("TODO");
    }

    public void requireCanView(Session session, Ticket ticket) {
        // TODO: owner == session.userId() OR role >= TECHNICIAN; else throw
        //       Use the same "not found" message for missing and forbidden tickets
        throw new UnsupportedOperationException("TODO");
    }

    public void requireCanModify(Session session, Ticket ticket) {
        throw new UnsupportedOperationException("TODO");
    }
}

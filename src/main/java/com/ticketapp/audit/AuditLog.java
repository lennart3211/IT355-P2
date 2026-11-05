package com.ticketapp.audit;

/**
 * Security audit log.
 *
 * CWE-778 Insufficient Logging: every event type below MUST be logged by the
 *   service that performs it (logins, failed logins, role changes, deletions...).
 * CWE-117 Improper Output Neutralization for Logs: every user-supplied value is
 *   passed through LogSanitizer before it is written.
 * Never log passwords, hashes, session tokens, or contact details.
 */
public class AuditLog {

    public enum Event {
        LOGIN_SUCCESS,
        LOGIN_FAILURE,
        ACCOUNT_LOCKED,
        LOGOUT,
        PASSWORD_CHANGED,
        ROLE_CHANGED,
        TICKET_CREATED,
        TICKET_ASSIGNED,
        TICKET_DELETED,
        ACCESS_DENIED,
        EXPORT_CREATED,
        IMPORT_COMPLETED
    }

    /**
     * @param event   what happened
     * @param actor   username performing the action (or "anonymous")
     * @param detail  free text; WILL be sanitized
     */
    public void record(Event event, String actor, String detail) {
        String safeActor = LogSanitizer.clean(actor);
        String safeDetail = LogSanitizer.clean(detail);
        // TODO: write timestamp | event | safeActor | safeDetail to audit_log table or file
        //       (use PreparedStatement if DB; append-only file with owner-only perms if file)
        throw new UnsupportedOperationException("TODO");
    }
}

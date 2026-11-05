package com.ticketapp.assign;

import com.ticketapp.audit.AuditLog;
import com.ticketapp.model.Role;
import com.ticketapp.session.AccessControl;
import com.ticketapp.session.Session;
import com.ticketapp.ticket.TicketRepository;

/**
 * Owner: (unassigned)
 *
 * CWE-367 TOCTOU: claim() does NOT "read status, then write". It calls
 *   repo.assignIfUnassigned() — a single conditional UPDATE — and checks the row count.
 * CWE-820 / CWE-821: updates go through TicketLockManager + version column.
 * CWE-833: merge() locks both tickets via withLocks() (sorted order).
 * CWE-778: TICKET_ASSIGNED logged.
 */
public class AssignmentService {

    private final TicketRepository repo;
    private final TicketLockManager locks;
    private final AccessControl access;
    private final AuditLog audit;

    public AssignmentService(TicketRepository repo, TicketLockManager locks,
                             AccessControl access, AuditLog audit) {
        this.repo = repo;
        this.locks = locks;
        this.access = access;
        this.audit = audit;
    }

    /** @return true if this technician won the ticket; false if someone else already has it. */
    public boolean claim(Session session, long ticketId) {
        // TODO: requireRole(TECHNICIAN); repo.assignIfUnassigned(ticketId, session.userId()); audit
        throw new UnsupportedOperationException("TODO");
    }

    public void reassign(Session session, long ticketId, long newTechId) {
        // TODO: requireRole(ADMIN); locks.withLock(ticketId, ...) + updateIfVersion
        throw new UnsupportedOperationException("TODO");
    }

    /** Merge 'from' into 'into'. Locks both in ascending id order (CWE-833). */
    public void merge(Session session, long fromId, long intoId) {
        throw new UnsupportedOperationException("TODO");
    }
}

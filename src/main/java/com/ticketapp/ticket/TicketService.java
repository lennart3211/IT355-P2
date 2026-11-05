package com.ticketapp.ticket;

import com.ticketapp.audit.AuditLog;
import com.ticketapp.model.Role;
import com.ticketapp.model.Ticket;
import com.ticketapp.session.AccessControl;
import com.ticketapp.session.Session;

import java.util.List;

/**
 * Owner: Jocelyn (auth checks: Luke)
 *
 * CWE-770 Resource Allocation Without Limits: description <= MAX_DESCRIPTION_LENGTH,
 *   open tickets per user <= MAX_OPEN_TICKETS_PER_USER; also cap title length.
 * CWE-1333 ReDoS: search() uses String.contains() on lower-cased text, NOT a
 *   user-supplied regex.
 * CWE-359 Exposure of Private Personal Information: list/view return TicketView,
 *   which omits other users' contact info unless the viewer is TECHNICIAN+.
 * CWE-639 / CWE-749 / CWE-306: AccessControl inside every method.
 * CWE-778: TICKET_CREATED / TICKET_DELETED logged.
 */
public class TicketService {

    private final TicketRepository repo;
    private final AccessControl access;
    private final AuditLog audit;

    public TicketService(TicketRepository repo, AccessControl access, AuditLog audit) {
        this.repo = repo;
        this.access = access;
        this.audit = audit;
    }

    public TicketView create(Session session, String title, String description, String contactInfo) {
        // TODO: requireValid; validate lengths; countOpenByOwner < cap; insert; audit TICKET_CREATED
        throw new UnsupportedOperationException("TODO");
    }

    public TicketView view(Session session, long ticketId) {
        // TODO: findById; access.requireCanView (CWE-639); return TicketView.forViewer(...)
        throw new UnsupportedOperationException("TODO");
    }

    public List<TicketView> list(Session session) {
        // TODO: USER -> own tickets only; TECHNICIAN+ -> all; map through TicketView (CWE-359)
        throw new UnsupportedOperationException("TODO");
    }

    public List<TicketView> search(Session session, String keyword) {
        // TODO: cap keyword length; plain contains(), no Pattern.compile(userInput) (CWE-1333)
        throw new UnsupportedOperationException("TODO");
    }

    public void delete(Session session, long ticketId) {
        // TODO: access.requireRole(session, Role.ADMIN) (CWE-306/749); repo.delete; audit TICKET_DELETED
        throw new UnsupportedOperationException("TODO");
    }
}

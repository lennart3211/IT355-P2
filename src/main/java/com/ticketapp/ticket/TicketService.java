package com.ticketapp.ticket;
import com.ticketapp.config.AppConfig;
import com.ticketapp.audit.AuditLog;
import com.ticketapp.model.Role;
import com.ticketapp.model.Ticket;
import com.ticketapp.session.AccessControl;
import com.ticketapp.session.Session;
import java.util.Locale;
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

    private static final int MAX_TITLE_LENGTH = 200;
    private static final int MAX_SEARCH_LENGTH = 100;

    private final TicketRepository repo;
    private final AccessControl access;
    private final AuditLog audit;

    public TicketService(
            TicketRepository repo,
            AccessControl access,
            AuditLog audit) {
        this.repo = repo;
        this.access = access;
        this.audit = audit;
    }

    // CWE-770: Enforce limits on ticket creation.
    public TicketView create(
            Session session,
            String title,
            String description,
            String contactInfo) {

        Session valid = access.requireValid(session);

        if (title == null || title.isBlank()
                || title.length() > MAX_TITLE_LENGTH) {
            throw new IllegalArgumentException(
                    "Title must be between 1 and 200 characters");
        }

        if (description == null
                || description.length() > AppConfig.MAX_DESCRIPTION_LENGTH) {
            throw new IllegalArgumentException(
                    "Description exceeds the allowed length");
        }

        int openTickets = repo.countOpenByOwner(valid.userId());

        if (openTickets >= AppConfig.MAX_OPEN_TICKETS_PER_USER) {
            throw new IllegalStateException(
                    "Maximum number of open tickets reached");
        }

        Ticket ticket = new Ticket();
        ticket.setOwnerId(valid.userId());
        ticket.setTitle(title);
        ticket.setDescription(description);
        ticket.setContactInfo(contactInfo);
        ticket.setStatus(Ticket.Status.OPEN);

        Ticket saved = repo.insert(ticket);

        audit.record(
                AuditLog.Event.TICKET_CREATED,
                valid.username(),
                "Ticket created: " + saved.getId()
        );

        return TicketView.forViewer(saved, valid);
    }

    // CWE-639: Verify ownership or technician role.
    public TicketView view(Session session, long ticketId) {
        Session valid = access.requireValid(session);

        Ticket ticket = repo.findById(ticketId).orElse(null);

        access.requireCanView(valid, ticket);

        return TicketView.forViewer(ticket, valid);
    }

    // CWE-359: Return only authorized ticket views.
    public List<TicketView> list(Session session) {
        Session valid = access.requireValid(session);

        List<Ticket> tickets;

        if (valid.role().atLeast(Role.TECHNICIAN)) {
            tickets = repo.findAll();
        } else {
            tickets = repo.findByOwner(valid.userId());
        }

        return tickets.stream()
                .map(ticket -> TicketView.forViewer(ticket, valid))
                .toList();
    }

    // CWE-1333: Literal search instead of user-controlled regex.
    public List<TicketView> search(Session session, String keyword) {
        Session valid = access.requireValid(session);

        if (keyword == null || keyword.isBlank()
                || keyword.length() > MAX_SEARCH_LENGTH) {
            throw new IllegalArgumentException(
                    "Search keyword must be between 1 and 100 characters");
        }

        String normalized = keyword.toLowerCase(Locale.ROOT);

        List<Ticket> tickets;

        if (valid.role().atLeast(Role.TECHNICIAN)) {
            tickets = repo.findAll();
        } else {
            tickets = repo.findByOwner(valid.userId());
        }

        return tickets.stream()
                .filter(ticket ->
                        ticket.getTitle() != null
                        && ticket.getTitle()
                                .toLowerCase(Locale.ROOT)
                                .contains(normalized))
                .map(ticket -> TicketView.forViewer(ticket, valid))
                .toList();
    }

    // CWE-306 / CWE-749: Admin-only deletion.
    public void delete(Session session, long ticketId) {
        Session valid = access.requireRole(session, Role.ADMIN);

        boolean deleted = repo.delete(ticketId);

        if (deleted) {
            audit.record(
                    AuditLog.Event.TICKET_DELETED,
                    valid.username(),
                    "Ticket deleted: " + ticketId
            );
        }
    }
}
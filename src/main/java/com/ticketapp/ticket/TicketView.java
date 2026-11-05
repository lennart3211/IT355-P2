package com.ticketapp.ticket;

import com.ticketapp.model.Role;
import com.ticketapp.model.Ticket;
import com.ticketapp.session.Session;

/**
 * Read-only DTO shown to the CLI.
 * CWE-359: contactInfo is null unless the viewer owns the ticket or is TECHNICIAN+.
 */
public record TicketView(long id, String title, String description, String status,
                         Long assigneeId, String contactInfo) {

    public static TicketView forViewer(Ticket t, Session viewer) {
        boolean canSeeContact = t.getOwnerId() == viewer.userId()
                || viewer.role().atLeast(Role.TECHNICIAN);
        return new TicketView(t.getId(), t.getTitle(), t.getDescription(), t.getStatus().name(),
                t.getAssigneeId(), canSeeContact ? t.getContactInfo() : null);
    }
}

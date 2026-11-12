
package com.ticketapp.ticket;

import com.ticketapp.audit.AuditLog;
import com.ticketapp.model.Role;
import com.ticketapp.model.Ticket;
import com.ticketapp.session.AccessControl;
import com.ticketapp.session.Session;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class TicketServiceTest {

    private Session user() {
        return new Session("test-token", 1L, "jocelyn",
                Role.USER, Instant.now());
    }

    private AccessControl testAccess() {
        return new AccessControl(null, null) {
            @Override
            public Session requireValid(Session session) {
                return session;
            }
        };
    }

    private AuditLog testAudit() {
        return new AuditLog() {
            @Override
            public void record(Event event, String actor, String detail) {
                // Avoid unfinished audit implementation in tests.
            }
        };
    }

    private Ticket ticket(long ownerId, String title) {
        Ticket t = new Ticket();
        t.setId(1L);
        t.setOwnerId(ownerId);
        t.setTitle(title);
        t.setDescription("Test description");
        t.setContactInfo("private@example.com");
        t.setStatus(Ticket.Status.OPEN);
        return t;
    }

    @Test
    void rejectsDescriptionOver4000Characters() {
        TicketRepository repo = new TicketRepository(null, null) {};

        TicketService service =
                new TicketService(repo, testAccess(), testAudit());

        assertThrows(IllegalArgumentException.class,
                () -> service.create(user(), "Test",
                        "a".repeat(4001), "private@example.com"));
    }

    @Test
    void rejectsMoreThan20OpenTickets() {
        TicketRepository repo = new TicketRepository(null, null) {
            @Override
            public int countOpenByOwner(long ownerId) {
                return 20;
            }
        };

        TicketService service =
                new TicketService(repo, testAccess(), testAudit());

        assertThrows(IllegalStateException.class,
                () -> service.create(user(), "Test",
                        "Valid description", "private@example.com"));
    }

    @Test
    void searchTreatsRegexAsLiteralText() {
        TicketRepository repo = new TicketRepository(null, null) {
            @Override
            public List<Ticket> findByOwner(long ownerId) {
                return List.of(
                        ticket(1L, "Normal ticket"),
                        ticket(1L, "Literal .* example")
                );
            }
        };

        TicketService service =
                new TicketService(repo, testAccess(), testAudit());

        List<TicketView> results = service.search(user(), ".*");

        assertEquals(1, results.size());
        assertEquals("Literal .* example", results.get(0).title());
    }

    @Test
    void hidesContactInfoFromOtherUsers() {
        Ticket t = ticket(2L, "Private ticket");

        TicketView view = TicketView.forViewer(t, user());

        assertNull(view.contactInfo());
    }

    @Test
    void ownerCanSeeContactInfo() {
        Ticket t = ticket(1L, "My ticket");

        TicketView view = TicketView.forViewer(t, user());

        assertEquals("private@example.com", view.contactInfo());
    }

    @Test
    void technicianCanSeeContactInfo() {
        Ticket t = ticket(2L, "Assigned ticket");

        Session technician = new Session(
                "tech-token", 3L, "technician",
                Role.TECHNICIAN, Instant.now()
        );

        TicketView view = TicketView.forViewer(t, technician);

        assertEquals("private@example.com", view.contactInfo());
    }
}

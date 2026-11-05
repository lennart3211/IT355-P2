package com.ticketapp.ticket;

import com.ticketapp.db.Database;
import com.ticketapp.model.Ticket;

import java.util.List;
import java.util.Optional;

/**
 * Owner: Jocelyn
 *
 * CWE-89 SQL Injection: EVERY query uses PreparedStatement with '?' placeholders.
 *   No string concatenation of user input into SQL, including ORDER BY / LIKE.
 * CWE-772 Missing Release of Resource: Connection, PreparedStatement and ResultSet
 *   are all opened in try-with-resources.
 * CWE-312: contactInfo goes through FieldEncryptor on write/read.
 */
public class TicketRepository {

    private final Database db;
    private final FieldEncryptor encryptor;

    public TicketRepository(Database db, FieldEncryptor encryptor) {
        this.db = db;
        this.encryptor = encryptor;
    }

    public Ticket insert(Ticket t) {
        // TODO: INSERT INTO tickets(owner_id, title, description, contact_enc, status, created_at, version)
        //       VALUES (?, ?, ?, ?, ?, ?, 0)
        throw new UnsupportedOperationException("TODO");
    }

    public Optional<Ticket> findById(long id) {
        throw new UnsupportedOperationException("TODO");
    }

    public List<Ticket> findByOwner(long ownerId) {
        throw new UnsupportedOperationException("TODO");
    }

    public List<Ticket> findAll() {
        throw new UnsupportedOperationException("TODO");
    }

    public int countOpenByOwner(long ownerId) {
        // TODO: used for CWE-770 per-user cap
        throw new UnsupportedOperationException("TODO");
    }

    /**
     * Atomic assign (CWE-367): UPDATE tickets SET assignee_id = ?, status = 'ASSIGNED', version = version + 1
     *                          WHERE id = ? AND assignee_id IS NULL
     * @return true if exactly one row updated
     */
    public boolean assignIfUnassigned(long ticketId, long technicianId) {
        throw new UnsupportedOperationException("TODO");
    }

    /** Optimistic-lock update (CWE-820/821): ... WHERE id = ? AND version = ? */
    public boolean updateIfVersion(Ticket t, long expectedVersion) {
        throw new UnsupportedOperationException("TODO");
    }

    public boolean delete(long id) {
        throw new UnsupportedOperationException("TODO");
    }
}

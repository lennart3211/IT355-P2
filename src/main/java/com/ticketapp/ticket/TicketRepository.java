package com.ticketapp.ticket;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

import com.ticketapp.db.Database;
import com.ticketapp.model.Ticket;

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
        String sql = """
            INSERT INTO tickets
            (owner_id, title, description, contact_enc,
            status, created_at, version)
            VALUES (?, ?, ?, ?, ?, ?, 0)
            """;

        if (t == null) {
            throw new IllegalArgumentException("Ticket cannot be null");
        }

        Instant createdAt = t.getCreatedAt() != null
            ? t.getCreatedAt()
            : Instant.now();

        try (Connection conn = db.connect();
            PreparedStatement ps = conn.prepareStatement(
                sql, Statement.RETURN_GENERATED_KEYS)) {

            ps.setLong(1, t.getOwnerId());
            ps.setString(2, t.getTitle());
            ps.setString(3, t.getDescription());

            String encryptedContact = t.getContactInfo() == null
                ? null
                : encryptor.encrypt(t.getContactInfo());

            ps.setString(4, encryptedContact);
            ps.setString(5, t.getStatus().name());
            ps.setTimestamp(6, Timestamp.from(createdAt));

            int rows = ps.executeUpdate();

            if (rows != 1) {
                throw new IllegalStateException(
                    "Ticket insertion failed"
                );
            }

            try (ResultSet keys = ps.getGeneratedKeys()) {
                if (!keys.next()) {
                    throw new IllegalStateException(
                        "Ticket ID was not generated"
                    );
                }

                t.setId(keys.getLong(1));
            }

            t.setCreatedAt(createdAt);
            t.setVersion(0);

            return t;

        } catch (SQLException e) {
            throw new IllegalStateException(
                "Failed to insert ticket", e
            );
        }
    }
    
    public Optional<Ticket> findById(long id) {
        String sql = "SELECT * FROM tickets WHERE id = ?";

        try (Connection conn = db.connect();
            PreparedStatement ps = conn.prepareStatement(sql)) {

            ps.setLong(1, id);

            try (ResultSet rs = ps.executeQuery()) {

                if (!rs.next()) {
                    return Optional.empty();
                }

                Ticket ticket = new Ticket();

                ticket.setId(rs.getLong("id"));
                ticket.setOwnerId(rs.getLong("owner_id"));

                long assigneeId = rs.getLong("assignee_id");
                ticket.setAssigneeId(
                    rs.wasNull() ? null : assigneeId
                );

                ticket.setTitle(rs.getString("title"));
                ticket.setDescription(rs.getString("description"));

                String encryptedContact =
                    rs.getString("contact_enc");

                ticket.setContactInfo(
                    encryptedContact == null
                        ? null
                        : encryptor.decrypt(encryptedContact)
                );

                ticket.setStatus(
                    Ticket.Status.valueOf(rs.getString("status"))
                );

                Timestamp createdAt =
                    rs.getTimestamp("created_at");

                ticket.setCreatedAt(
                    createdAt == null ? null : createdAt.toInstant()
                );

                ticket.setVersion(rs.getLong("version"));

                return Optional.of(ticket);
            }

        } catch (SQLException e) {
            throw new IllegalStateException(
                "Failed to retrieve ticket", e
            );
        }
    }


    public List<Ticket> findByOwner(long ownerId) {
        String sql = "SELECT id FROM tickets WHERE owner_id = ?";

        List<Ticket> tickets = new java.util.ArrayList<>();

        try (Connection conn = db.connect();
            PreparedStatement ps = conn.prepareStatement(sql)) {

            ps.setLong(1, ownerId);

            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    findById(rs.getLong("id")).ifPresent(tickets::add);
                }
            }

            return tickets;

        } catch (SQLException e) {
            throw new IllegalStateException(
                "Failed to retrieve tickets by owner", e
            );
        }
    }

        
    public List<Ticket> findAll() {
        String sql = "SELECT id FROM tickets";

        List<Ticket> tickets = new java.util.ArrayList<>();

        try (Connection conn = db.connect();
            PreparedStatement ps = conn.prepareStatement(sql);
            ResultSet rs = ps.executeQuery()) {

            while (rs.next()) {
                findById(rs.getLong("id")).ifPresent(tickets::add);
            }

            return tickets;

        } catch (SQLException e) {
            throw new IllegalStateException(
                "Failed to retrieve all tickets", e
            );
        }
    }


        
    public int countOpenByOwner(long ownerId) {
        String sql = """
            SELECT COUNT(*)
            FROM tickets
            WHERE owner_id = ? AND status = ?
            """;

        try (Connection conn = db.connect();
            PreparedStatement ps = conn.prepareStatement(sql)) {

            ps.setLong(1, ownerId);
            ps.setString(2, Ticket.Status.OPEN.name());

            try (ResultSet rs = ps.executeQuery()) {
                return rs.next() ? rs.getInt(1) : 0;
            }

        } catch (SQLException e) {
            throw new IllegalStateException(
                "Failed to count open tickets", e
            );
        }
    }

    /**
     * Atomic assign (CWE-367): UPDATE tickets SET assignee_id = ?, status = 'ASSIGNED', version = version + 1
     *                          WHERE id = ? AND assignee_id IS NULL
     * @return true if exactly one row updated
     */
        
    public boolean assignIfUnassigned(long ticketId, long technicianId) {
        String sql = """
            UPDATE tickets
            SET assignee_id = ?,
                status = 'ASSIGNED',
                version = version + 1
            WHERE id = ?
            AND assignee_id IS NULL
            """;

        try (Connection conn = db.connect();
            PreparedStatement ps = conn.prepareStatement(sql)) {

            ps.setLong(1, technicianId);
            ps.setLong(2, ticketId);

            return ps.executeUpdate() == 1;

        } catch (SQLException e) {
            throw new IllegalStateException(
                "Failed to assign ticket", e
            );
        }
    }


    /** Optimistic-lock update (CWE-820/821): ... WHERE id = ? AND version = ? */
        
    public boolean updateIfVersion(Ticket t, long expectedVersion) {
        String sql = """
            UPDATE tickets
            SET title = ?,
                description = ?,
                contact_enc = ?,
                status = ?,
                assignee_id = ?,
                version = version + 1
            WHERE id = ? AND version = ?
            """;

        try (Connection conn = db.connect();
            PreparedStatement ps = conn.prepareStatement(sql)) {

            ps.setString(1, t.getTitle());
            ps.setString(2, t.getDescription());

            String encryptedContact = t.getContactInfo() == null
                ? null
                : encryptor.encrypt(t.getContactInfo());

            ps.setString(3, encryptedContact);
            ps.setString(4, t.getStatus().name());

            if (t.getAssigneeId() == null) {
                ps.setNull(5, java.sql.Types.BIGINT);
            } else {
                ps.setLong(5, t.getAssigneeId());
            }

            ps.setLong(6, t.getId());
            ps.setLong(7, expectedVersion);

            boolean updated = ps.executeUpdate() == 1;

            if (updated) {
                t.setVersion(expectedVersion + 1);
            }

            return updated;

        } catch (SQLException e) {
            throw new IllegalStateException(
                "Failed to update ticket", e
            );
        }
    }


    
    public boolean delete(long id) {
        String sql = "DELETE FROM tickets WHERE id = ?";

        try (Connection conn = db.connect();
            PreparedStatement ps = conn.prepareStatement(sql)) {

            ps.setLong(1, id);

            return ps.executeUpdate() == 1;

        } catch (SQLException e) {
            throw new IllegalStateException(
                "Failed to delete ticket", e
            );
        }
    }

}

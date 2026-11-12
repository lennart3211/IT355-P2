package com.ticketapp.files;

import com.ticketapp.model.Ticket;
import com.ticketapp.session.AccessControl;
import com.ticketapp.session.Session;
import com.ticketapp.ticket.TicketRepository;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.UUID;

/**
 * Owner: Lennart
 *
 * CWE-22 Path Traversal: "attach 42 ../../etc/passwd" must be rejected.
 *   resolve = root.resolve(name).normalize(); then require resolved.startsWith(root)
 *   AND check toRealPath() after creation (symlinks). Prefer server-generated names.
 */
public class AttachmentStore {

    static final long MAX_ATTACHMENT_BYTES = 5L * 1024 * 1024;   // CWE-770

    private final Path root;   // AppConfig.attachmentsDir(), stored as toRealPath()
    private final AccessControl access;
    private final TicketRepository tickets;

    public AttachmentStore(Path root, AccessControl access, TicketRepository tickets) {
        this.root = root.toAbsolutePath().normalize();
        this.access = access;
        this.tickets = tickets;
    }

    /** Copy a local file into the attachments folder for a ticket. */
    public Path attach(Session session, long ticketId, Path source) {
        access.requireCanModify(session, findTicket(ticketId));
        try {
            if (!Files.isRegularFile(source) || Files.size(source) > MAX_ATTACHMENT_BYTES) {
                throw new IllegalArgumentException("Attachment must be a regular file up to "
                        + MAX_ATTACHMENT_BYTES + " bytes");
            }
            // Server-generated name: the user-supplied file name is never used.
            Path target = safeResolve(ticketId + "-" + UUID.randomUUID());
            Files.copy(source, target);
            return target;
        } catch (IOException e) {
            throw new UncheckedIOException("Attach failed", e);
        }
    }

    public Path open(Session session, long ticketId, String storedName) {
        access.requireCanView(session, findTicket(ticketId));
        if (storedName == null || !storedName.startsWith(ticketId + "-")) {
            throw new SecurityException("Invalid attachment name");
        }
        Path path = safeResolve(storedName);
        try {
            // Re-check after resolving symlinks.
            if (!path.toRealPath().startsWith(root.toRealPath())) {
                throw new SecurityException("Invalid attachment path");
            }
        } catch (IOException e) {
            throw new UncheckedIOException("Attachment not found", e);
        }
        return path;
    }

    private Ticket findTicket(long ticketId) {
        return tickets.findById(ticketId).orElseThrow(() -> new IllegalArgumentException("Ticket not found"));
    }

    /** @throws SecurityException if the result escapes root. */
    Path safeResolve(String name) {
        if (name == null || name.isEmpty() || name.contains("..") || name.contains("/")
                || name.contains("\\") || name.indexOf('\0') >= 0) {
            throw new SecurityException("Invalid attachment name");
        }
        Path resolved = root.resolve(name).normalize();
        if (!resolved.startsWith(root) || resolved.equals(root)) {
            throw new SecurityException("Invalid attachment name");
        }
        return resolved;
    }
}

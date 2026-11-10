package com.ticketapp.files;

import com.ticketapp.audit.AuditLog;
import com.ticketapp.model.Role;
import com.ticketapp.model.Ticket;
import com.ticketapp.session.AccessControl;
import com.ticketapp.session.Session;
import com.ticketapp.ticket.TicketRepository;

import java.io.File;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Instant;
import java.util.UUID;

/**
 * Owner: Lennart
 *
 * CWE-378 Temp File With Insecure Permissions: create temp files with
 *   Files.createTempFile(exportsDir, ..., PosixFilePermissions.asFileAttribute(rw-------))
 *   (fallback for Windows: restrict ACL to owner).
 * CWE-459 Incomplete Cleanup: delete the temp file in finally, even on failure.
 * CWE-552 Files Accessible to External Parties: final reports go ONLY to
 *   AppConfig.exportsDir() (owner-only, rwx------), never a shared/world-readable folder.
 * CWE-749: requireRole(TECHNICIAN) inside export().
 * CWE-778: EXPORT_CREATED logged.
 */
public class ExportService {

    private final Path exportsDir;
    private final AccessControl access;
    private final AuditLog audit;
    private final TicketRepository tickets;

    public ExportService(Path exportsDir, AccessControl access, AuditLog audit, TicketRepository tickets) {
        this.exportsDir = exportsDir;
        this.access = access;
        this.audit = audit;
        this.tickets = tickets;
    }

    /** @return path of the finished report inside exportsDir. */
    public Path export(Session session) {
        access.requireRole(session, Role.TECHNICIAN);
        Path temp = null;
        try {
            temp = createOwnerOnlyTempFile();
            StringBuilder csv = new StringBuilder("id,owner_id,assignee_id,title,status,created_at\n");
            for (Ticket t : tickets.findAll()) {
                csv.append(t.getId()).append(',')
                   .append(t.getOwnerId()).append(',')
                   .append(t.getAssigneeId() == null ? "" : t.getAssigneeId()).append(',')
                   .append(cell(t.getTitle())).append(',')
                   .append(t.getStatus()).append(',')
                   .append(t.getCreatedAt()).append('\n');
            }
            Files.writeString(temp, csv, StandardCharsets.UTF_8);
            Path target = exportsDir.resolve("tickets-" + Instant.now().toEpochMilli() + "-" + UUID.randomUUID() + ".csv");
            Files.move(temp, target, StandardCopyOption.ATOMIC_MOVE);
            audit.record(AuditLog.Event.EXPORT_CREATED, session.username(), "export " + target.getFileName());
            return target;
        } catch (IOException e) {
            throw new UncheckedIOException("Export failed", e);
        } finally {
            if (temp != null) {
                try {
                    Files.deleteIfExists(temp);
                } catch (IOException ignored) {
                    // best-effort cleanup
                }
            }
        }
    }

    /** Quotes a CSV cell and neutralizes spreadsheet formula prefixes. */
    private static String cell(String v) {
        String s = v == null ? "" : v;
        if (!s.isEmpty() && "=+-@\t\r".indexOf(s.charAt(0)) >= 0) {
            s = "'" + s;
        }
        return '"' + s.replace("\"", "\"\"") + '"';
    }

    Path createOwnerOnlyTempFile() {
        try {
            if (FileSystems.getDefault().supportedFileAttributeViews().contains("posix")) {
                return Files.createTempFile(exportsDir, "export-", ".tmp",
                        PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
            }
            // Non-POSIX (Windows): create, then drop access for everyone but the owner.
            Path temp = Files.createTempFile(exportsDir, "export-", ".tmp");
            File f = temp.toFile();
            boolean ok = f.setReadable(false, false) & f.setWritable(false, false) & f.setExecutable(false, false)
                    & f.setReadable(true, true) & f.setWritable(true, true);
            if (!ok) {
                Files.deleteIfExists(temp);
                throw new IOException("Could not restrict temp file permissions");
            }
            return temp;
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to create temp file", e);
        }
    }
}

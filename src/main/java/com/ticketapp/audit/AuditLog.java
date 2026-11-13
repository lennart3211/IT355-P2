package com.ticketapp.audit;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Instant;


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
    private static final Path LOG_FILE = Path.of("audit.log");

    public enum Event {
        LOGIN_SUCCESS,
        LOGIN_FAILURE,
        ACCOUNT_LOCKED,
        ACCOUNT_UNLOCKED,
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
    public synchronized void record(Event event, String actor, String detail) {
        String safeActor = LogSanitizer.clean(actor);
        String safeDetail = LogSanitizer.clean(detail);

        String entry = Instant.now() + " | " + event + " | "
                + safeActor + " | " + safeDetail + System.lineSeparator();

        try {
            Files.writeString(
                    LOG_FILE,
                    entry,
                    StandardCharsets.UTF_8,
                    StandardOpenOption.CREATE,
                    StandardOpenOption.APPEND
            );

            if (Files.getFileStore(LOG_FILE)
                    .supportsFileAttributeView("posix")) {
                Files.setPosixFilePermissions(
                        LOG_FILE,
                        PosixFilePermissions.fromString("rw-------")
                );
            }
        } catch (IOException e) {
            throw new IllegalStateException("Failed to write audit log", e);
        }
    }
}
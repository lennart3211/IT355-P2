package com.ticketapp.files;

import com.ticketapp.session.Session;

import java.nio.file.Path;

/**
 * Owner: Lennart
 *
 * CWE-22 Path Traversal: "attach 42 ../../etc/passwd" must be rejected.
 *   resolve = root.resolve(name).normalize(); then require resolved.startsWith(root)
 *   AND check toRealPath() after creation (symlinks). Prefer server-generated names.
 */
public class AttachmentStore {

    private final Path root;   // AppConfig.attachmentsDir(), stored as toRealPath()

    public AttachmentStore(Path root) {
        this.root = root;
    }

    /** Copy a local file into the attachments folder for a ticket. */
    public Path attach(Session session, long ticketId, Path source) {
        // TODO: access check on ticket; size cap (CWE-770); generate safe stored name;
        //       safeResolve(); copy
        throw new UnsupportedOperationException("TODO");
    }

    public Path open(Session session, long ticketId, String storedName) {
        throw new UnsupportedOperationException("TODO");
    }

    /** @throws SecurityException if the result escapes root. */
    Path safeResolve(String name) {
        // TODO: reject absolute paths, "..", separators; normalize; startsWith(root)
        throw new UnsupportedOperationException("TODO");
    }
}

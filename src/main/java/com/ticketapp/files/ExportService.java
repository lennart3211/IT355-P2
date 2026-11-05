package com.ticketapp.files;

import com.ticketapp.audit.AuditLog;
import com.ticketapp.session.AccessControl;
import com.ticketapp.session.Session;

import java.nio.file.Path;

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

    public ExportService(Path exportsDir, AccessControl access, AuditLog audit) {
        this.exportsDir = exportsDir;
        this.access = access;
        this.audit = audit;
    }

    /** @return path of the finished report inside exportsDir. */
    public Path export(Session session) {
        Path temp = null;
        try {
            // TODO: requireRole; temp = createOwnerOnlyTempFile(); write CSV;
            //       atomic move into exportsDir; audit EXPORT_CREATED
            throw new UnsupportedOperationException("TODO");
        } finally {
            // TODO: if (temp != null) Files.deleteIfExists(temp)   (CWE-459)
        }
    }

    Path createOwnerOnlyTempFile() {
        throw new UnsupportedOperationException("TODO");
    }
}
